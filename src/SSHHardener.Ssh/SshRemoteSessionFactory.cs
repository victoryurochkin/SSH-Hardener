using System.Security.Cryptography;
using System.Text;
using System.Net;
using System.Text.RegularExpressions;
using Renci.SshNet;
using SSHHardener.Core;

namespace SSHHardener.Ssh;

public sealed class SshRemoteSessionFactory(KnownHostsStore knownHosts) : IRemoteSessionFactory
{
    public async Task<IRemoteSession> ConnectAsync(ConnectionOptions options,
        Func<HostIdentity, Task<bool>> trustHost, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(options.Host) || options.Host.Length > 253
            || (!IPAddress.TryParse(options.Host, out _) && Uri.CheckHostName(options.Host) == UriHostNameType.Unknown)
            || options.Host.Any(char.IsControl) || options.Port is < 1 or > 65535
            || !Regex.IsMatch(options.Username, @"\A[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("Invalid SSH endpoint or user.");
        var methods = new List<AuthenticationMethod>();
        PrivateKeyFile? key = null;
        if (!string.IsNullOrWhiteSpace(options.PrivateKeyPath))
        {
            key = new PrivateKeyFile(options.PrivateKeyPath, options.Passphrase);
            methods.Add(new PrivateKeyAuthenticationMethod(options.Username, key));
        }
        else if (options.Password is not null)
            methods.Add(new PasswordAuthenticationMethod(options.Username, options.Password));
        else throw new ArgumentException("A private key or password is required.");
        var info = new ConnectionInfo(options.Host, options.Port, options.Username, methods.ToArray())
        {
            Timeout = TimeSpan.FromSeconds(20), RetryAttempts = 3
        };
        SshAlgorithmPolicy.Apply(info);
        var client = new SshClient(info) { KeepAliveInterval = TimeSpan.FromSeconds(20) };
        HostIdentity? identity = null;
        Exception? verificationError = null;
        client.HostKeyReceived += (_, e) =>
        {
            e.CanTrust = false;
            try
            {
                var candidate = new HostIdentity(options.Host, options.Port, e.HostKeyName,
                    "SHA256:" + Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('='), Convert.ToBase64String(e.HostKey));
                knownHosts.VerifyAsync(candidate, trustHost, cancellationToken).GetAwaiter().GetResult();
                identity = candidate;
                e.CanTrust = true;
            }
            catch (Exception ex) { verificationError = ex; }
        };
        try
        {
            // Host-key callbacks run on SSH.NET's worker. A UI confirmation must marshal to Dispatcher.
            await Task.Run(() => client.ConnectAsync(cancellationToken), cancellationToken).ConfigureAwait(false);
            if (identity is null) throw new InvalidOperationException("Server identity was not established.");
            return new SshRemoteSession(client, key, options, identity);
        }
        catch
        {
            client.Dispose(); key?.Dispose();
            if (verificationError is HostKeyChangedException changed) throw changed;
            if (verificationError is not null) throw new InvalidOperationException("SSH host identity verification failed.", verificationError);
            throw;
        }
    }
}

public static class SshAlgorithmPolicy
{
    public static void Apply(ConnectionInfo connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        foreach (var name in connection.KeyExchangeAlgorithms.Keys.Where(x => x.Contains("sha1", StringComparison.OrdinalIgnoreCase)).ToArray())
            connection.KeyExchangeAlgorithms.Remove(name);
        foreach (var name in connection.Encryptions.Keys.Where(x => x.EndsWith("-cbc", StringComparison.Ordinal) || x.Contains("3des", StringComparison.Ordinal) || x.Contains("arcfour", StringComparison.Ordinal)).ToArray())
            connection.Encryptions.Remove(name);
        foreach (var name in connection.HmacAlgorithms.Keys.Where(x => x.Contains("sha1", StringComparison.OrdinalIgnoreCase) || x.Contains("md5", StringComparison.OrdinalIgnoreCase)).ToArray())
            connection.HmacAlgorithms.Remove(name);
        connection.HostKeyAlgorithms.Remove("ssh-dss");
        connection.HostKeyAlgorithms.Remove("ssh-rsa"); // RSA SHA-2 host signatures remain supported.
    }
}

internal sealed class SshRemoteSession(SshClient client, PrivateKeyFile? key,
    ConnectionOptions options, HostIdentity identity) : IRemoteSession
{
    private readonly SemaphoreSlim _commands = new(1, 1);
    public ConnectionOptions Options { get; } = options;
    public HostIdentity Identity { get; } = identity;

    public async Task<CommandResult> ExecuteAsync(string script, bool privileged, CancellationToken cancellationToken)
    {
        if (script.Contains('\0')) throw new ArgumentException("NUL in remote script.");
        await _commands.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Script and sudo password are transmitted via the SSH channel's stdin, never argv.
            // sudo -S consumes one password line only when needed; validate first on a separate channel
            // so no shell script can accidentally become its password.
            if (privileged && Options.Username != "root")
            {
                var probe = await RunAsync("sudo -n -v", "", cancellationToken).ConfigureAwait(false);
                if (probe.ExitCode != 0)
                {
                    var secret = Options.SudoPassword ?? Options.Password;
                    if (secret is null || secret.Contains('\n') || secret.Contains('\r'))
                        throw new InvalidOperationException("sudo requires a password. Enter it in connection settings; requiretty-only sudo is unsupported.");
                    var validated = await RunAsync("sudo -S -p '' -v", secret + "\n", cancellationToken).ConfigureAwait(false);
                    if (validated.ExitCode != 0) throw new InvalidOperationException("sudo authentication failed or a terminal is required.");
                }
            }
            // Sudo tickets can be per-terminal/channel. Use -S with a single password prefix if
            // -n cannot run the exact target; the wrapper reads the script only after sudo succeeds.
            if (privileged && Options.Username != "root")
            {
                var check = await RunAsync("sudo -n /bin/sh -c 'exit 0'", "", cancellationToken).ConfigureAwait(false);
                if (check.ExitCode != 0)
                {
                    var secret = Options.SudoPassword ?? Options.Password;
                    if (secret is null) throw new InvalidOperationException("Passwordless privileged shell is unavailable.");
                    // Isolate the password from sh stdin using a fixed pipe reader and -c script data.
                    // The encoded script contains no credentials. Password remains stdin only.
                    var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(script));
                    var command = "sudo -S -p '' /bin/sh -c 'printf %s " + encoded + " | base64 -d | /bin/sh -s'";
                    return await RunAsync(command, secret + "\n", cancellationToken).ConfigureAwait(false);
                }
            }
            return await RunAsync(privileged && Options.Username != "root" ? "sudo -n /bin/sh -s" : "/bin/sh -s",
                script.Replace("\r\n", "\n") + "\n", cancellationToken).ConfigureAwait(false);
        }
        finally { _commands.Release(); }
    }
    private async Task<CommandResult> RunAsync(string command, string input, CancellationToken ct)
    {
        using var cmd = client.CreateCommand(command);
        cmd.CommandTimeout = TimeSpan.FromMinutes(3);
        var execution = cmd.ExecuteAsync(ct);
        // SSH.NET opens the channel synchronously before returning ExecuteAsync's task.
        if (input.Length > 0)
        {
            try
            {
                using var stream = cmd.CreateInputStream();
                var bytes = Encoding.UTF8.GetBytes(input);
                try { await stream.WriteAsync(bytes, ct).ConfigureAwait(false); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            catch (InvalidOperationException) when (execution.IsCompleted)
            {
                // A rejected sudo command can close its channel before accepting stdin.
                // Preserve its real exit status/error instead of masking it with a stream race.
            }
        }
        await execution.ConfigureAwait(false);
        return new CommandResult(cmd.ExitStatus ?? -1, cmd.Result, cmd.Error);
    }
    public ValueTask DisposeAsync()
    {
        client.Dispose(); key?.Dispose(); _commands.Dispose(); return ValueTask.CompletedTask;
    }
}
