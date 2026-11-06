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
        var authentication = SshAuthentication.Create(options, cancellationToken);
        var info = authentication.ConnectionInfo;
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
            return new SshRemoteSession(client, authentication, options, identity);
        }
        catch
        {
            client.Dispose(); authentication.Dispose();
            if (verificationError is HostKeyChangedException changed) throw changed;
            if (verificationError is not null) throw new InvalidOperationException("SSH host identity verification failed.", verificationError);
            if (authentication.ChallengeError is OperationCanceledException cancelled) throw cancelled;
            if (authentication.ChallengeError is not null) throw new InvalidOperationException("Interactive authentication was not completed.", authentication.ChallengeError);
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

internal sealed class SshRemoteSession(SshClient client, SshAuthenticationContext authentication,
    ConnectionOptions options, HostIdentity identity) : IRemoteSession, IRemoteSensitiveSession
{
    private readonly SemaphoreSlim _commands = new(1, 1);
    public ConnectionOptions Options { get; } = options;
    public HostIdentity Identity { get; } = identity;

    public async Task<CommandResult> ExecuteSensitiveAsync(string script, ReadOnlyMemory<byte> input,
        bool privileged, CancellationToken cancellationToken)
    {
        if (script.Contains('\0') || input.Length > 65536) throw new ArgumentException("Invalid sensitive-input operation.");
        var scriptBytes = Encoding.UTF8.GetBytes(script.Replace("\r\n", "\n") + "\n");
        if (scriptBytes.Length > 2 * 1024 * 1024) throw new ArgumentException("The remote script exceeds the supported size.");
        await _commands.WaitAsync(cancellationToken).ConfigureAwait(false);
        byte[]? combined = null;
        byte[]? prefix = null;
        try
        {
            // A fixed wrapper receives script-length, script and separate sensitive data through stdin.
            // Long scripts and credentials never become process arguments. The temporary file holds
            // reviewed script bytes only, is created privately, and is removed when the wrapper exits.
            var command = "/bin/sh -c " + SSHHardener.Core.Shell.Quote(FramedInputWrapper);
            if (privileged && Options.Username != "root")
            {
                var probe = await RunAsync("sudo -n /bin/sh -c 'exit 0'", "", cancellationToken).ConfigureAwait(false);
                if (probe.ExitCode == 0) command = "sudo -n " + command;
                else
                {
                    var password = Options.SudoPassword ?? Options.Password;
                    if (string.IsNullOrEmpty(password) || password.Any(x => x is '\r' or '\n' or '\0'))
                        throw new InvalidOperationException("A valid administrator sudo password is required for this operation.");
                    // Invalidate a PASSWD timestamp so sudo consumes exactly one password line.
                    // NOPASSWD takes the successful -n path above and receives no password prefix.
                    command = "sudo -k -S -p '' " + command;
                    prefix = Encoding.UTF8.GetBytes(password + "\n");
                }
            }
            var header = Encoding.ASCII.GetBytes(scriptBytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\n");
            var offset = prefix?.Length ?? 0;
            combined = new byte[offset + header.Length + scriptBytes.Length + input.Length];
            prefix?.CopyTo(combined, 0);
            header.CopyTo(combined, offset); offset += header.Length;
            scriptBytes.CopyTo(combined, offset); offset += scriptBytes.Length;
            input.Span.CopyTo(combined.AsSpan(offset));
            using var cmd = client.CreateCommand(command);
            cmd.CommandTimeout = TimeSpan.FromMinutes(3);
            var execution = cmd.ExecuteAsync(cancellationToken);
            try
            {
                using var stream = cmd.CreateInputStream();
                await stream.WriteAsync(combined, cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidOperationException) when (execution.IsCompleted) { }
            await execution.ConfigureAwait(false);
            return new CommandResult(cmd.ExitStatus ?? -1, cmd.Result, cmd.Error);
        }
        finally
        {
            if (combined is not null) CryptographicOperations.ZeroMemory(combined);
            if (prefix is not null) CryptographicOperations.ZeroMemory(prefix);
            CryptographicOperations.ZeroMemory(scriptBytes);
            _commands.Release();
        }
    }

    public Task<CommandResult> ExecuteAsync(string script, bool privileged, CancellationToken cancellationToken) =>
        ExecuteSensitiveAsync(script, ReadOnlyMemory<byte>.Empty, privileged, cancellationToken);

    private const string FramedInputWrapper = """
        set -eu
        umask 077
        IFS= read -r script_length
        case "$script_length" in ''|*[!0-9]*) exit 65;; esac
        [ "$script_length" -gt 0 ] && [ "$script_length" -le 2097152 ] || exit 65
        channel_script=$(mktemp /tmp/sshhardener-channel.XXXXXXXXXX)
        trap 'rm -f "$channel_script"' EXIT
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        dd bs=1 count="$script_length" of="$channel_script" 2>/dev/null
        [ "$(wc -c < "$channel_script")" -eq "$script_length" ] || exit 65
        # The source contains no credentials. Unlink it before execution so a
        # server that rejects SSH signal requests cannot leave a named script.
        # Cancellation is not proof that remote descendants have exited.
        exec 3<"$channel_script"
        rm -f "$channel_script"
        /bin/sh /proc/self/fd/3
        """;
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
        client.Dispose(); authentication.Dispose(); _commands.Dispose(); return ValueTask.CompletedTask;
    }
}
