using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using SSHHardener.Core;
using SSHHardener.Ssh;

internal static class TotpAuthenticationScenario
{
    // Public fixture values, never loaded from a user profile, key or server.
    private const string Seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    private const string Passphrase = "public-synthetic-sshnet-totp-fixture-2026";
    private const string Recovery = "12345678";

    public static async Task RunAsync(string folder)
    {
        Check(OperatingSystem.IsWindows(), "This explicit runner requires Windows and WSL Docker.");
        folder = Path.GetFullPath(folder);
        Directory.CreateDirectory(folder);
        var evidence = new List<string>();
        var privateKey = Path.Combine(folder, "fixture.ppk");
        await new KeyService().GenerateEd25519Async(privateKey, Passphrase);
        var before = SHA256.HashData(await File.ReadAllBytesAsync(privateKey));
        var script = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../tests/SSHHardener.IntegrationTests/TotpAuthenticationScenario.server.sh"));
        var name = "sshhardener-totp-auth-" + Guid.NewGuid().ToString("N")[..12];
        var started = false;
        try
        {
            await DockerAsync(["run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::22",
                "-v", WslPath(privateKey + ".pub") + ":/fixture.pub:ro",
                "-v", WslPath(script) + ":/fixture-server.sh:ro", "sshhardener-access-policy:local", "/fixture-server.sh"]);
            started = true;
            var mapping = (await DockerAsync(["port", name, "22/tcp"])).Trim();
            Check(mapping.StartsWith("127.0.0.1:", StringComparison.Ordinal), "The disposable SSH endpoint is not bound to loopback.");
            var port = int.Parse(mapping[(mapping.LastIndexOf(':') + 1)..], System.Globalization.CultureInfo.InvariantCulture);
            await WaitForListenerAsync(port);
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            var known = new KnownHostsStore(Path.Combine(folder, "fixture-trust"));
            var ssh = new SshRemoteSessionFactory(known);
            var sftp = new SftpSessionFactory(known);
            HostIdentity? pin = null;
            Task<bool> Trust(HostIdentity identity)
            {
                Check(identity.Host == "127.0.0.1" && identity.Port == port, "Unexpected authentication fixture endpoint.");
                if (pin is null) pin = identity;
                return Task.FromResult(identity.Algorithm == pin.Algorithm && identity.KeyBase64 == pin.KeyBase64 && identity.Fingerprint == pin.Fingerprint);
            }
            ConnectionOptions Options(string user, Func<CancellationToken, Task<string>>? provider = null) =>
                new("127.0.0.1", port, user, PrivateKeyPath: privateKey, Passphrase: Passphrase) { OneTimeCodeProvider = provider };
            async Task DeniedSsh(ConnectionOptions options, string label)
            {
                var denied = false;
                try { await using var unexpected = await ssh.ConnectAsync(options, Trust, deadline.Token); }
                catch (OperationCanceledException) { throw; }
                catch { denied = true; }
                Check(denied, label + " unexpectedly authenticated.");
                Pass(evidence, label + " rejected by actual SSH.NET/PAM authentication.");
            }

            await DeniedSsh(Options("otp-shell"), "Missing second-factor provider");
            var wrongCalls = 0;
            await DeniedSsh(Options("otp-shell", _ =>
            {
                Interlocked.Increment(ref wrongCalls);
                Check(pin is not null, "An OTP callback ran before server host-key verification.");
                var current = TotpService.GenerateCode(Seed, DateTimeOffset.UtcNow);
                return Task.FromResult(current == "000000" ? "111111" : "000000");
            }), "Incorrect TOTP code");
            Check(wrongCalls > 0, "The production keyboard-interactive callback was never reached.");

            var successfulCode = "";
            var correctCalls = 0;
            await using (var session = await ssh.ConnectAsync(Options("otp-shell", _ =>
            {
                Interlocked.Increment(ref correctCalls);
                Check(pin is not null, "An OTP callback ran before host-key verification.");
                successfulCode = TotpService.GenerateCode(Seed, DateTimeOffset.UtcNow);
                return Task.FromResult(successfulCode);
            }), Trust, deadline.Token))
            {
                var identity = await session.ExecuteAsync("id -un", false, deadline.Token);
                Check(identity.ExitCode == 0 && identity.Output.Trim() == "otp-shell", "Key plus TOTP did not prove the expected shell account.");
            }
            Check(correctCalls > 0, "A successful key+TOTP connection bypassed the code callback.");
            Pass(evidence, "Encrypted Ed25519 key plus callback-supplied TOTP authenticated and executed id -un.");
            await DeniedSsh(Options("otp-shell", _ => Task.FromResult(successfulCode)), "Reused TOTP code (DISALLOW_REUSE)");

            var recoveryCalls = 0;
            await using (var recovery = await ssh.ConnectAsync(Options("otp-shell", _ => { recoveryCalls++; return Task.FromResult(Recovery); }), Trust, deadline.Token))
            {
                var identity = await recovery.ExecuteAsync("id -un", false, deadline.Token);
                Check(identity.ExitCode == 0 && identity.Output.Trim() == "otp-shell", "Eight-digit recovery code did not authenticate.");
            }
            Check(recoveryCalls > 0, "Recovery login bypassed keyboard-interactive.");
            Pass(evidence, "An eight-digit recovery code authenticated through the production callback.");
            await DeniedSsh(Options("otp-shell", _ => Task.FromResult(Recovery)), "Consumed recovery code");

            await CancelledSshAsync(ssh, Options("otp-shell"), Trust, deadline.Token);
            Pass(evidence, "Cancelling a pending production SSH code callback terminates authentication.");

            var sftpMissingDenied = false;
            try { await using var unexpected = await sftp.ConnectSftpAsync(Options("otp-sftp"), Trust, deadline.Token); }
            catch (OperationCanceledException) { throw; }
            catch { sftpMissingDenied = true; }
            Check(sftpMissingDenied, "SFTP accepted the key without a second factor.");
            var sftpCalls = 0;
            await using (var session = await sftp.ConnectSftpAsync(Options("otp-sftp", _ =>
            { sftpCalls++; return Task.FromResult(TotpService.GenerateCode(Seed, DateTimeOffset.UtcNow)); }), Trust, deadline.Token))
            {
                var entries = await session.ListAsync("/", deadline.Token);
                Check(entries.Any(entry => entry.Name == "uploads" && entry.IsDirectory), "The authenticated SFTP chroot was not visible.");
                var path = "/uploads/production-sshnet-fixture.bin";
                var payload = RandomNumberGenerator.GetBytes(128);
                using var upload = new MemoryStream(payload, writable: false);
                await session.UploadAsync(upload, path, false, deadline.Token);
                using var downloaded = new MemoryStream();
                await session.DownloadAsync(path, downloaded, deadline.Token);
                Check(CryptographicOperations.FixedTimeEquals(payload, downloaded.ToArray()), "Production SFTP transfer changed the fixture payload.");
                await session.DeleteAsync(path, false, deadline.Token);
                CryptographicOperations.ZeroMemory(payload);
            }
            Check(sftpCalls > 0, "Successful SFTP bypassed its production code callback.");
            Pass(evidence, "Production SftpSessionFactory requires key+TOTP and lists/uploads/downloads/deletes in the chroot.");
            await CancelledSftpAsync(sftp, Options("otp-sftp"), Trust, deadline.Token);
            Pass(evidence, "Cancelling a pending production SFTP code callback terminates authentication.");
            Check(before.SequenceEqual(SHA256.HashData(await File.ReadAllBytesAsync(privateKey))), "The synthetic source private key changed.");
            Pass(evidence, "Synthetic encrypted source key unchanged; no user VM, profile or key was accessed.");
        }
        catch (Exception error)
        {
            evidence.Add("FAIL: " + error.GetType().Name + ": " + Sanitize(error.Message));
            throw;
        }
        finally
        {
            if (started)
            {
                try { await File.WriteAllTextAsync(Path.Combine(folder, "sshd-fixture.log"), Sanitize(await DockerAsync(["logs", name]))); } catch { }
                try { await DockerAsync(["rm", "-f", name]); } catch { }
            }
            await File.WriteAllTextAsync(Path.Combine(folder, "result.txt"), string.Join('\n', evidence) + "\n");
        }
    }

    private static async Task CancelledSshAsync(IRemoteSessionFactory factory, ConnectionOptions options,
        Func<HostIdentity, Task<bool>> trust, CancellationToken deadline)
    {
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(deadline);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        options = options with { OneTimeCodeProvider = async token => { entered.TrySetResult(); await Task.Delay(Timeout.Infinite, token); return "000000"; } };
        var connect = factory.ConnectAsync(options, trust, cancel.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(15), deadline);
        cancel.Cancel();
        try { await using var unexpected = await connect.WaitAsync(TimeSpan.FromSeconds(15), deadline); }
        catch (OperationCanceledException) { return; }
        throw new InvalidOperationException("SSH callback cancellation was not propagated.");
    }
    private static async Task CancelledSftpAsync(ISftpSessionFactory factory, ConnectionOptions options,
        Func<HostIdentity, Task<bool>> trust, CancellationToken deadline)
    {
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(deadline);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        options = options with { OneTimeCodeProvider = async token => { entered.TrySetResult(); await Task.Delay(Timeout.Infinite, token); return "000000"; } };
        var connect = factory.ConnectSftpAsync(options, trust, cancel.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(15), deadline);
        cancel.Cancel();
        try { await using var unexpected = await connect.WaitAsync(TimeSpan.FromSeconds(15), deadline); }
        catch (OperationCanceledException) { return; }
        throw new InvalidOperationException("SFTP callback cancellation was not propagated.");
    }
    private static async Task WaitForListenerAsync(int port)
    {
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        for (var attempt = 0; ; attempt++)
        {
            try { using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, port, limit.Token); return; }
            catch (SocketException) when (attempt < 30) { await Task.Delay(250, limit.Token); }
        }
    }
    private static async Task<string> DockerAsync(string[] arguments)
    {
        var start = new ProcessStartInfo("wsl.exe")
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in new[] { "-d", "Ubuntu", "--exec", "docker" }.Concat(arguments)) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the opt-in Docker fixture.");
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await process.WaitForExitAsync(timeout.Token); } catch { if (!process.HasExited) process.Kill(true); throw; }
        var stdout = await output; var stderr = await error;
        Check(process.ExitCode == 0, "Disposable Docker command failed: " + Sanitize(stderr));
        return stdout + stderr;
    }
    private static string WslPath(string path)
    {
        path = Path.GetFullPath(path);
        Check(path.Length > 3 && char.IsAsciiLetter(path[0]) && path[1] == ':', "Use an absolute Windows drive path.");
        return "/mnt/" + char.ToLowerInvariant(path[0]) + path[2..].Replace('\\', '/');
    }
    private static string Sanitize(string value) => value.Replace(Seed, "[fixture-seed]", StringComparison.Ordinal)
        .Replace(Passphrase, "[fixture-passphrase]", StringComparison.Ordinal).Replace(Recovery, "[fixture-recovery-code]", StringComparison.Ordinal);
    private static void Pass(List<string> evidence, string message) { var line = "PASS: " + message; evidence.Add(line); Console.WriteLine(line); }
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
