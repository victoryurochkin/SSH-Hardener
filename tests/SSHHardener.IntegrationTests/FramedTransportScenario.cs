using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SSHHardener.Core;
using SSHHardener.Ssh;

internal static class FramedTransportScenario
{
    private const string KeyPassphrase = "public-framed-transport-key-passphrase";
    private const string SudoPassword = "Public-Fixture-Sudo-2026!";

    public static async Task PrepareAsync(string directory)
    {
        Directory.CreateDirectory(directory);
        await new KeyService().GenerateEd25519Async(Path.Combine(directory, "fixture.ppk"), KeyPassphrase);
    }

    public static async Task VerifyAsync(string directory, int port)
    {
        Require(port is > 0 and <= 65535, "Invalid loopback fixture port.");
        var hostParts = (await File.ReadAllTextAsync(Path.Combine(directory, "host.pub"))).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var pin = hostParts[1];
        var factory = new SshRemoteSessionFactory(new KnownHostsStore(Path.Combine(directory, "trust")));
        var results = new List<string>();
        var evidence = Path.Combine(directory, "transport-results.txt");
        await File.WriteAllTextAsync(evidence, "");
        void Record(string line) { results.Add(line); File.AppendAllText(evidence, line + "\n"); Console.WriteLine(line); }
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        var rootOptions = new ConnectionOptions("127.0.0.1", port, "root", PrivateKeyPath: Path.Combine(directory, "fixture.ppk"), Passphrase: KeyPassphrase);
        await using var inspector = await factory.ConnectAsync(rootOptions, identity => Task.FromResult(identity.KeyBase64 == pin), deadline.Token);
        foreach (var (username, privileged) in new[] { ("transport_pass", true), ("transport_plain", false), ("transport_nopass", true), ("root", true) })
        {
            var options = rootOptions with { Username = username, SudoPassword = username == "transport_pass" ? SudoPassword : null };
            await using var session = await factory.ConnectAsync(options, identity => Task.FromResult(identity.KeyBase64 == pin), deadline.Token);
            Require(session is IRemoteSensitiveSession, "Sensitive transport interface is unavailable.");
            var sensitive = (IRemoteSensitiveSession)session;
            var marker = "UNIQUE_SCRIPT_NEVER_ARGV_" + Guid.NewGuid().ToString("N");
            var largeScript = Script(marker, exitCode: 37);
            Require(Encoding.UTF8.GetByteCount(largeScript) > 256 * 1024, "Fixture script is not large enough.");
            var normal = await session.ExecuteAsync(largeScript, privileged, deadline.Token);
            CheckResult(normal, 37, marker, expectedLength: 0, SHA256.HashData([]), privileged || username == "root");
            await RequireNoTempsAsync(inspector, deadline.Token);
            Record("PASS " + username + ": >256 KiB UTF-8 ExecuteAsync, stdout/stderr/exit, UID, 0600 helper, EOF input, no script/password in argv and cleanup.");

            var payloadMarker = Encoding.UTF8.GetBytes("SENSITIVE_BINARY_NEVER_ARGV_" + Guid.NewGuid().ToString("N"));
            var payload = new byte[2 + 256 * 4 + payloadMarker.Length + 5];
            payload[0] = payload[1] = (byte)'\n';
            for (var index = 0; index < 1024; index++) payload[index + 2] = (byte)index;
            payloadMarker.CopyTo(payload, 1026);
            payload[^5] = 0; payload[^4] = (byte)'\r'; payload[^3] = (byte)'\n'; payload[^2] = 0; payload[^1] = 255;
            try
            {
                var result = await sensitive.ExecuteSensitiveAsync(Script(marker, exitCode: 23), payload, privileged, deadline.Token);
                CheckResult(result, 23, marker, payload.Length, SHA256.HashData(payload), privileged || username == "root");
                Require(!result.Output.Contains(Encoding.UTF8.GetString(payloadMarker), StringComparison.Ordinal), "Sensitive input was echoed.");
                var argvLine = result.Output.Split('\n').Single(line => line.StartsWith("ARGV64=", StringComparison.Ordinal));
                var argv = Convert.FromBase64String(argvLine[7..]);
                Require(argv.AsSpan().IndexOf(payloadMarker) < 0, "Sensitive bytes appeared in process arguments.");
                await RequireNoTempsAsync(inspector, deadline.Token);
                Record("PASS " + username + ": >256 KiB sensitive script, exact binary payload including leading LF/NUL/CRLF/non-UTF8, no echo/argv and cleanup.");
            }
            finally { CryptographicOperations.ZeroMemory(payload); CryptographicOperations.ZeroMemory(payloadMarker); }

            using var cancel = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            var readyPath = "/tmp/sshhardener-framed-fixture-ready-" + Guid.NewGuid().ToString("N");
            var running = session.ExecuteAsync("printf ready > " + readyPath + "\nsleep 60\n", privileged, cancel.Token);
            // Wait for actual script execution before cancelling; this is not a pre-cancelled token test.
            await WaitForRunningScriptAsync(inspector, readyPath, deadline.Token);
            cancel.Cancel();
            var cancelled = false;
            try { await running; } catch (OperationCanceledException) { cancelled = true; }
            Require(cancelled, "Cancellation was not propagated.");
            await RequireNoTempsAsync(inspector, deadline.Token);
            var usable = await session.ExecuteAsync("printf reused", privileged, deadline.Token);
            Require(usable.ExitCode == 0 && usable.Output == "reused", "Session could not be reused after cancellation.");
            Record("PASS " + username + ": client cancellation after real script start, no named helper and session reuse; immediate server-child termination is not asserted.");
        }
        await RequireNoTempsAsync(inspector, deadline.Token);
        await File.WriteAllLinesAsync(evidence, results);
    }

    private static string Script(string marker, int exitCode)
    {
        // This literal marker is intentionally in the script, never in payload or expected-value argv.
        return "# " + new string('x', 320_000) + "\n# " + marker + "\n" +
            "printf '%s\\n' 'Привет · λ · 世界 · 🔒'\nprintf '%s\\n' 'stderr · ошибка · λ' >&2\n" +
            "printf 'MODE=%s\\n' \"$(stat -L -c %a \"$0\")\"\n" +
            "python3 -c 'import os,sys,hashlib,base64; data=sys.stdin.buffer.read(); print(\"UID=\"+str(os.geteuid())); print(\"LENGTH=\"+str(len(data))); print(\"SHA256=\"+hashlib.sha256(data).hexdigest()); p=os.getpid(); a=[]\n" +
            "for i in range(16):\n" +
            " try:\n" +
            "  a.append(open(\"/proc/\"+str(p)+\"/cmdline\",\"rb\").read()); s=open(\"/proc/\"+str(p)+\"/status\").read(); p=int(next(x for x in s.splitlines() if x.startswith(\"PPid:\")).split()[1]);\n" +
            "  if p<=0: break\n" +
            " except (OSError,StopIteration): break\n" +
            "print(\"ARGV64=\"+base64.b64encode(b\"\\n\".join(a)).decode())'\n" +
            "exit " + exitCode.ToString(CultureInfo.InvariantCulture) + "\n";
    }

    private static void CheckResult(CommandResult result, int exitCode, string marker, int expectedLength, byte[] expectedHash, bool root)
    {
        Require(result.ExitCode == exitCode, "Remote exit code changed.");
        Require(result.Output.StartsWith("Привет · λ · 世界 · 🔒\n", StringComparison.Ordinal), "Unicode stdout changed.");
        Require(result.Error == "stderr · ошибка · λ\n", "Unicode stderr changed or credentials were echoed.");
        var fields = result.Output.Split('\n').Where(line => line.Contains('=')).ToDictionary(line => line[..line.IndexOf('=')], line => line[(line.IndexOf('=') + 1)..]);
        Require(fields["MODE"] == "600", "Helper script is not mode 0600.");
        Require((fields["UID"] == "0") == root, "Command privilege differs from the requested mode.");
        Require(fields["LENGTH"] == expectedLength.ToString(CultureInfo.InvariantCulture) && fields["SHA256"] == Convert.ToHexStringLower(expectedHash), "Binary stdin changed.");
        var argv = Encoding.UTF8.GetString(Convert.FromBase64String(fields["ARGV64"]));
        Require(!argv.Contains(marker, StringComparison.Ordinal) && !argv.Contains(SudoPassword, StringComparison.Ordinal) &&
            !argv.Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes(marker)), StringComparison.Ordinal), "Script or sudo password appeared in argv.");
    }

    private static async Task RequireNoTempsAsync(IRemoteSession inspector, CancellationToken ct)
    {
        for (var attempt = 0; attempt < 40; attempt++)
        {
            var result = await inspector.ExecuteAsync("find /tmp -maxdepth 1 -type f -name 'sshhardener-channel.*' ! -path \"$0\" -print", false, ct);
            Require(result.ExitCode == 0, "Could not inspect fixture helper files.");
            if (result.Output.Length == 0) return;
            await Task.Delay(100, ct);
        }
        throw new InvalidOperationException("Transport helper files remained after the operation.");
    }
    private static async Task WaitForRunningScriptAsync(IRemoteSession inspector, string marker, CancellationToken ct)
    {
        for (var attempt = 0; attempt < 40; attempt++)
        {
            var result = await inspector.ExecuteAsync("if [ -f " + marker + " ]; then printf ready; fi", false, ct);
            Require(result.ExitCode == 0, "Could not inspect the running fixture command.");
            if (result.Output == "ready") return;
            await Task.Delay(50, ct);
        }
        throw new InvalidOperationException("The remote script did not begin executing.");
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
