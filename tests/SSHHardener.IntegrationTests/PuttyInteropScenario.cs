using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using SSHHardener.Core;
using SSHHardener.Ssh;

internal static class PuttyInteropScenario
{
    // Public fixture-only passphrase. Never used for an existing user key or supplied in child argv.
    private const string Passphrase = "public-putty-interop-fixture-passphrase-2026";

    public static async Task PrepareAsync(string folder)
    {
        folder = Path.GetFullPath(folder);
        Directory.CreateDirectory(folder);
        Directory.CreateDirectory(Path.Combine(folder, "tool-output"));
        var source = Path.Combine(folder, "source.pem");
        var destination = Path.Combine(folder, "exported.ppk");
        var service = new KeyService();
        await service.GenerateRsaAsync(source, Passphrase);
        var before = SHA256.HashData(await File.ReadAllBytesAsync(source));
        await service.ExportRsaToPuttyAsync(source, destination, Passphrase, Passphrase);
        Check(before.SequenceEqual(SHA256.HashData(await File.ReadAllBytesAsync(source))), "Source key changed during export.");
        var original = service.ReadPublicKey(source, Passphrase);
        var exported = service.ReadPublicKey(destination, Passphrase);
        Check(Identity(original) == Identity(exported), "Export changed the RSA identity.");
        await File.WriteAllTextAsync(Path.Combine(folder, "source.sha256"), Convert.ToHexString(before));
        await File.WriteAllTextAsync(Path.Combine(folder, "expected.pub"), original + "\n");
        await File.WriteAllTextAsync(Path.Combine(folder, "expected.fingerprint"), KeyService.Fingerprint(original));
        var script = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../tests/SSHHardener.IntegrationTests/PuttyInterop.probe.sh"));
        File.Copy(script, Path.Combine(folder, "PuttyInterop.probe.sh"), false);
        Console.WriteLine("PASS: fresh encrypted PKCS#8 fixture exported to encrypted PPKv3 with unchanged source and public identity.");
    }

    public static async Task RunOracleAsync(string folder)
    {
        folder = Path.GetFullPath(folder);
        Check(OperatingSystem.IsWindows(), "The explicit WSL oracle runner requires Windows.");
        var mount = WslPath(folder);
        var name = "sshhardener-putty-oracle-" + Guid.NewGuid().ToString("N")[..12];
        var start = new ProcessStartInfo("wsl.exe")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in new[] { "-d", "Ubuntu", "--exec", "docker", "run", "--rm", "-i", "--network", "none", "--name", name,
            "-v", mount + ":/probe:ro", "-v", mount + "/tool-output:/out", "sshhardener-putty-interop:local", "/probe/PuttyInterop.probe.sh" })
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the isolated PuTTYgen oracle.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.StandardInput.WriteLineAsync(Passphrase);
        process.StandardInput.Close();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try { await process.WaitForExitAsync(deadline.Token); }
        catch { if (!process.HasExited) process.Kill(true); throw; }
        var stdout = await output;
        var stderr = await error;
        await File.WriteAllTextAsync(Path.Combine(folder, "tool-output", "oracle.txt"), stdout + "\n" + stderr);
        Console.Write(stdout);
        Check(process.ExitCode == 0, "Independent PuTTYgen failed: " + stderr);
        Check(Identity(await File.ReadAllTextAsync(Path.Combine(folder, "tool-output", "puttygen.pub"))) ==
            Identity(await File.ReadAllTextAsync(Path.Combine(folder, "expected.pub"))), "The independent tool exported another public key.");
        Check(Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(Path.Combine(folder, "source.pem")))) ==
            await File.ReadAllTextAsync(Path.Combine(folder, "source.sha256")), "The independent test changed the source fixture.");
    }

    public static async Task VerifyAsync(string folder, string host, int port)
    {
        folder = Path.GetFullPath(folder);
        Check(IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address), "This fixture verifier only permits loopback endpoints.");
        Check(port is > 0 and < 65536, "Invalid fixture port.");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var factory = new SshRemoteSessionFactory(new KnownHostsStore(Path.Combine(folder, "trust-" + Guid.NewGuid().ToString("N"))));
        await using var source = await factory.ConnectAsync(new ConnectionOptions(host, port, "testadmin",
            PrivateKeyPath: Path.Combine(folder, "source.pem"), Passphrase: Passphrase), _ => Task.FromResult(true), deadline.Token);
        await using var putty = await factory.ConnectAsync(new ConnectionOptions(host, port, "testadmin",
            PrivateKeyPath: Path.Combine(folder, "exported.ppk"), Passphrase: Passphrase),
            identity => Task.FromResult(identity.KeyBase64 == source.Identity.KeyBase64), deadline.Token);
        var result = await putty.ExecuteAsync("id -un", false, deadline.Token);
        result.EnsureSuccess("PPKv3 fixture login");
        Check(result.Output.Trim() == "testadmin", "Encrypted PPKv3 login identity did not match.");
        var key = new KeyService().ReadPublicKey(Path.Combine(folder, "exported.ppk"), Passphrase);
        Check(Identity(key) == Identity(await File.ReadAllTextAsync(Path.Combine(folder, "expected.pub"))), "Authenticated PPK public identity changed.");
        Check(Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(Path.Combine(folder, "source.pem")))) ==
            await File.ReadAllTextAsync(Path.Combine(folder, "source.sha256")), "SSH verification changed the source fixture.");
        const string message = "PASS: original PKCS#8 and same-key encrypted PPKv3 both authenticated through actual SSH.NET to an unchanged fixture authorized_keys.";
        await File.WriteAllTextAsync(Path.Combine(folder, "ssh-verification.txt"), message);
        Console.WriteLine(message);
    }

    private static string WslPath(string path)
    {
        Check(path.Length > 3 && char.IsAsciiLetter(path[0]) && path[1] == ':', "Use an absolute drive path for the explicit WSL test.");
        return "/mnt/" + char.ToLowerInvariant(path[0]) + path[2..].Replace('\\', '/');
    }
    private static string Identity(string key) => string.Join(' ', key.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Take(2));
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
