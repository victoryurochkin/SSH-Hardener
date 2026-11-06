using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SSHHardener.Core;
using SSHHardener.Ssh;

internal static class Ed25519KeyInteropScenario
{
    // Public, disposable fixture value. Never a user credential or a child-process argument.
    private const string Passphrase = "public-ed25519-interop-fixture-passphrase-2026";
    private static readonly string[] PrivateFiles = ["generated.ppk", "exported.ppk", "source.pem", "pkcs8-exported.ppk"];

    public static async Task PrepareAsync(string folder)
    {
        folder = Path.GetFullPath(folder);
        Directory.CreateDirectory(folder);
        Directory.CreateDirectory(Path.Combine(folder, "tool-output"));
        var service = new KeyService();
        var generated = await service.GenerateEd25519Async(Path.Combine(folder, "generated.ppk"), Passphrase);
        var exported = await service.ExportToPuttyAsync(Path.Combine(folder, "generated.ppk"), Path.Combine(folder, "exported.ppk"), Passphrase, Passphrase);
        Check(Identity(generated) == Identity(exported), "PPK export changed the Ed25519 public identity.");
        var pkcs8 = await service.GenerateEd25519Async(Path.Combine(folder, "source.pem"), Passphrase,
            format: PrivateKeyFormat.EncryptedPkcs8Pem);
        var converted = await service.ExportToPuttyAsync(Path.Combine(folder, "source.pem"), Path.Combine(folder, "pkcs8-exported.ppk"), Passphrase, Passphrase);
        Check(Identity(pkcs8) == Identity(converted), "PKCS#8 export changed the Ed25519 public identity.");
        await File.WriteAllTextAsync(Path.Combine(folder, "expected-generated.pub"), generated + "\n");
        await File.WriteAllTextAsync(Path.Combine(folder, "expected-pkcs8.pub"), pkcs8 + "\n");
        await File.WriteAllTextAsync(Path.Combine(folder, "expected.pub"), generated + "\n" + pkcs8 + "\n");
        var hashes = new Dictionary<string, string>();
        foreach (var name in PrivateFiles)
            hashes.Add(name, Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(Path.Combine(folder, name)))));
        await File.WriteAllTextAsync(Path.Combine(folder, "fixture-sha256.json"), JsonSerializer.Serialize(hashes));
        var script = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../tests/SSHHardener.IntegrationTests/Ed25519KeyInterop.probe.sh"));
        File.Copy(script, Path.Combine(folder, "Ed25519KeyInterop.probe.sh"), false);
        Console.WriteLine("PASS: fresh encrypted Ed25519 PPKv3 and RFC 8410 PKCS#8 generated; same-key PPK exports retain each identity.");
    }

    public static async Task RunOracleAsync(string folder)
    {
        folder = Path.GetFullPath(folder);
        Check(OperatingSystem.IsWindows(), "The explicit WSL oracle runner requires Windows.");
        var mount = WslPath(folder);
        var start = new ProcessStartInfo("wsl.exe")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in new[] { "-d", "Ubuntu", "--exec", "docker", "run", "--rm", "-i", "--network", "none",
            "--name", "sshhardener-ed25519-oracle-" + Guid.NewGuid().ToString("N")[..12],
            "-v", mount + ":/probe:ro", "-v", mount + "/tool-output:/out", "sshhardener-putty-interop:local", "/probe/Ed25519KeyInterop.probe.sh" })
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the isolated PuTTYgen oracle.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.StandardInput.WriteLineAsync(Passphrase);
        process.StandardInput.Close();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        try { await process.WaitForExitAsync(deadline.Token); }
        catch { if (!process.HasExited) process.Kill(true); throw; }
        var stdout = await output;
        var stderr = await error;
        await File.WriteAllTextAsync(Path.Combine(folder, "tool-output", "oracle.txt"), stdout + "\n" + stderr);
        Console.Write(stdout);
        Check(process.ExitCode == 0, "Independent PuTTYgen failed: " + stderr);
        foreach (var name in new[] { "generated", "exported", "pkcs8-exported" })
        {
            var expected = Path.Combine(folder, name == "pkcs8-exported" ? "expected-pkcs8.pub" : "expected-generated.pub");
            Check(Identity(await File.ReadAllTextAsync(Path.Combine(folder, "tool-output", name + ".pub"))) ==
                Identity(await File.ReadAllTextAsync(expected)), "Independent private conversion changed " + name + " identity.");
        }
        await VerifySourceHashesAsync(folder);
    }

    public static async Task VerifyAsync(string folder, string host, int port)
    {
        folder = Path.GetFullPath(folder);
        Check(IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address), "This fixture permits only loopback SSH endpoints.");
        Check(port is > 0 and < 65536, "Invalid fixture port.");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var factory = new SshRemoteSessionFactory(new KnownHostsStore(Path.Combine(folder, "trust-" + Guid.NewGuid().ToString("N"))));
        string? pinnedHostKey = null;
        foreach (var name in PrivateFiles)
        {
            await using var session = await factory.ConnectAsync(new ConnectionOptions(host, port, "testadmin",
                PrivateKeyPath: Path.Combine(folder, name), Passphrase: Passphrase),
                identity => Task.FromResult(pinnedHostKey is null || identity.KeyBase64 == pinnedHostKey), deadline.Token);
            pinnedHostKey ??= session.Identity.KeyBase64;
            var result = await session.ExecuteAsync("id -un", false, deadline.Token);
            result.EnsureSuccess("Encrypted Ed25519 fixture login: " + name);
            Check(result.Output.Trim() == "testadmin", "Authenticated fixture identity did not match.");
            Console.WriteLine("PASS: actual SSH.NET authentication with " + name + ".");
        }
        await VerifySourceHashesAsync(folder);
        const string message = "PASS: all four encrypted Ed25519 representations authenticated through actual SSH.NET against unchanged fixture authorized_keys; source hashes unchanged.";
        await File.WriteAllTextAsync(Path.Combine(folder, "ssh-verification.txt"), message);
        Console.WriteLine(message);
    }

    private static async Task VerifySourceHashesAsync(string folder)
    {
        var hashes = JsonSerializer.Deserialize<Dictionary<string, string>>(await File.ReadAllTextAsync(Path.Combine(folder, "fixture-sha256.json")))
            ?? throw new InvalidOperationException("Missing fixture hash manifest.");
        foreach (var name in PrivateFiles)
            Check(hashes[name] == Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(Path.Combine(folder, name)))),
                "The integration test changed fixture key " + name + ".");
    }

    private static string WslPath(string path)
    {
        Check(path.Length > 3 && char.IsAsciiLetter(path[0]) && path[1] == ':', "Use an absolute drive path for the explicit WSL test.");
        return "/mnt/" + char.ToLowerInvariant(path[0]) + path[2..].Replace('\\', '/');
    }
    private static string Identity(string key) => string.Join(' ', key.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Take(2));
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
