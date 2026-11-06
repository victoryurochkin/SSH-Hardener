using SSHHardener.Core;
using SSHHardener.Ssh;
using SSHHardener.Profiles;

// This is an explicit integration runner, not a test which silently passes without Docker.
var folder = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../artifacts/integration"));
if (args.Length > 1 && args[0] == "--prepare")
{
    folder = Path.GetFullPath(args[1]);
    Directory.CreateDirectory(folder);
    var path = Path.Combine(folder, "fixture.pem");
    if (!File.Exists(path)) await new KeyService().GenerateRsaAsync(path, "integration-key-passphrase");
    Console.WriteLine("Integration public key prepared: " + path + ".pub");
    return 0;
}
if (args.Length > 0) folder = Path.GetFullPath(args[0]);
var host = args.Length > 1 ? args[1] : "127.0.0.1";
var privateKey = Path.Combine(folder, "fixture.pem");
if (!File.Exists(privateKey)) throw new FileNotFoundException("Run --prepare before starting Docker Compose.");
var failed = 0;
foreach (var (port, os) in new[] { (22412, "Debian 12"), (22424, "Ubuntu 24.04"), (22490, "Rocky 9") })
{
    try
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var factory = new SshRemoteSessionFactory(new KnownHostsStore(Path.Combine(folder, "trust-" + Guid.NewGuid().ToString("N"))));
        var passwordOptions = new ConnectionOptions(host, port, "testadmin", Password: "TestOnly-SSHHardener-2026!");
        IRemoteSession? connected = null;
        for (var retry = 0; retry < 20; retry++)
        {
            try { connected = await factory.ConnectAsync(passwordOptions, _ => Task.FromResult(true), deadline.Token); break; }
            catch when (retry < 19 && !deadline.IsCancellationRequested) { await Task.Delay(500, deadline.Token); }
        }
        await using var password = connected ?? throw new InvalidOperationException("SSH fixture did not start.");
        var command = await password.ExecuteAsync("id -un", false, deadline.Token);
        command.EnsureSuccess("Password connection");
        Check(command.Output.Trim() == "testadmin", "Password login identity");
        var sudo = await password.ExecuteAsync("id -u", true, deadline.Token);
        sudo.EnsureSuccess("NOPASSWD sudo");
        Check(sudo.Output.Trim() == "0", "NOPASSWD root identity");
        var payload = new string('x', 16_384);
        var stdin = await password.ExecuteAsync("cat <<'SSHARDENER_PAYLOAD'\n" + payload + "\nSSHARDENER_PAYLOAD", false, deadline.Token);
        stdin.EnsureSuccess("Script stdin transport");
        Check(stdin.Output.Trim() == payload, "Entire script is delivered through stdin");
        var exit = await password.ExecuteAsync("printf diagnostic >&2; exit 17", false, deadline.Token);
        Check(exit.ExitCode == 17 && exit.Error == "diagnostic", "Exit code/stderr propagation");
        await using var key = await factory.ConnectAsync(new ConnectionOptions(host, port, "testadmin",
            PrivateKeyPath: privateKey, Passphrase: "integration-key-passphrase"),
            identity => Task.FromResult(identity.KeyBase64 == password.Identity.KeyBase64), deadline.Token);
        var keyResult = await key.ExecuteAsync("id -un", false, deadline.Token);
        Check(keyResult.ExitCode == 0 && keyResult.Output.Trim() == "testadmin", "Encrypted private-key authentication");
        await using var withPasswordSudo = await factory.ConnectAsync(new ConnectionOptions(host, port, "passwordsudo",
            Password: "TestOnly-SSHHardener-2026!", SudoPassword: "TestOnly-SSHHardener-2026!"),
            identity => Task.FromResult(identity.KeyBase64 == password.Identity.KeyBase64), deadline.Token);
        var root = await withPasswordSudo.ExecuteAsync("id -u", true, deadline.Token);
        Check(root.ExitCode == 0 && root.Output.Trim() == "0", "Password-based sudo across command channels");
        var audit = await new AuditService().AuditAsync(password, deadline.Token);
        Check(audit.HasRoot && audit.OsId != "unknown", "Read-only audit detects OS and privilege");
        Check(System.Net.IPAddress.TryParse(audit.AdminAddress, out _), "Administrator address survives sudo environment filtering");
        var readOnly = false;
        try
        {
            new PlanBuilder().Build(audit, passwordOptions, new HardeningOptions
            {
                Username = "testadmin", CreateUser = false, PrivateKeyPath = privateKey,
                PublicKey = new KeyService().ReadPublicKey(privateKey, "integration-key-passphrase")
            });
        }
        catch (NotSupportedException) { readOnly = true; }
        Check(readOnly, "A container without systemd cannot apply host changes");
        await LinuxProvisionScenario.VerifyAsync(password, factory, audit, privateKey,
            new KeyService().ReadPublicKey(privateKey, "integration-key-passphrase"), deadline.Token);
        var rejected = false;
        try
        {
            await using var unexpected = await factory.ConnectAsync(passwordOptions,
                _ => Task.FromResult(false), deadline.Token);
        }
        catch (InvalidOperationException) { rejected = true; }
        Check(rejected, "A stricter host pin is enforced even for a known endpoint");
        Console.WriteLine($"PASS {os}: transport, sudo, host pin, audit, init guard, real user/key/sudo provisioning and recovery (service probe mocked).");
    }
    catch (Exception ex) { failed++; Console.Error.WriteLine($"FAIL {os}: {ex.GetType().Name}: {ex.Message}"); }
}
return failed == 0 ? 0 : 1;

static void Check(bool value, string scenario)
{
    if (!value) throw new InvalidOperationException("Failed: " + scenario);
}
