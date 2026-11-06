using System.Buffers.Binary;
using System.Text;
using SSHHardener.Core;
using SSHHardener.Profiles;

internal static class Fail2BanScenario
{
    // Explicit fixture export only. These scripts are never executed against a user endpoint.
    public static void Export(string folder)
    {
        folder = Path.GetFullPath(folder);
        Directory.CreateDirectory(folder);
        using var wire = new MemoryStream();
        foreach (var field in new[] { Encoding.ASCII.GetBytes("ssh-ed25519"), Enumerable.Range(1, 32).Select(x => (byte)x).ToArray() })
        {
            var length = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(length, (uint)field.Length);
            wire.Write(length); wire.Write(field);
        }
        var key = "ssh-ed25519 " + Convert.ToBase64String(wire.ToArray()) + " fail2ban-plan-fixture";
        var plan = new PlanBuilder().Build(new ServerAudit
        {
            OsId = "debian", OsVersion = "12", HasRoot = true, InitSystem = "systemd",
            Firewall = "none", AdminAddress = "192.0.2.10", ServiceName = "ssh"
        }, new ConnectionOptions("fixture.invalid", 22, "root"), new HardeningOptions
        {
            ConfigureFail2Ban = true, Username = "testadmin", CreateUser = false,
            NewPort = 22022, PublicKey = key, PrivateKeyPath = "unused-public-plan-fixture",
            MaxRetry = 3, FindTimeSeconds = 600, BanSeconds = 3600, MaxAuthTries = 3
        });
        var stage = plan.Steps.Single(x => x.Id == "configure-fail2ban");
        Write("configure-fail2ban.sh", stage.Script);
        Write("rollback.sh", stage.RollbackScript);
        const string marker = "# SSHHardener managed firewall probe end";
        var helperStart = stage.Script.IndexOf("only_managed_fail2ban_firewall()", StringComparison.Ordinal);
        var markerStart = stage.Script.IndexOf(marker, helperStart >= 0 ? helperStart : 0, StringComparison.Ordinal);
        if (helperStart < 0 || markerStart < helperStart) throw new InvalidOperationException("The actual managed-firewall helper was not found in the generated plan.");
        Write("managed-firewall-helper.sh", stage.Script[helperStart..(markerStart + marker.Length)] + "\n");
        Write("scenario.env", "txid=" + Shell.Quote(plan.TransactionId) + "\njail=sshhardener-sshd\n");
        Console.WriteLine("Exported actual Fail2ban preparation and rollback scripts: " + folder);

        void Write(string name, string content) => File.WriteAllText(Path.Combine(folder, name), content.Replace("\r\n", "\n"), new UTF8Encoding(false));
    }
}
