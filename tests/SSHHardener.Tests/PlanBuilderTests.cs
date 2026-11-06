using SSHHardener.Core;
using SSHHardener.Profiles;

namespace SSHHardener.Tests;

public sealed class PlanBuilderTests
{
    private static ServerAudit Audit => new() { OsId = "debian", OsVersion = "12", HasRoot = true, InitSystem = "systemd", Firewall = "none", AdminAddress = "192.0.2.10", ServiceName = "ssh" };
    private static HardeningOptions Options => InputValidatorsTests.ValidOptions with { GrantSudo = true, NoPasswordSudo = true };
    private static ConnectionOptions Connection => new("server.example", 2222, "root", Password: "connection-secret");

    [Theory]
    [InlineData("alpine", "3.21")]
    [InlineData("centos", "7")]
    [InlineData("debian", "10")]
    public void UnsupportedOsIsAuditOnly(string os, string version) =>
        Assert.Throws<NotSupportedException>(() => new PlanBuilder().Build(Audit with { OsId = os, OsVersion = version }, Connection, Options));

    [Fact]
    public void SocketActivationIsNotSilentlyTreatedAsService() =>
        Assert.Throws<NotSupportedException>(() => new PlanBuilder().Build(Audit with { SocketActivated = true }, Connection, Options));

    [Theory]
    [InlineData("nftables")]
    [InlineData("iptables")]
    [InlineData("ambiguous")]
    public void UnmanagedFirewallCannotBeChanged(string firewall) =>
        Assert.Throws<NotSupportedException>(() => new PlanBuilder().Build(Audit with { Firewall = firewall }, Connection, Options));

    [Fact]
    public void NewUnprivilegedUserCannotBecomeOnlyRecoveryPath() =>
        Assert.Throws<ArgumentException>(() => new PlanBuilder().Build(Audit, Connection, Options with { GrantSudo = false, NoPasswordSudo = false }));

    [Fact]
    public void GeneratedCommandsExcludeCredentialsAndRetainActualOriginalPort()
    {
        var plan = new PlanBuilder().Build(Audit, Connection, Options with { KeyPassphrase = "key-secret" });
        Assert.DoesNotContain("connection-secret", plan.Preview);
        Assert.DoesNotContain("key-secret", plan.Preview);
        Assert.DoesNotMatch(@"\bcmp\b", plan.Preview);
        Assert.Contains("oldport='2222'", plan.Preview);
        Assert.DoesNotContain("@@", plan.Preview);
        Assert.Equal(new[] { "preflight", "arm-rollback", "provision", "open-port", "configure-dual-port", "configure-final", "commit" }, plan.Steps.Select(x => x.Id));
        Assert.Contains("[Timer]", plan.Preview);
        Assert.Contains("Before=ssh.service sshd.service fail2ban.service", plan.Preview);
    }
}
