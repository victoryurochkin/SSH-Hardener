using SSHHardener.Core;
using SSHHardener.Profiles;

namespace SSHHardener.Tests;

public sealed class Fail2BanPlanTests
{
    [Fact]
    public void DefaultsLimitMatchingFailuresAndConnectionAuthenticationAttempts()
    {
        var options = new HardeningOptions();
        Assert.Equal(3, options.MaxRetry);
        Assert.Equal(600, options.FindTimeSeconds);
        Assert.Equal(3600, options.BanSeconds);
        Assert.Equal(3, options.MaxAuthTries);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(21)]
    public void InvalidConnectionAuthenticationLimitIsRejected(int attempts) =>
        Assert.Throws<ArgumentException>(() => InputValidators.Validate(InputValidatorsTests.ValidOptions with { MaxAuthTries = attempts }));

    [Theory]
    [InlineData(59)]
    [InlineData(86401)]
    public void InvalidFailureWindowIsRejected(int seconds) =>
        Assert.Throws<ArgumentException>(() => InputValidators.Validate(InputValidatorsTests.ValidOptions with { FindTimeSeconds = seconds }));

    [Fact]
    public void Fail2BanInstallationRunsOnlyAfterRecoveryIsArmedAndBeforeAccessChanges()
    {
        var steps = Plan().Steps.Select(x => x.Id).ToList();
        Assert.True(steps.IndexOf("arm-rollback") < steps.IndexOf("configure-fail2ban"));
        Assert.True(steps.IndexOf("configure-fail2ban") < steps.IndexOf("provision"));
        Assert.True(steps.IndexOf("configure-fail2ban") < steps.IndexOf("configure-dual-port"));
    }

    [Theory]
    [InlineData("debian", "12", "apt")]
    [InlineData("ubuntu", "24.04", "apt")]
    [InlineData("rocky", "9", "unsupported")]
    public void PackageProviderComesFromTheAuditedDistribution(string os, string version, string expected)
    {
        var step = Plan(os, version).Steps.Single(x => x.Id == "configure-fail2ban");
        Assert.Contains("package_manager='" + expected + "'", step.Script);
    }

    [Fact]
    public void ManagedJailIncludesPasswordAndPublicKeyFailuresAndProtectsTheAdministrator()
    {
        var step = Plan().Steps.Single(x => x.Id == "configure-fail2ban");
        Assert.Contains("/etc/fail2ban/jail.d/sshhardener-sshd.local", step.Script);
        Assert.Contains("[sshhardener-sshd]", step.Script);
        Assert.Contains("filter = sshd[mode=normal,publickey=any]", step.Script);
        Assert.Contains("backend = systemd", step.Script);
        Assert.Contains("maxretry='3'", step.Script);
        Assert.Contains("findtime='600'", step.Script);
        Assert.Contains("bantime='3600'", step.Script);
        Assert.Contains("192.0.2.10", step.Script);
        Assert.Contains("127.0.0.1/8", step.Script);
        Assert.Contains("::1", step.Script);
        Assert.Contains("python3-systemd", step.Script);
        Assert.Contains("apt-get", step.Script);
        Assert.DoesNotContain("> /etc/fail2ban/jail.local", step.Script);
    }

    [Fact]
    public void UserSelectedLimitsReachBothThePlanAndSshPolicy()
    {
        var plan = Plan(options: InputValidatorsTests.ValidOptions with
        {
            ConfigureFail2Ban = true, CreateUser = false, MaxRetry = 5,
            FindTimeSeconds = 1200, MaxAuthTries = 4
        });
        Assert.Contains("maxretry='5'", plan.Preview);
        Assert.Contains("findtime='1200'", plan.Preview);
        Assert.Contains("maxauthtries='4'", plan.Preview);
        Assert.Contains("MaxAuthTries", plan.Steps.Single(x => x.Id == "configure-final").Script);
        Assert.Contains("LogLevel VERBOSE", plan.Steps.Single(x => x.Id == "configure-final").Script);
    }

    [Fact]
    public void RecoveryDoesNotRemoveInstalledPackagesOrOverwriteGeneralJailConfiguration()
    {
        var rollback = Plan().Steps.Single(x => x.Id == "configure-fail2ban").RollbackScript;
        Assert.DoesNotMatch(@"apt-get\s+(?:remove|purge|autoremove)", rollback);
        Assert.Contains("/etc/fail2ban/jail.d/sshhardener-sshd.local", rollback);
        Assert.Contains("fail2ban.service", rollback);
        Assert.DoesNotContain("> /etc/fail2ban/jail.local", rollback);
    }

    private static HardeningPlan Plan(string os = "debian", string version = "12", HardeningOptions? options = null) =>
        new PlanBuilder().Build(new ServerAudit
        {
            OsId = os, OsVersion = version, HasRoot = true, InitSystem = "systemd", Firewall = "none",
            AdminAddress = "192.0.2.10", ServiceName = os == "rocky" ? "sshd" : "ssh"
        }, new ConnectionOptions("fixture.invalid", 22, "root"), options ?? InputValidatorsTests.ValidOptions with
        {
            ConfigureFail2Ban = true, CreateUser = false
        });
}
