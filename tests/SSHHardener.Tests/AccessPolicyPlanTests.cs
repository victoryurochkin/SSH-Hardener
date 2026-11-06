using System.Diagnostics;
using SSHHardener.Core;
using SSHHardener.Profiles;

namespace SSHHardener.Tests;

public sealed class AccessPolicyPlanTests
{
    [Theory]
    [InlineData("password")]
    [InlineData("sftp")]
    [InlineData("restricted")]
    [InlineData("totp")]
    public async Task AdvancedPlansArmRecoveryBeforeOneSensitiveStepAndNeverEmbedCredentialMaterial(string policy)
    {
        var options = InputValidatorsTests.ValidOptions with
        {
            GrantSudo = false, NoPasswordSudo = false, SudoMode = SudoPolicyMode.None,
            KeyPassphrase = "unique-key-passphrase-not-for-shell-plan"
        };
        options = policy switch
        {
            "password" => options with { SudoMode = SudoPolicyMode.Password, NewUserSudoPassword = "unique-account-password-not-for-shell-plan" },
            "sftp" => options with { AccountAccess = AccountAccess.SftpOnly, SftpReadOnly = true },
            "restricted" => options with { SudoMode = SudoPolicyMode.Restricted,
                RestrictedSudoCommands = [new("/usr/bin/systemctl", "--no-pager --full status fixture.service"), new("/usr/bin/systemctl", "restart fixture.service")] },
            _ => EnrolledTotp(options)
        };
        var plan = Build(options);
        var sensitive = Assert.Single(plan.Steps, step => step.SensitiveInput != SensitiveInputKind.None);
        Assert.Equal(SensitiveInputKind.AccessCredentials, sensitive.SensitiveInput);
        var ids = plan.Steps.Select(step => step.Id).ToList();
        Assert.True(ids.IndexOf("arm-rollback") < ids.IndexOf(sensitive.Id));
        Assert.True(ids.IndexOf("provision") < ids.IndexOf(sensitive.Id));
        Assert.True(ids.IndexOf(sensitive.Id) < ids.IndexOf("configure-access"));
        Assert.True(ids.IndexOf("configure-access") < ids.IndexOf("configure-final"));
        Assert.Contains("' </dev/null >> \"$tx/access-packages.log\"", sensitive.Script);
        var scripts = plan.Steps.SelectMany(step => new[] { step.Script, step.RollbackScript }).Distinct().ToArray();
        foreach (var script in scripts)
        {
            Assert.DoesNotContain(options.KeyPassphrase!, script);
            if (options.NewUserSudoPassword is not null) Assert.DoesNotContain(options.NewUserSudoPassword, script);
            if (options.TotpSecret is not null) Assert.DoesNotContain(options.TotpSecret, script);
            foreach (var code in options.TotpRecoveryCodes) Assert.DoesNotContain(code, script);
        }
        await ParseScriptsAsync(scripts);
    }

    [Fact]
    public void LegacyPlanHasNoSensitiveAccessProvisioningStep()
    {
        var plan = Build(InputValidatorsTests.ValidOptions with { GrantSudo = true, NoPasswordSudo = true });
        Assert.All(plan.Steps, step => Assert.Equal(SensitiveInputKind.None, step.SensitiveInput));
        Assert.DoesNotContain(plan.Steps, step => step.Id is "provision-access" or "configure-access");
    }

    [Fact]
    public void UnprivilegedTargetCannotRelyOnPasswordOnlyControlAfterSshPasswordsAreDisabled()
    {
        var options = InputValidatorsTests.ValidOptions with { SudoMode = SudoPolicyMode.None, GrantSudo = false, NoPasswordSudo = false };
        Assert.Throws<ArgumentException>(() => Build(options, controlKey: null));
    }

    [Theory]
    [InlineData("/bin/sh", "-c id")]
    [InlineData("/usr/bin/systemctl", "restart fixture.service; /bin/sh")]
    [InlineData("/usr/bin/systemctl", "restart *.service")]
    [InlineData("/usr/bin/systemctl", "restart fixture.service\n/bin/sh")]
    [InlineData("/usr/bin/systemctl", "status fixture.service")]
    [InlineData("/usr/bin/systemctl", "is-active fixture.service extra")]
    [InlineData("/usr/bin/systemctl", "restart ../fixture.service")]
    public void RestrictedSudoRejectsShellSyntaxWildcardsPagersAndAdditionalArguments(string executable, string arguments) =>
        Assert.Throws<ArgumentException>(() => AccessPolicyValidation.ValidateRestrictedCommand(new(executable, arguments)));

    private static HardeningOptions EnrolledTotp(HardeningOptions options)
    {
        var time = DateTimeOffset.UtcNow;
        var secret = TotpService.GenerateSecret();
        return options with { EnableTotp = true, TotpSecret = secret, TotpEnrollmentCode = TotpService.GenerateCode(secret, time),
            TotpEnrollmentConfirmedAt = time, TotpRecoveryCodes = TotpService.GenerateRecoveryCodes().ToArray() };
    }

    private static HardeningPlan Build(HardeningOptions options, string? controlKey = "C:\\fixture\\control.pem") => new PlanBuilder().Build(new ServerAudit
    {
        OsId = "debian", OsVersion = "12", HasRoot = true, InitSystem = "systemd", Firewall = "none",
        AdminAddress = "192.0.2.10", ServiceName = "ssh"
    }, new ConnectionOptions("fixture.example", 2222, "root", PrivateKeyPath: controlKey), options);

    private static async Task ParseScriptsAsync(IEnumerable<string> scripts)
    {
        var shell = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "bin", "sh.exe") : "/bin/sh";
        Assert.True(File.Exists(shell), "Install Git for Windows for the real POSIX syntax parser.");
        var directory = Path.Combine(Path.GetTempPath(), "sshhardener-access-syntax-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var index = 0;
            foreach (var script in scripts)
            {
                var file = Path.Combine(directory, index++ + ".sh");
                await File.WriteAllTextAsync(file, script.Replace("\r\n", "\n", StringComparison.Ordinal));
                var start = new ProcessStartInfo(shell) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true };
                start.ArgumentList.Add("-n"); start.ArgumentList.Add(file);
                using var process = Process.Start(start) ?? throw new InvalidOperationException("Cannot start the real shell parser.");
                var errors = await process.StandardError.ReadToEndAsync();
                using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await process.WaitForExitAsync(cancellation.Token);
                Assert.True(process.ExitCode == 0, "Advanced policy script did not parse: " + errors);
            }
        }
        finally
        {
            foreach (var file in Directory.GetFiles(directory)) File.Delete(file);
            Directory.Delete(directory);
        }
    }
}
