using System.Diagnostics;
using SSHHardener.Core;
using SSHHardener.Profiles;

namespace SSHHardener.Tests;

public sealed class ScriptSyntaxTests
{
    [Fact]
    public async Task AllGeneratedScriptsIncludingNestedRecoveryHeredocsParseAsPosixShell()
    {
        var shell = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "bin", "sh.exe")
            : "/bin/sh";
        Assert.True(File.Exists(shell), "Install Git for Windows to run the POSIX shell syntax check.");
        var plan = new PlanBuilder().Build(new ServerAudit
        {
            OsId = "debian", OsVersion = "12", HasRoot = true, InitSystem = "systemd",
            Firewall = "ufw", AdminAddress = "192.0.2.10", ServiceName = "ssh"
        }, new ConnectionOptions("server.example", 22, "root"),
            InputValidatorsTests.ValidOptions with { GrantSudo = true, NoPasswordSudo = true, ConfigureFail2Ban = true, CloseOldPort = true });
        var directory = Path.Combine(Path.GetTempPath(), "sshhardener-syntax-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var scripts = plan.Steps.Select(x => x.Script).Concat(plan.Steps.Select(x => x.RollbackScript)).Distinct().ToArray();
            for (var index = 0; index < scripts.Length; index++)
            {
                var path = Path.Combine(directory, index + ".sh");
                await File.WriteAllTextAsync(path, scripts[index].Replace("\r\n", "\n"));
                var start = new ProcessStartInfo(shell) { UseShellExecute = false, RedirectStandardError = true, CreateNoWindow = true };
                start.ArgumentList.Add("-n"); start.ArgumentList.Add(path);
                using var process = Process.Start(start) ?? throw new InvalidOperationException("Cannot start the shell parser.");
                var diagnostic = await process.StandardError.ReadToEndAsync();
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await process.WaitForExitAsync(deadline.Token);
                Assert.True(process.ExitCode == 0, $"Generated script {index} failed syntax validation: {diagnostic}");
            }
        }
        finally
        {
            foreach (var path in Directory.EnumerateFiles(directory)) File.Delete(path);
            Directory.Delete(directory);
        }
    }
}
