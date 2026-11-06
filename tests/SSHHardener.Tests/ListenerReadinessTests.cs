using System.Diagnostics;
using System.Text;
using SSHHardener.Core;
using SSHHardener.Profiles;

namespace SSHHardener.Tests;

public sealed class ListenerReadinessTests
{
    [Fact]
    public async Task DelayedNewListenerIsAwaitedInsteadOfFailingTheFirstProbe()
    {
        var result = await ProbeAsync("delayed-new", "dual", "no");
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("READY_TICKS=3", result.Output);
    }

    [Fact]
    public async Task MissingNewListenerFailsAfterBoundedLogicalDeadline()
    {
        var result = await ProbeAsync("never-new", "dual", "no");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("FAIL_TICKS=15", result.Error);
    }

    [Fact]
    public async Task ListeningSocketsDoNotSubstituteForAnActiveSshService()
    {
        var result = await ProbeAsync("inactive-service", "dual", "no");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("FAIL_TICKS=15", result.Error);
    }

    [Theory]
    [InlineData("dual")]
    [InlineData("final")]
    public async Task OldListenerIsRequiredWhenThePlanKeepsIt(string phase)
    {
        var result = await ProbeAsync("delayed-old", phase, "no");
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("READY_TICKS=2", result.Output);
    }

    [Fact]
    public async Task PermanentlyMissingOldListenerCannotPassDualPortReadiness()
    {
        var result = await ProbeAsync("never-old", "dual", "yes");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("FAIL_TICKS=15", result.Error);
    }

    [Fact]
    public async Task FinalPhaseWaitsForTheOldListenerToClose()
    {
        var result = await ProbeAsync("closing-old", "final", "yes");
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("READY_TICKS=4", result.Output);
    }

    [Fact]
    public async Task FinalPhaseRejectsAnOldListenerThatNeverCloses()
    {
        var result = await ProbeAsync("both-open", "final", "yes");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("FAIL_TICKS=15", result.Error);
    }

    [Fact]
    public async Task RecoveryWaitsForOriginalListenerAndRemovalOfTheNewOne()
    {
        var result = await ProbeAsync("recovering", "recovery", "yes");
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("READY_TICKS=4", result.Output);
    }

    [Theory]
    [InlineData("recovery-old-missing")]
    [InlineData("both-open")]
    public async Task RecoveryCannotConfirmMissingOriginalOrLingeringNewListener(string scenario)
    {
        var result = await ProbeAsync(scenario, "recovery", "yes");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("FAIL_TICKS=15", result.Error);
    }

    [Theory]
    [InlineData("new-query-error")]
    [InlineData("old-query-error")]
    public async Task FailedSocketQueryCannotBeMistakenForAClosedPort(string scenario)
    {
        var result = await ProbeAsync(scenario, "final", "yes");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("FAIL_TICKS=0", result.Error);
        Assert.DoesNotContain("READY_TICKS", result.Output);
    }

    private static async Task<ShellResult> ProbeAsync(string scenario, string phase, string closeOld)
    {
        var shell = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "bin", "sh.exe")
            : "/bin/sh";
        Assert.True(File.Exists(shell), "Install Git for Windows for executable POSIX shell behavior checks.");
        var generated = new PlanBuilder().Build(new ServerAudit
        {
            OsId = "debian", OsVersion = "12", HasRoot = true, InitSystem = "systemd",
            Firewall = "none", AdminAddress = "192.0.2.10", ServiceName = "ssh"
        }, new ConnectionOptions("fixture.invalid", 22, "root"),
            InputValidatorsTests.ValidOptions with { GrantSudo = true, NoPasswordSudo = true }).Steps.Single(x => x.Id == "configure-dual-port").Script;
        var start = generated.IndexOf("wait_for_ssh_listeners()", StringComparison.Ordinal);
        var end = start >= 0 ? generated.IndexOf("guard()", start, StringComparison.Ordinal) : -1;
        Assert.True(start >= 0 && end > start, "The generated listener readiness helper was not found.");
        var helper = generated[start..end];
        var fixture = """
            set -eu
            port=22022
            oldport=22
            service=ssh
            tick=0
            fail() { printf 'FAIL_TICKS=%s\n%s\n' "$tick" "$*" >&2; exit 7; }
            systemctl() { [ "$scenario" != inactive-service ]; }
            sleep() {
              [ "$1" = 1 ] || fail 'Readiness uses an unexpected polling interval.'
              tick=$((tick+1))
              [ "$tick" -le 16 ] || fail 'Readiness polling is unbounded.'
            }
            ss() {
              case "$*" in
                *':22022'*)
                  [ "$scenario" != new-query-error ] || return 2
                  [ "$scenario" != never-new ] || return 0
                  [ "$scenario" != recovery-old-missing ] || return 0
                  if [ "$scenario" = delayed-new ] && [ "$tick" -lt 3 ]; then return 0; fi
                  if [ "$scenario" = recovering ] && [ "$tick" -ge 4 ]; then return 0; fi
                  printf 'LISTEN 0 128 0.0.0.0:22022 0.0.0.0:*\n'
                  ;;
                *':22'*)
                  [ "$scenario" != old-query-error ] || return 2
                  [ "$scenario" != never-old ] || return 0
                  [ "$scenario" != recovery-old-missing ] || return 0
                  if [ "$scenario" = delayed-old ] && [ "$tick" -lt 2 ]; then return 0; fi
                  if [ "$scenario" = recovering ] && [ "$tick" -lt 2 ]; then return 0; fi
                  if [ "$scenario" = closing-old ] && [ "$tick" -ge 4 ]; then return 0; fi
                  printf 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n'
                  ;;
                *) printf 'Fixture socket diagnostics\n';;
              esac
            }
            """;
        var script = fixture + "\nscenario=" + Shell.Quote(scenario) + "\nclose_old=" + Shell.Quote(closeOld) + "\n" + helper
            + "\nif wait_for_ssh_listeners " + Shell.Quote(phase)
            + "; then printf 'READY_TICKS=%s\\n' \"$tick\"; else printf 'FAIL_TICKS=%s\\n' \"$tick\" >&2; exit 7; fi\n";
        var path = Path.Combine(Path.GetTempPath(), "sshhardener-listener-" + Guid.NewGuid().ToString("N") + ".sh");
        try
        {
            await File.WriteAllTextAsync(path, script.Replace("\r\n", "\n"), new UTF8Encoding(false));
            var startInfo = new ProcessStartInfo(shell)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
            };
            startInfo.ArgumentList.Add(path);
            using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start the listener behavior shell.");
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            try { await process.WaitForExitAsync(deadline.Token); }
            catch { if (!process.HasExited) process.Kill(true); throw; }
            return new ShellResult(process.ExitCode, await output, await error);
        }
        finally { File.Delete(path); }
    }

    private sealed record ShellResult(int ExitCode, string Output, string Error);
}
