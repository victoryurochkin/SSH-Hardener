using System.Diagnostics;
using System.Text;
using System.Text.Json;
using SSHHardener.Core;
using SSHHardener.Profiles;

namespace SSHHardener.Tests;

/// <summary>
/// Executes the actual generated firewall inspector against isolated standard-library fixtures.
/// Development requirement: Python 3.11+; SSH_HARDENER_TEST_PYTHON may select an executable
/// by path/name. Otherwise Windows uses "py -3" and other platforms use "python3".
/// No package installation, network access or host firewall commands are performed.
/// </summary>
public sealed class ManagedFirewallProbeTests
{
    [Theory]
    [InlineData("baseline", true)]
    [InlineData("tampered-hash", false)]
    [InlineData("writable-policy", false)]
    [InlineData("unsafe-base-chain", false)]
    [InlineData("foreign-input-accept", false)]
    [InlineData("foreign-nft-table", false)]
    [InlineData("hidden-nft-rule", false)]
    [InlineData("unknown-nft-set", false)]
    [InlineData("own-lookalike-chain", false)]
    [InlineData("drop-policy", false)]
    [InlineData("query-failure", false)]
    [InlineData("legacy-owned-empty-nft", true)]
    [InlineData("legacy-foreign-native-nft", false)]
    public async Task ActualManagedFirewallInspectorAcceptsOnlyRecognizedState(string scenario, bool expectedAcceptance)
    {
        var audit = new ServerAudit
        {
            OsId = "debian", OsVersion = "12", InitSystem = "systemd", Firewall = "none",
            HasRoot = true, AdminAddress = "192.0.2.10", ServiceName = "ssh"
        };
        var plan = new PlanBuilder().Build(audit, new ConnectionOptions("fixture.example", 22, "root"),
            InputValidatorsTests.ValidOptions with { GrantSudo = true, NoPasswordSudo = true });
        var preflight = plan.Steps.Single(step => step.Id == "preflight").Script.Replace("\r\n", "\n");
        const string marker = "/usr/bin/python3 - <<'SSHARDENER_OWNED_FIREWALL_PY'\n";
        var start = preflight.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, "The public preflight plan must contain the actual managed-firewall Python helper.");
        start += marker.Length;
        var end = preflight.IndexOf("\nSSHARDENER_OWNED_FIREWALL_PY", start, StringComparison.Ordinal);
        Assert.True(end > start, "The generated Python helper must have a complete heredoc terminator.");
        var helper = preflight[start..end];
        var fixture = Path.Combine(AppContext.BaseDirectory, "Fixtures", "managed-firewall-fixture.py");
        Assert.True(File.Exists(fixture), "The standard-library firewall fixture must be copied to the test output.");
        var directory = Path.Combine(Path.GetTempPath(), "sshhardener-firewall-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var helperPath = Path.Combine(directory, "actual-managed-firewall.py");
        try
        {
            await File.WriteAllTextAsync(helperPath, helper, new UTF8Encoding(false), CancellationToken.None);
            var selectedPython = Environment.GetEnvironmentVariable("SSH_HARDENER_TEST_PYTHON");
            var useWindowsLauncher = string.IsNullOrWhiteSpace(selectedPython) && OperatingSystem.IsWindows();
            var processInfo = new ProcessStartInfo
            {
                FileName = !string.IsNullOrWhiteSpace(selectedPython) ? selectedPython : useWindowsLauncher ? "py" : "python3",
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                WorkingDirectory = directory
            };
            if (useWindowsLauncher) processInfo.ArgumentList.Add("-3");
            processInfo.ArgumentList.Add("-I");
            processInfo.ArgumentList.Add(fixture);
            processInfo.ArgumentList.Add(helperPath);
            processInfo.ArgumentList.Add(scenario);
            Process process;
            try { process = Process.Start(processInfo) ?? throw new InvalidOperationException("Python did not start."); }
            catch (System.ComponentModel.Win32Exception exception)
            {
                throw new InvalidOperationException("Managed-firewall tests require Python 3.11+. Install the Python launcher or set SSH_HARDENER_TEST_PYTHON to a Python executable.", exception);
            }
            using (process)
            using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                var output = process.StandardOutput.ReadToEndAsync();
                var error = process.StandardError.ReadToEndAsync();
                try { await process.WaitForExitAsync(timeout.Token); }
                catch (OperationCanceledException)
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                    throw new TimeoutException("The isolated managed-firewall fixture exceeded its 10-second time limit.");
                }
                var stdout = await output;
                var stderr = await error;
                Assert.True(process.ExitCode == 0, $"Fixture failed for {scenario}: exit={process.ExitCode}\n{stdout}\n{stderr}");
                using var result = JsonDocument.Parse(stdout);
                Assert.Equal(expectedAcceptance, result.RootElement.GetProperty("accepted").GetBoolean());
            }
        }
        finally
        {
            if (File.Exists(helperPath)) File.Delete(helperPath);
            Directory.Delete(directory);
        }
    }
}
