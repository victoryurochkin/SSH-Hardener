using SSHHardener.Core;
using SSHHardener.Profiles;

namespace SSHHardener.Tests;

public sealed class EngineTests : IDisposable
{
    private const string Id = "20261106120000-abcdef123456";
    private readonly string _key = Path.Combine(Path.GetTempPath(), "sshhardener-engine-test-" + Guid.NewGuid().ToString("N"));
    private readonly List<string> _events = [];
    private string _state = "pending";
    private static ConnectionOptions OriginalOptions => new("server.example", 22, "root", Password: "original-secret");
    private static HostIdentity Pin => new("server.example", 22, "ssh-ed25519", "SHA256:pinned", "cGlubmVk");

    public EngineTests() => File.WriteAllText(_key, "existence-only fixture; mock transport does not parse it");

    [Fact]
    public async Task CommitFollowsTwoFreshPinnedKeyOnlyAdministrativeLogins()
    {
        var factory = Factory();
        var result = await new HardeningEngine(factory).ApplyAsync(Original(), Plan(), null, CancellationToken.None);
        Assert.True(result.Committed);
        Assert.False(result.RolledBack);
        Assert.Equal(2, factory.Connections.Count);
        Assert.All(factory.Connections, connection =>
        {
            Assert.Equal(22022, connection.Port);
            Assert.Equal("sshadmin", connection.Username);
            Assert.Equal(_key, connection.PrivateKeyPath);
            Assert.Null(connection.Password);
            Assert.Null(connection.SudoPassword);
        });
        Assert.True(_events.IndexOf("new2:privilege") < _events.IndexOf("new2:commit"));
        Assert.True(_events.IndexOf("new1:configure-final") < _events.IndexOf("connect2"));
        Assert.DoesNotContain(_events, x => x.Contains("rollback.sh", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ChangedHostIdentityNeverReachesCommitAndTriggersRecovery()
    {
        var factory = Factory(changedKey: true);
        var result = await new HardeningEngine(factory).ApplyAsync(Original(), Plan(), null, CancellationToken.None);
        Assert.False(result.Committed);
        Assert.True(result.RolledBack);
        Assert.DoesNotContain(_events, x => x.EndsWith(":commit", StringComparison.Ordinal));
        Assert.Contains(_events, x => x.Contains("rollback.sh", StringComparison.Ordinal));
    }

    [Fact]
    public async Task FinalVerificationFailureKeepsCommitUnexecuted()
    {
        var factory = Factory(failSecondPrivilege: true);
        var result = await new HardeningEngine(factory).ApplyAsync(Original(), Plan(), null, CancellationToken.None);
        Assert.False(result.Committed);
        Assert.True(result.RolledBack);
        Assert.DoesNotContain(_events, x => x.EndsWith(":commit", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PreflightFailureDoesNotClaimRollbackOrRunMutation()
    {
        var original = Original(failPreflight: true);
        var result = await new HardeningEngine(Factory()).ApplyAsync(original, Plan(), null, CancellationToken.None);
        Assert.False(result.Committed);
        Assert.False(result.RolledBack);
        Assert.Equal(new[] { "original:preflight" }, _events);
    }

    [Fact]
    public async Task Fail2BanPackagesAreConfiguredOnlyAfterRecoveryIsArmed()
    {
        var plan = PlanWithFail2Ban();
        var result = await new HardeningEngine(Factory()).ApplyAsync(Original(), plan, null, CancellationToken.None);
        Assert.True(result.Committed);
        Assert.True(_events.IndexOf("original:arm-rollback") < _events.IndexOf("original:configure-fail2ban"));
        Assert.True(_events.IndexOf("original:configure-fail2ban") < _events.IndexOf("original:provision"));
    }

    [Fact]
    public async Task Fail2BanFailureRecoversBeforeSshOrAccountsAreChanged()
    {
        var result = await new HardeningEngine(Factory()).ApplyAsync(Original(failFail2Ban: true), PlanWithFail2Ban(), null, CancellationToken.None);
        Assert.False(result.Committed);
        Assert.True(result.RolledBack);
        Assert.Contains(_events, value => value.Contains("rollback.sh", StringComparison.Ordinal));
        Assert.DoesNotContain("original:provision", _events);
        Assert.DoesNotContain("original:configure-dual-port", _events);
    }

    [Fact]
    public async Task RequestedFail2BanCannotBeSilentlySkippedByAnIncompletePlan()
    {
        var plan = Plan();
        plan = plan with { Options = plan.Options with { ConfigureFail2Ban = true } };
        await Assert.ThrowsAsync<InvalidOperationException>(() => new HardeningEngine(Factory()).ApplyAsync(Original(), plan, null, CancellationToken.None));
        Assert.Empty(_events);
    }

    [Fact]
    public async Task CancellationAfterArmingUsesIndependentRecoveryToken()
    {
        using var stop = new CancellationTokenSource();
        var original = Original(afterArm: stop.Cancel);
        var result = await new HardeningEngine(Factory()).ApplyAsync(original, Plan(), null, stop.Token);
        Assert.True(result.RolledBack);
        Assert.False(result.Committed);
        Assert.DoesNotContain("original:provision", _events);
        Assert.Contains(_events, x => x.Contains("rollback.sh", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ObserverFailuresAfterArmingAndDuringRollbackCannotPreventConfirmedRecovery()
    {
        var observedStages = new List<string>();
        var observer = new SynchronousProgress(value =>
        {
            observedStages.Add(value.Step);
            if (value.Step is "provision" or "rollback") throw new InvalidOperationException("Progress observer failed.");
        });
        var factory = Factory();

        var result = await new HardeningEngine(factory).ApplyAsync(Original(), Plan(), observer, CancellationToken.None);

        Assert.Equal(new[] { "preflight", "arm-rollback", "provision", "rollback" }, observedStages);
        Assert.Contains("original:arm-rollback", _events);
        Assert.DoesNotContain("original:provision", _events);
        Assert.Contains(_events, value => value.Contains("rollback.sh", StringComparison.Ordinal));
        Assert.Empty(factory.Connections);
        Assert.True(result.RolledBack);
        Assert.False(result.Committed);
        Assert.Equal("rolled-back", _state);
    }

    [Fact]
    public async Task UnreachableRecoveryIsNotReportedAsRolledBack()
    {
        var result = await new HardeningEngine(Factory(changedKey: true)).ApplyAsync(Original(failRecovery: true), Plan(), null, CancellationToken.None);
        Assert.False(result.Committed);
        Assert.False(result.RolledBack);
        Assert.Contains("not confirmed", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LostCommitAcknowledgementDoesNotUndoACommittedTransaction()
    {
        var result = await new HardeningEngine(Factory(loseCommitAcknowledgement: true))
            .ApplyAsync(Original(), Plan(), null, CancellationToken.None);
        Assert.True(result.Committed);
        Assert.False(result.RolledBack);
        Assert.DoesNotContain(_events, value => value.EndsWith(" manual", StringComparison.Ordinal));
        Assert.Equal("committed", _state);
    }

    [Fact]
    public async Task ManualRecoveryReadsOutcomeBeforeItsOwnSudoGrantIsRevoked()
    {
        var calls = 0;
        var session = new FakeSession(OriginalOptions, Pin, (script, privileged, ct) =>
        {
            if (++calls > 1) throw new InvalidOperationException("A second sudo elevation is no longer allowed.");
            Assert.True(privileged);
            Assert.Contains(" manual", script);
            return new CommandResult(0, "Recovery completed.\nSSHARDENER_STATE=rolled-back\n", "");
        });
        await new HardeningEngine(Factory()).RollbackAsync(session, Id, CancellationToken.None);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task ManualRecoveryDoesNotTreatAnUnchangedCommittedStateAsSuccess()
    {
        var session = new FakeSession(OriginalOptions, Pin, (_, _, _) => new CommandResult(0, "SSHARDENER_STATE=committed\n", ""));
        await Assert.ThrowsAsync<InvalidOperationException>(() => new HardeningEngine(Factory()).RollbackAsync(session, Id, CancellationToken.None));
    }

    private HardeningPlan Plan()
    {
        var ids = new[] { "preflight", "arm-rollback", "provision", "open-port", "configure-dual-port", "configure-final", "commit" };
        return new HardeningPlan(Id, new ServerAudit { HasRoot = true, InitSystem = "systemd" }, OriginalOptions,
            InputValidatorsTests.ValidOptions with { PrivateKeyPath = _key, GrantSudo = true, NoPasswordSudo = true },
            ids.Select(id => new PlannedStep(id, id, id, "rollback")).ToArray(), []);
    }

    private HardeningPlan PlanWithFail2Ban()
    {
        var plan = Plan();
        return plan with
        {
            Options = plan.Options with { ConfigureFail2Ban = true },
            Steps = plan.Steps.Take(2).Append(new PlannedStep("configure-fail2ban", "configure-fail2ban", "configure-fail2ban", "rollback")).Concat(plan.Steps.Skip(2)).ToArray()
        };
    }

    private FakeSession Original(bool failPreflight = false, bool failRecovery = false, Action? afterArm = null, bool failFail2Ban = false) => new(OriginalOptions, Pin, (script, privileged, ct) =>
    {
        ct.ThrowIfCancellationRequested();
        _events.Add("original:" + script);
        if (script.Contains("rollback.sh", StringComparison.Ordinal))
        {
            if (failRecovery) throw new IOException("Transport lost.");
            if (_state != "committed" || script.Contains(" manual", StringComparison.Ordinal)) _state = "rolled-back";
        }
        if (script.StartsWith("cat ", StringComparison.Ordinal)) return new(0, _state, "");
        if (script == "preflight" && failPreflight) return new(1, "", "Rejected preflight.");
        if (script == "configure-fail2ban" && failFail2Ban) return new(1, "", "Package installation failed.");
        if (script == "arm-rollback") afterArm?.Invoke();
        return new(0, "", "");
    });

    private FakeFactory Factory(bool changedKey = false, bool failSecondPrivilege = false, bool loseCommitAcknowledgement = false) => new(async (options, trust, number) =>
    {
        _events.Add("connect" + number);
        var identity = Pin with { Port = 22022, KeyBase64 = changedKey ? "bWl0bQ==" : Pin.KeyBase64 };
        if (!await trust(identity)) throw new InvalidOperationException("Pinned key rejected.");
        return new FakeSession(options, identity, (script, privileged, ct) =>
        {
            ct.ThrowIfCancellationRequested();
            var suffix = script == "id -u" ? "privilege" : script;
            _events.Add($"new{number}:" + suffix);
            if (script == "id -un") return new(0, "sshadmin\n", "");
            if (script == "id -u") return failSecondPrivilege && number == 2 ? new(1, "", "sudo denied") : new(0, "0\n", "");
            if (script == "commit")
            {
                _state = "committed";
                if (loseCommitAcknowledgement) throw new IOException("The committed acknowledgement was lost.");
            }
            if (script.StartsWith("cat ", StringComparison.Ordinal)) return new(0, _state, "");
            return new(0, "", "");
        });
    });

    public void Dispose() => File.Delete(_key);

    private sealed class SynchronousProgress(Action<OperationProgress> report) : IProgress<OperationProgress>
    {
        public void Report(OperationProgress value) => report(value);
    }

    private sealed class FakeFactory(Func<ConnectionOptions, Func<HostIdentity, Task<bool>>, int, Task<IRemoteSession>> connect) : IRemoteSessionFactory
    {
        public List<ConnectionOptions> Connections { get; } = [];
        public Task<IRemoteSession> ConnectAsync(ConnectionOptions options, Func<HostIdentity, Task<bool>> trustHost, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Connections.Add(options);
            return connect(options, trustHost, Connections.Count);
        }
    }

    private sealed class FakeSession(ConnectionOptions options, HostIdentity identity, Func<string, bool, CancellationToken, CommandResult> execute) : IRemoteSession
    {
        public ConnectionOptions Options { get; } = options;
        public HostIdentity Identity { get; } = identity;
        public Task<CommandResult> ExecuteAsync(string script, bool privileged, CancellationToken cancellationToken) => Task.FromResult(execute(script, privileged, cancellationToken));
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
