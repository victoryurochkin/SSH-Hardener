using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SSHHardener.Core;
using SSHHardener.Profiles;

namespace SSHHardener.Tests;

public sealed class BulkCoordinatorTests
{
    [Fact]
    public void CsvAcceptsQuotedMetadataAndRejectsCredentials()
    {
        var hosts = BulkHardeningCoordinator.ParseCsv("host,port,username,privateKeyPath,id,displayName\r\nserver.example,22022,operator,\"C:\\keys\\a,b.ppk\",a,\"First, host\"\r\n");
        var host = Assert.Single(hosts);
        Assert.Equal("First, host", host.DisplayName);
        Assert.Equal("C:\\keys\\a,b.ppk", host.PrivateKeyPath);
        Assert.Equal(22022, host.Port);
        Assert.Throws<ArgumentException>(() => BulkHardeningCoordinator.ParseCsv("host,password\nserver.example,never-import-secret"));
        Assert.Throws<ArgumentException>(() => BulkHardeningCoordinator.ParseCsv("host,totpSecret\nserver.example,never-import-seed"));
    }

    [Theory]
    [InlineData("host,port\nSERVER.EXAMPLE,22\nserver.example.,22022")]
    [InlineData("host\n192.0.2.1\n::ffff:192.0.2.1")]
    [InlineData("host,id\none.example,same\ntwo.example,same")]
    [InlineData("host\n\"unclosed")]
    [InlineData("host\n\"server.example\"suffix")]
    [InlineData("host,port\nserver.example,0")]
    public void CsvRejectsUnsafeOrAmbiguousInput(string csv) =>
        Assert.Throws<ArgumentException>(() => BulkHardeningCoordinator.ParseCsv(csv));

    [Fact]
    public async Task UnknownHostRequiresExplicitTrustBeforeAudit()
    {
        var fixture = new Fixture();
        var calls = 0;
        var preview = await fixture.Coordinator.PreviewAsync(Targets(1), Configuration,
            (_, _, _) => { calls++; return Task.FromResult(false); });
        Assert.Equal(1, calls);
        Assert.False(Assert.Single(preview.Hosts).IsReady);
        Assert.Equal(0, fixture.AuditCalls);
        Assert.Equal(0, fixture.EngineCalls);
        Assert.Empty(fixture.History);
    }

    [Fact]
    public async Task PolicyRefusalIsReadableWithoutExposingCredentials()
    {
        var fixture = new Fixture { PlanError = "A separate administrator key is required; original-password target-sudo-password private-key-passphrase." };
        var preview = await fixture.Preview(1);
        var error = Assert.Single(preview.Hosts).Error!;
        Assert.Contains("separate administrator key is required", error);
        Assert.Contains("[redacted]", error);
        Assert.DoesNotContain("original-password", error);
        Assert.DoesNotContain("target-sudo-password", error);
        Assert.DoesNotContain("private-key-passphrase", error);
        Assert.Equal(0, fixture.EngineCalls);
        Assert.Empty(fixture.History);
    }

    [Fact]
    public async Task PreviewAndSerializedMetadataExcludeCredentialsAndEnrollmentSecrets()
    {
        var fixture = new Fixture();
        var preview = await fixture.Preview(1, target => Config(target) with
        {
            Options = Options() with { EnableTotp = true, TotpSecret = "TEST-SEED-NEVER-SERIALIZE", TotpEnrollmentCode = "123456", TotpRecoveryCodes = ["87654321"] }
        });
        var entry = Assert.Single(preview.Hosts);
        Assert.True(entry.IsReady);
        Assert.Null(entry.Plan!.OriginalConnection.Password);
        Assert.Null(entry.Plan.Options.KeyPassphrase);
        Assert.Null(entry.Plan.Options.VerificationOneTimeCodeProvider);
        Assert.Null(entry.Plan.Options.VerificationSudoPassword);
        Assert.Null(entry.Plan.OriginalConnection.OneTimeCodeProvider);
        Assert.Null(entry.Plan.Options.TotpSecret);
        Assert.Empty(entry.Plan.Options.TotpRecoveryCodes);
        var json = JsonSerializer.Serialize(preview);
        Assert.DoesNotContain("original-password", json);
        Assert.DoesNotContain("private-key-passphrase", json);
        Assert.DoesNotContain("target-sudo-password", json);
        Assert.DoesNotContain("TEST-SEED", json);
        Assert.DoesNotContain("87654321", json);
        Assert.DoesNotContain("RawReport", json);
        Assert.DoesNotContain("Steps", json);
        Assert.DoesNotContain("Password", new BulkHostConfiguration(Config(Targets(1)[0]).Connection, Options()).ToString());
    }

    [Fact]
    public async Task EveryHostPersistsRecoveryMetadataBeforeItsEngine()
    {
        var fixture = new Fixture();
        var preview = await fixture.Preview(3);
        var result = await fixture.Coordinator.ApplyAsync(preview, Configuration, new BulkRunSettings(2, false));
        Assert.All(result.Hosts, outcome => Assert.Equal(BulkHostState.Committed, outcome.State));
        Assert.All(result.Hosts, outcome => Assert.True(outcome.HistoryUpdated));
        Assert.Equal(3, fixture.EngineCalls);
        foreach (var record in fixture.History.Where(record => record.LastConfirmedState == OperationState.Unknown))
        {
            var events = fixture.Events.ToArray();
            Assert.True(Array.IndexOf(events, "history:" + record.TransactionId) < Array.IndexOf(events, "engine:" + record.TransactionId));
        }
        Assert.All(fixture.History, record => Assert.DoesNotContain("password", JsonSerializer.Serialize(record)));
    }

    [Fact]
    public async Task ChangedSettingsOrAlteredPreviewCannotReachAnEngine()
    {
        var fixture = new Fixture();
        var preview = await fixture.Preview(1);
        var changed = await fixture.Coordinator.ApplyAsync(preview, (target, _) => Task.FromResult(Config(target) with
        { Options = Options() with { NewPort = 33333 } }));
        Assert.Equal(BulkHostState.Failed, Assert.Single(changed.Hosts).State);
        Assert.Equal(0, fixture.EngineCalls);
        Assert.Empty(fixture.History);
        preview.Hosts[0].Plan!.Options.IgnoreAddresses[0] = "198.51.100.99";
        var mutated = await fixture.Coordinator.ApplyAsync(preview, Configuration);
        Assert.Equal(BulkHostState.Failed, Assert.Single(mutated.Hosts).State);
        Assert.Equal(0, fixture.EngineCalls);
    }

    [Fact]
    public async Task ReenteredCredentialsMayChangeWithoutChangingApprovedPolicy()
    {
        var fixture = new Fixture();
        var preview = await fixture.Preview(1);
        var result = await fixture.Coordinator.ApplyAsync(preview, (target, _) => Task.FromResult(Config(target) with
        { Connection = Config(target).Connection with { Password = "reentered-password" }, Options = Options() with
            { KeyPassphrase = "reentered-key-passphrase", VerificationSudoPassword = "reentered-target-sudo", VerificationOneTimeCodeProvider = _ => Task.FromResult("654321") } }));
        Assert.Equal(BulkHostState.Committed, Assert.Single(result.Hosts).State);
    }

    [Fact]
    public async Task ChangedHostPinIsRejectedBeforeHistoryOrEngine()
    {
        var fixture = new Fixture();
        var preview = await fixture.Preview(1);
        fixture.ChangeKey = true;
        var result = await fixture.Coordinator.ApplyAsync(preview, Configuration);
        Assert.Equal(BulkHostState.Failed, Assert.Single(result.Hosts).State);
        Assert.Equal(0, fixture.EngineCalls);
        Assert.Empty(fixture.History);
    }

    [Fact]
    public async Task InitialHistoryFailureStopsBeforeMutation()
    {
        var fixture = new Fixture { FailInitialHistory = true };
        var preview = await fixture.Preview(1);
        var result = await fixture.Coordinator.ApplyAsync(preview, Configuration);
        Assert.Equal(BulkHostState.Failed, Assert.Single(result.Hosts).State);
        Assert.Equal(0, fixture.EngineCalls);
    }

    [Fact]
    public async Task HistoryFailureAfterCommitCannotTurnSuccessIntoFailure()
    {
        var fixture = new Fixture { FailConfirmedHistory = true };
        var preview = await fixture.Preview(1);
        var result = await fixture.Coordinator.ApplyAsync(preview, Configuration);
        var outcome = Assert.Single(result.Hosts);
        Assert.Equal(BulkHostState.Committed, outcome.State);
        Assert.False(outcome.HistoryUpdated);
        Assert.True(outcome.Result!.Committed);
    }

    [Fact]
    public async Task DefaultStopsAfterFirstFailureWithoutRollingBackOtherHosts()
    {
        var fixture = new Fixture { RollBackFirst = true };
        var preview = await fixture.Preview(3);
        var result = await fixture.Coordinator.ApplyAsync(preview, Configuration);
        Assert.Equal([BulkHostState.RolledBack, BulkHostState.Skipped, BulkHostState.Skipped], result.Hosts.Select(x => x.State).ToArray());
        Assert.Equal(1, fixture.EngineCalls);
        Assert.Equal(0, fixture.ManualRollbacks);
    }

    [Fact]
    public async Task BoundedConcurrencyKeepsIndependentHostsWithinConfiguredLimit()
    {
        var fixture = new Fixture { EngineDelay = TimeSpan.FromMilliseconds(30) };
        var preview = await fixture.Preview(9);
        var result = await fixture.Coordinator.ApplyAsync(preview, Configuration, new BulkRunSettings(3, false));
        Assert.All(result.Hosts, item => Assert.Equal(BulkHostState.Committed, item.State));
        Assert.InRange(fixture.MaximumActive, 2, 3);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => fixture.Coordinator.ApplyAsync(preview, Configuration, new BulkRunSettings(5)));
    }

    [Fact]
    public async Task CancellationStopsNotStartedHostsAndRetainsConfirmedRecovery()
    {
        using var stop = new CancellationTokenSource();
        var fixture = new Fixture { OnEngine = stop.Cancel, RollBackFirst = true };
        var preview = await fixture.Preview(3);
        var result = await fixture.Coordinator.ApplyAsync(preview, Configuration, cancellationToken: stop.Token);
        Assert.Equal(BulkHostState.RolledBack, result.Hosts[0].State);
        Assert.All(result.Hosts.Skip(1), item => Assert.Equal(BulkHostState.Skipped, item.State));
        Assert.Contains(fixture.History, item => item.LastConfirmedState == OperationState.RolledBack);
    }

    [Fact]
    public async Task UnexpectedEngineFailureIsUnconfirmedAndNeverInventsRecovery()
    {
        var fixture = new Fixture { ThrowInsideEngine = true };
        var preview = await fixture.Preview(1);
        var result = await fixture.Coordinator.ApplyAsync(preview, Configuration);
        Assert.Equal(BulkHostState.Unconfirmed, Assert.Single(result.Hosts).State);
        Assert.Equal(0, fixture.ManualRollbacks);
        Assert.Single(fixture.History);
        Assert.Equal(OperationState.Unknown, fixture.History.Single().LastConfirmedState);
    }

    [Fact]
    public async Task TotpEnrollmentCannotBeBlindlySharedOrChangedAfterPreview()
    {
        var fixture = new Fixture();
        BulkHostConfiguration Enrolled(BulkTarget target, string seed) => Config(target) with
        { Options = Options() with { EnableTotp = true, TotpSecret = seed, TotpRecoveryCodes = ["12345678"] } };
        var preview = await fixture.Preview(2, target => Enrolled(target, "SAME-SEED-FOR-BOTH"));
        Assert.Equal(1, preview.Hosts.Count(item => item.IsReady));
        var single = await fixture.Preview(1, target => Enrolled(target, "ORIGINAL-SEED"));
        var result = await fixture.Coordinator.ApplyAsync(single, (target, _) => Task.FromResult(Enrolled(target, "DIFFERENT-SEED")));
        Assert.Equal(BulkHostState.Failed, Assert.Single(result.Hosts).State);
        Assert.Equal(0, fixture.EngineCalls);
    }

    private static BulkTarget[] Targets(int count) => Enumerable.Range(1, count).Select(index =>
        new BulkTarget(index.ToString(), "Host " + index, "host" + index + ".example", 22, "operator")).ToArray();
    private static HardeningOptions Options() => new()
    {
        PublicKey = "ssh-ed25519 " + Convert.ToBase64String(KeyBlob(1)),
        PrivateKeyPath = "C:\\fixture\\replacement.ppk", KeyPassphrase = "private-key-passphrase",
        VerificationSudoPassword = "target-sudo-password", VerificationOneTimeCodeProvider = _ => Task.FromResult("123456"),
        IgnoreAddresses = ["192.0.2.1"]
    };
    private static BulkHostConfiguration Config(BulkTarget target) => new(
        new ConnectionOptions(target.Host, target.Port, target.Username, Password: "original-password")
            { OneTimeCodeProvider = _ => Task.FromResult("123456") }, Options());
    private static Task<BulkHostConfiguration> Configuration(BulkTarget target, CancellationToken _) => Task.FromResult(Config(target));
    private static byte[] KeyBlob(byte marker)
    {
        var name = Encoding.ASCII.GetBytes("ssh-ed25519");
        var output = new byte[4 + name.Length + 4 + 32];
        BinaryPrimitives.WriteInt32BigEndian(output, name.Length);
        name.CopyTo(output, 4);
        BinaryPrimitives.WriteInt32BigEndian(output.AsSpan(4 + name.Length), 32);
        output[^1] = marker;
        return output;
    }

    private sealed class Fixture : IRemoteSessionFactory, IAuditService, IPlanBuilder, IHardeningEngine
    {
        public BulkHardeningCoordinator Coordinator { get; }
        public ConcurrentQueue<OperationRecord> History { get; } = new();
        public ConcurrentQueue<string> Events { get; } = new();
        public bool ChangeKey, FailInitialHistory, FailConfirmedHistory, RollBackFirst, ThrowInsideEngine;
        public TimeSpan EngineDelay;
        public string? PlanError;
        public Action? OnEngine;
        public int AuditCalls, EngineCalls, ManualRollbacks, MaximumActive;
        private int _active, _ids;
        public Fixture() => Coordinator = new(this, this, this, this, Persist);
        public Task<BulkPreview> Preview(int count, Func<BulkTarget, BulkHostConfiguration>? configuration = null) =>
            Coordinator.PreviewAsync(Targets(count), (target, _) => Task.FromResult(configuration?.Invoke(target) ?? Config(target)), (_, _, _) => Task.FromResult(true));
        private Task Persist(OperationRecord record, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (record.LastConfirmedState == OperationState.Unknown ? FailInitialHistory : FailConfirmedHistory) throw new IOException("Synthetic local history failure.");
            History.Enqueue(record); Events.Enqueue("history:" + record.TransactionId);
            return Task.CompletedTask;
        }
        public async Task<IRemoteSession> ConnectAsync(ConnectionOptions options, Func<HostIdentity, Task<bool>> trustHost, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var blob = KeyBlob(ChangeKey ? (byte)2 : (byte)1);
            var identity = new HostIdentity(options.Host, options.Port, "ssh-ed25519",
                "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('='), Convert.ToBase64String(blob));
            if (!await trustHost(identity)) throw new InvalidOperationException("Host key was rejected before authentication.");
            return new Session(options, identity);
        }
        public Task<ServerAudit> AuditAsync(IRemoteSession session, CancellationToken cancellationToken)
        { Interlocked.Increment(ref AuditCalls); return Task.FromResult(new ServerAudit { HasRoot = true, InitSystem = "systemd", RawReport = "private audit diagnostics" }); }
        public HardeningPlan Build(ServerAudit audit, ConnectionOptions connection, HardeningOptions options)
        {
            if (PlanError is not null) throw new ArgumentException(PlanError);
            return new("20261106120000-" + Interlocked.Increment(ref _ids).ToString("x12"), audit, connection, options,
                [new PlannedStep("preflight", "Read-only preflight", "safe script", "safe rollback")], []);
        }
        public async Task<HardeningResult> ApplyAsync(IRemoteSession original, HardeningPlan plan, IProgress<OperationProgress>? progress, CancellationToken cancellationToken)
        {
            var number = Interlocked.Increment(ref EngineCalls);
            Events.Enqueue("engine:" + plan.TransactionId);
            var active = Interlocked.Increment(ref _active);
            int maximum;
            do { maximum = MaximumActive; } while (maximum < active && Interlocked.CompareExchange(ref MaximumActive, active, maximum) != maximum);
            try
            {
                OnEngine?.Invoke();
                if (ThrowInsideEngine) throw new IOException("Synthetic lost outcome.");
                if (EngineDelay > TimeSpan.Zero) await Task.Delay(EngineDelay);
                var rollback = RollBackFirst && number == 1;
                return new HardeningResult(plan.TransactionId, !rollback, rollback, "Synthetic server confirmation.", DateTimeOffset.UtcNow);
            }
            finally { Interlocked.Decrement(ref _active); }
        }
        public Task RollbackAsync(IRemoteSession session, string transactionId, CancellationToken cancellationToken)
        { Interlocked.Increment(ref ManualRollbacks); return Task.CompletedTask; }
    }

    private sealed class Session(ConnectionOptions options, HostIdentity identity) : IRemoteSession
    {
        public ConnectionOptions Options => options;
        public HostIdentity Identity => identity;
        public Task<CommandResult> ExecuteAsync(string script, bool privileged, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Bulk coordinator must not run its own mutating shell commands.");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
