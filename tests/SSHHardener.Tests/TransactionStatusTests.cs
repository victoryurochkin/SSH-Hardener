using SSHHardener.Core;
using SSHHardener.Profiles;

namespace SSHHardener.Tests;

public sealed class TransactionStatusTests
{
    [Theory]
    [InlineData("pending", OperationState.Pending)]
    [InlineData("rolling-back", OperationState.RollingBack)]
    [InlineData("recovery-deferred", OperationState.RecoveryDeferred)]
    [InlineData("recovery-failed", OperationState.RecoveryFailed)]
    [InlineData("rolled-back", OperationState.RolledBack)]
    [InlineData("committed", OperationState.Committed)]
    [InlineData("not-found", OperationState.NotFound)]
    public async Task RecognizedServerStatesAreReturnedThroughOnePrivilegedReadOnlyProbe(string state, OperationState expected)
    {
        var session = Session(Response(state));
        var result = await new TransactionStatusService().CheckAsync(session, Record(), CancellationToken.None);
        Assert.Equal(expected, result.State);
        Assert.False(result.IsLastCommitted);
        Assert.Equal(1, session.Calls);
        Assert.True(session.LastPrivileged);
        Assert.DoesNotContain("rollback.sh", session.LastScript);
        Assert.DoesNotContain("systemctl reload", session.LastScript);
        Assert.DoesNotContain("apt-get", session.LastScript);
        Assert.DoesNotContain("rm -", session.LastScript);
    }

    [Theory]
    [InlineData("yes", true)]
    [InlineData("no", false)]
    public async Task LatestCommitFlagComesFromFreshServerResponse(string latest, bool expected)
    {
        var session = Session(Response("committed", latest));
        var record = Record() with { LastConfirmedState = OperationState.Pending };
        var status = await new TransactionStatusService().CheckAsync(session, record, CancellationToken.None);
        Assert.Equal(OperationState.Committed, status.State);
        Assert.Equal(expected, status.IsLastCommitted);
    }

    [Theory]
    [InlineData("SSHARDENER_TX_STATE=unknown\nSSHARDENER_LAST_COMMITTED=yes\n")]
    [InlineData("SSHARDENER_TX_STATE=future-state\nSSHARDENER_LAST_COMMITTED=no\n")]
    [InlineData("SSHARDENER_TX_STATE=committed\nSSHARDENER_LAST_COMMITTED=maybe\n")]
    [InlineData("SSHARDENER_TX_STATE=committed\n")]
    [InlineData("SSHARDENER_TX_STATE=committed\nSSHARDENER_LAST_COMMITTED=yes\nUNEXPECTED=output\n")]
    [InlineData("SSHARDENER_TX_STATE=pending\nSSHARDENER_TX_STATE=committed\nSSHARDENER_LAST_COMMITTED=yes\n")]
    public async Task UnknownOrMalformedProtocolCannotBeMistakenForACompletedTransaction(string response)
    {
        var result = await new TransactionStatusService().CheckAsync(Session(response), Record(), CancellationToken.None);
        Assert.Equal(OperationState.Unknown, result.State);
        Assert.False(result.IsLastCommitted);
    }

    [Fact]
    public async Task PermissionFailureDoesNotBecomeNotFoundOrTrustPrintedCommittedState()
    {
        var session = Session(Response("committed", "yes"), exitCode: 1);
        var result = await new TransactionStatusService().CheckAsync(session, Record(), CancellationToken.None);
        Assert.Equal(OperationState.Unknown, result.State);
        Assert.False(result.IsLastCommitted);
    }

    [Fact]
    public async Task PrivilegeExceptionDoesNotBecomeNotFound()
    {
        var session = new FakeSession(Options(), OperationHistoryTests.Identity(port: 22022), (_, _, _) => throw new InvalidOperationException("sudo unavailable"));
        var result = await new TransactionStatusService().CheckAsync(session, Record(), CancellationToken.None);
        Assert.Equal(OperationState.Unknown, result.State);
        Assert.False(result.IsLastCommitted);
    }

    [Theory]
    [InlineData("host")]
    [InlineData("port")]
    [InlineData("identity-host")]
    [InlineData("identity-port")]
    [InlineData("key")]
    [InlineData("algorithm")]
    public async Task EndpointAndHostIdentityMismatchesAreRejectedBeforeAnyRemoteExecution(string mismatch)
    {
        var options = Options();
        var identity = OperationHistoryTests.Identity(port: 22022);
        if (mismatch == "host") options = options with { Host = "other.example" };
        if (mismatch == "port") options = options with { Port = 10022 };
        if (mismatch == "identity-host") identity = identity with { Host = "other.example" };
        if (mismatch == "identity-port") identity = identity with { Port = 10022 };
        if (mismatch == "key") identity = identity with { KeyBase64 = Convert.ToBase64String(new byte[64]) };
        if (mismatch == "algorithm") identity = identity with { Algorithm = "ssh-rsa" };
        var session = new FakeSession(options, identity, (_, _, _) => new CommandResult(0, Response("committed", "yes"), ""));
        var error = await Xunit.Record.ExceptionAsync(() => new TransactionStatusService().CheckAsync(session, Record(), CancellationToken.None));
        Assert.True(error is ArgumentException or InvalidOperationException, "An identity mismatch must fail before querying transaction state.");
        Assert.Equal(0, session.Calls);
    }

    [Theory]
    [InlineData("../other")]
    [InlineData("20261106120000-000000000001\n")]
    [InlineData("20261106120000-000000000001;id")]
    public async Task MalformedTransactionIdentifierCannotReachTheServer(string id)
    {
        var session = Session(Response("committed", "yes"));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => new TransactionStatusService().CheckAsync(session, Record() with { TransactionId = id }, CancellationToken.None));
        Assert.Equal(0, session.Calls);
    }

    [Theory]
    [InlineData(22)]
    [InlineData(22022)]
    public async Task EitherOriginalOrNewPortCanBeUsedWithTheSavedHostPin(int port)
    {
        var session = new FakeSession(Options() with { Host = "FIXTURE.EXAMPLE", Port = port },
            OperationHistoryTests.Identity("FIXTURE.EXAMPLE", port), (_, _, _) => new CommandResult(0, Response("pending"), ""));
        var status = await new TransactionStatusService().CheckAsync(session, Record(), CancellationToken.None);
        Assert.Equal(OperationState.Pending, status.State);
    }

    [Fact]
    public async Task CancellationPropagatesAndDoesNotReturnAnUnknownCachedStatus()
    {
        using var cancellation = new CancellationTokenSource();
        var session = new FakeSession(Options(), OperationHistoryTests.Identity(port: 22022), (_, _, token) =>
        {
            cancellation.Cancel();
            throw new OperationCanceledException(token);
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new TransactionStatusService().CheckAsync(session,
            Record() with { LastConfirmedState = OperationState.Committed }, cancellation.Token));
        Assert.Equal(1, session.Calls);
    }

    private static string Response(string state, string latest = "no") => $"SSHARDENER_TX_STATE={state}\nSSHARDENER_LAST_COMMITTED={latest}\n";
    private static ConnectionOptions Options() => new("fixture.example", 22022, "sshadmin");
    private static FakeSession Session(string response, int exitCode = 0) => new(Options(), OperationHistoryTests.Identity(port: 22022), (_, _, _) => new CommandResult(exitCode, response, ""));
    private static OperationRecord Record() => new("20261106120000-000000000001", DateTimeOffset.UtcNow,
        "fixture.example", 22, "root", null, 22022, "sshadmin", null,
        OperationHistoryTests.Identity().Algorithm, OperationHistoryTests.Identity().KeyBase64, OperationHistoryTests.Identity().Fingerprint);

    private sealed class FakeSession(ConnectionOptions options, HostIdentity identity, Func<string, bool, CancellationToken, CommandResult> execute) : IRemoteSession
    {
        public ConnectionOptions Options { get; } = options;
        public HostIdentity Identity { get; } = identity;
        public int Calls { get; private set; }
        public bool LastPrivileged { get; private set; }
        public string LastScript { get; private set; } = "";
        public Task<CommandResult> ExecuteAsync(string script, bool privileged, CancellationToken cancellationToken)
        {
            Calls++; LastPrivileged = privileged; LastScript = script;
            return Task.FromResult(execute(script, privileged, cancellationToken));
        }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
