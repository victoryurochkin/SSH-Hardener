using System.Text;
using SSHHardener.Core;
using SSHHardener.Profiles;

namespace SSHHardener.Tests;

public sealed class AccessPolicyEngineTests : IDisposable
{
    private const string Transaction = "20261106120000-abcdef123456";
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "sshhardener-access-engine-" + Guid.NewGuid().ToString("N"));
    private readonly List<string> _events = [];
    private string _state = "pending";
    private string ControlKey => Path.Combine(_directory, "control-existence-only.pem");
    private string TargetKey => Path.Combine(_directory, "target-existence-only.pem");
    private ConnectionOptions Control => new("fixture.example", 2222, "root", Password: "control-password-not-for-target", PrivateKeyPath: ControlKey);
    private HostIdentity Pin => OperationHistoryTests.Identity("fixture.example", 2222);

    public AccessPolicyEngineTests()
    {
        Directory.CreateDirectory(_directory);
        File.WriteAllText(ControlKey, "Mock transport checks existence only; this is not a private key.");
        File.WriteAllText(TargetKey, "Mock transport checks existence only; this is not a private key.");
    }

    [Fact]
    public async Task SftpTargetIsVerifiedIndependentlyAndCommitUsesFreshPinnedControlOnTheFinalPort()
    {
        var original = Original();
        var verifier = new Verifier(_events);
        var factory = Factory();
        var result = await new HardeningEngine(factory, verifier).ApplyAsync(original, Plan(), null, CancellationToken.None);

        Assert.True(result.Committed);
        Assert.Equal(new[] { false, true }, verifier.Calls.Select(call => call.Expectation.FinalPolicy));
        Assert.All(verifier.Calls, call => Assert.Equal(AccountAccess.SftpOnly, call.Expectation.Access));
        var control = Assert.Single(factory.Connections);
        Assert.Equal("root", control.Username);
        Assert.Equal(22022, control.Port);
        Assert.Equal(ControlKey, control.PrivateKeyPath);
        Assert.Null(control.Password);
        Assert.Contains("original:configure-final", _events);
        Assert.Contains("fresh-control:commit", _events);
        Assert.DoesNotContain("original:commit", _events);
        Assert.True(_events.IndexOf("target:final") < _events.IndexOf("fresh-control:commit"));
        Assert.True(original.BorrowedInput.Span.ToArray().All(value => value == 0), "The engine retained credential input after the sensitive command completed.");
    }

    [Fact]
    public async Task PasswordAndTotpTravelOnlyInSensitiveStdinAndReceiveTwoFinalVerificationCallsWithoutClockWaiting()
    {
        var plan = Plan();
        var time = DateTimeOffset.UtcNow;
        var seed = TotpService.GenerateSecret();
        var codes = TotpService.GenerateRecoveryCodes().ToArray();
        plan = plan with { Options = plan.Options with
        {
            SudoMode = SudoPolicyMode.Password, AccountAccess = AccountAccess.Shell,
            NewUserSudoPassword = "PublicMockAccountPassword42!", EnableTotp = true, TotpSecret = seed,
            TotpRecoveryCodes = codes, TotpEnrollmentCode = TotpService.GenerateCode(seed, time), TotpEnrollmentConfirmedAt = time
        } };
        var original = Original();
        var verifier = new Verifier(_events);
        var factory = Factory();

        var result = await new HardeningEngine(factory, verifier).ApplyAsync(original, plan, null, CancellationToken.None);

        Assert.True(result.Committed);
        Assert.Equal(new[] { false, true, true }, verifier.Calls.Select(call => call.Expectation.FinalPolicy));
        // The fake verifier checks the pipeline without consuming the real timed OTP provider.
        Assert.All(verifier.Calls, call =>
        {
            Assert.NotNull(call.Connection.OneTimeCodeProvider);
            Assert.Equal(plan.Options.NewUserSudoPassword, call.Connection.SudoPassword);
            Assert.Null(call.Connection.Password);
        });
        var input = Encoding.UTF8.GetString(original.InputCopy!).Split('\n');
        Assert.Equal(5, input.Length);
        Assert.Equal("SSHARDENER_ACCESS_V1", input[0]);
        Assert.Equal(plan.Options.NewUserSudoPassword, Decode(input[1]));
        Assert.Equal(seed, Decode(input[2]));
        Assert.Equal(string.Join('\n', codes), Decode(input[3]));
        Assert.Empty(input[4]);
        Assert.All(original.BorrowedInput.ToArray(), value => Assert.Equal(0, value));
        foreach (var value in new[] { plan.Options.NewUserSudoPassword!, seed }.Concat(codes))
        {
            Assert.DoesNotContain(value, plan.Preview);
            Assert.All(_events, entry => Assert.DoesNotContain(value, entry));
        }
        Assert.Empty(factory.Connections);
    }

    [Fact]
    public async Task FailedFinalTargetVerificationRecoversThroughControlAndNeverCommits()
    {
        var verifier = new Verifier(_events) { FailFinal = true };
        var factory = Factory();
        var result = await new HardeningEngine(factory, verifier).ApplyAsync(Original(), Plan(), null, CancellationToken.None);

        Assert.False(result.Committed);
        Assert.True(result.RolledBack);
        Assert.Contains("original:rollback", _events);
        Assert.DoesNotContain(_events, entry => entry.EndsWith(":commit", StringComparison.Ordinal));
        Assert.Empty(factory.Connections);
    }

    [Fact]
    public async Task SensitiveProvisioningFailureClearsInputAndRecoversBeforeTargetConnectionsOrFinalConfiguration()
    {
        var original = Original(failSensitive: true);
        var verifier = new Verifier(_events);
        var result = await new HardeningEngine(Factory(), verifier).ApplyAsync(original, Plan(), null, CancellationToken.None);

        Assert.True(result.RolledBack);
        Assert.False(result.Committed);
        Assert.Empty(verifier.Calls);
        Assert.DoesNotContain("original:configure-access", _events);
        Assert.DoesNotContain("original:configure-final", _events);
        Assert.Contains("original:rollback", _events);
        Assert.All(original.BorrowedInput.ToArray(), value => Assert.Equal(0, value));
    }

    [Fact]
    public async Task ChangedControlHostKeyAfterTargetSuccessPreventsCommitAndTriggersRecovery()
    {
        var verifier = new Verifier(_events);
        var result = await new HardeningEngine(Factory(changedKey: true), verifier).ApplyAsync(Original(), Plan(), null, CancellationToken.None);

        Assert.Equal(2, verifier.Calls.Count);
        Assert.False(result.Committed);
        Assert.True(result.RolledBack);
        Assert.DoesNotContain("fresh-control:commit", _events);
        Assert.Contains("original:rollback", _events);
    }

    private HardeningPlan Plan()
    {
        var ids = new[] { "preflight", "arm-rollback", "provision", "provision-access", "configure-access", "open-port", "configure-dual-port", "configure-final", "commit" };
        return new HardeningPlan(Transaction, new ServerAudit { HasRoot = true, InitSystem = "systemd" }, Control,
            InputValidatorsTests.ValidOptions with { GrantSudo = false, NoPasswordSudo = false, SudoMode = SudoPolicyMode.None,
                AccountAccess = AccountAccess.SftpOnly, PrivateKeyPath = TargetKey },
            ids.Select(id => new PlannedStep(id, id, id, "fixture rollback")
                { SensitiveInput = id == "provision-access" ? SensitiveInputKind.AccessCredentials : SensitiveInputKind.None }).ToArray(), []);
    }

    private Session Original(bool failSensitive = false) => new(Control, Pin,
        (script, privileged, ct) => Execute("original", script, privileged, ct), failSensitive);

    private CommandResult Execute(string name, string script, bool privileged, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (script.Contains("rollback.sh", StringComparison.Ordinal)) { _events.Add(name + ":rollback"); _state = "rolled-back"; return new(0, "", ""); }
        _events.Add(name + ":" + script);
        if (script == "date -u +%s") return new(0, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), "");
        if (script == "id -un") return new(0, "root\n", "");
        if (script == "id -u") { Assert.True(privileged); return new(0, "0\n", ""); }
        if (script == "commit") _state = "committed";
        if (script.StartsWith("cat ", StringComparison.Ordinal)) return new(0, _state + "\n", "");
        return new(0, "", "");
    }

    private FactoryStub Factory(bool changedKey = false) => new(async (connection, trust, ct) =>
    {
        var identity = Pin with { Port = connection.Port, KeyBase64 = changedKey ? "changed-fixture-key" : Pin.KeyBase64 };
        Assert.True(connection.Username == "root" && connection.PrivateKeyPath == ControlKey, "The engine attempted to use the restricted target as the control administrator.");
        if (!await trust(identity)) throw new InvalidOperationException("Changed control identity rejected.");
        return new Session(connection, identity, (script, privileged, token) => Execute("fresh-control", script, privileged, token));
    });

    private static string Decode(string value) => Encoding.UTF8.GetString(Convert.FromBase64String(value));

    public void Dispose()
    {
        foreach (var path in Directory.GetFiles(_directory)) File.Delete(path);
        Directory.Delete(_directory);
    }

    private sealed class Session(ConnectionOptions options, HostIdentity identity,
        Func<string, bool, CancellationToken, CommandResult> execute, bool failSensitive = false) : IRemoteSession, IRemoteSensitiveSession
    {
        public ConnectionOptions Options { get; } = options;
        public HostIdentity Identity { get; } = identity;
        public ReadOnlyMemory<byte> BorrowedInput { get; private set; }
        public byte[]? InputCopy { get; private set; }
        public Task<CommandResult> ExecuteAsync(string script, bool privileged, CancellationToken ct) => Task.FromResult(execute(script, privileged, ct));
        public Task<CommandResult> ExecuteSensitiveAsync(string script, ReadOnlyMemory<byte> input, bool privileged, CancellationToken ct)
        {
            Assert.True(privileged);
            Assert.Equal("provision-access", script);
            BorrowedInput = input;
            InputCopy = input.ToArray();
            return Task.FromResult(failSensitive ? new CommandResult(1, "", "Fixture sensitive provisioning failure.") : execute(script, true, ct));
        }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FactoryStub(Func<ConnectionOptions, Func<HostIdentity, Task<bool>>, CancellationToken, Task<IRemoteSession>> connect) : IRemoteSessionFactory
    {
        public List<ConnectionOptions> Connections { get; } = [];
        public Task<IRemoteSession> ConnectAsync(ConnectionOptions connection, Func<HostIdentity, Task<bool>> trust, CancellationToken ct)
        { Connections.Add(connection); return connect(connection, trust, ct); }
    }

    private sealed class Verifier(List<string> events) : ITargetAccessVerifier
    {
        public List<(ConnectionOptions Connection, TargetAccessExpectation Expectation)> Calls { get; } = [];
        public bool FailFinal { get; init; }
        public Task VerifyAsync(ConnectionOptions connection, HostIdentity pin, TargetAccessExpectation expectation, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Calls.Add((connection, expectation));
            events.Add(expectation.FinalPolicy ? "target:final" : "target:dual");
            if (FailFinal && expectation.FinalPolicy) throw new InvalidOperationException("Fixture final verification failed.");
            return Task.CompletedTask;
        }
    }
}
