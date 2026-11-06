using SSHHardener.Core;
using SSHHardener.Profiles;

namespace SSHHardener.Tests;

public sealed class AuditServiceTests
{
    [Fact]
    public async Task UnverifiableSudoStillAllowsReadOnlyAuditWithoutGrantingApplyPrivilege()
    {
        var session = new AuditSession(_ => throw new InvalidOperationException("sudo requires a password"));

        var audit = await new AuditService().AuditAsync(session, CancellationToken.None);

        Assert.False(audit.HasRoot);
        Assert.Equal("debian", audit.OsId);
        Assert.Equal("192.0.2.15", audit.AdminAddress);
        Assert.Equal(false, session.AuditWasPrivileged);
        Assert.Contains(audit.Warnings, warning => warning.Contains("Root/sudo could not be verified", StringComparison.Ordinal));
        Assert.Contains(audit.Warnings, warning => warning.Contains("applying changes is disabled", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ProvenUidZeroPermitsPrivilegedAudit()
    {
        var session = new AuditSession(_ => new CommandResult(0, " 0\n", ""));

        var audit = await new AuditService().AuditAsync(session, CancellationToken.None);

        Assert.True(audit.HasRoot);
        Assert.Equal(true, session.AuditWasPrivileged);
        Assert.DoesNotContain(audit.Warnings, warning => warning.Contains("No verified administrative privileges", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(1, "0\n")]
    [InlineData(0, "1000\n")]
    [InlineData(0, "")]
    [InlineData(0, "0\n1000\n")]
    public async Task NonzeroExitOrUnprovenRootUidCannotEnableChanges(int exitCode, string output)
    {
        var session = new AuditSession(_ => new CommandResult(exitCode, output, ""));

        var audit = await new AuditService().AuditAsync(session, CancellationToken.None);

        Assert.False(audit.HasRoot);
        Assert.Equal(false, session.AuditWasPrivileged);
        Assert.Contains(audit.Warnings, warning => warning.Contains("No verified administrative privileges", StringComparison.Ordinal));
    }

    [Fact]
    public async Task CancellationDuringPrivilegeProbePropagatesInsteadOfContinuingReadOnly()
    {
        using var cancellation = new CancellationTokenSource();
        var session = new AuditSession(token =>
        {
            cancellation.Cancel();
            throw new OperationCanceledException(token);
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new AuditService().AuditAsync(session, cancellation.Token));

        Assert.Null(session.AuditWasPrivileged);
    }

    private sealed class AuditSession(Func<CancellationToken, CommandResult> privilegeProbe) : IRemoteSession
    {
        public ConnectionOptions Options { get; } = new("test.example", 22, "operator");
        public HostIdentity Identity { get; } = new("test.example", 22, "ssh-ed25519", "SHA256:test", "dGVzdA==");
        public bool? AuditWasPrivileged { get; private set; }

        public Task<CommandResult> ExecuteAsync(string script, bool privileged, CancellationToken cancellationToken)
        {
            if (script == "id -u")
            {
                Assert.True(privileged);
                return Task.FromResult(privilegeProbe(cancellationToken));
            }
            if (script.Contains("SSHARDENER_OSID", StringComparison.Ordinal))
            {
                AuditWasPrivileged = privileged;
                return Task.FromResult(new CommandResult(0, "SSHARDENER_OSID=debian\nSSHARDENER_OSVERSION=12\nSSHARDENER_INIT=systemd\nSSHARDENER_FIREWALL=none\nSSHARDENER_SOCKET=no\nSSHARDENER_SELINUX=Disabled\nSSHARDENER_SERVICE=ssh\nSSHARDENER_CONFIG_BEGIN\nport 22\nSSHARDENER_CONFIG_END\n", ""));
            }
            Assert.False(privileged);
            return Task.FromResult(new CommandResult(0, "192.0.2.15\n", ""));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
