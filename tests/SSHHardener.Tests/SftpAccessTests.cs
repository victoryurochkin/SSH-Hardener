using System.Reflection;
using System.Security.Cryptography;
using Renci.SshNet;
using SSHHardener.Core;
using SSHHardener.Ssh;

namespace SSHHardener.Tests;

public sealed class SftpAccessTests
{
    private static readonly ConnectionOptions Connection = new("fixture.example", 22022, "fixture", SudoPassword: "not-a-user-secret");
    private static readonly HostIdentity Pin = MakeIdentity();
    private static TargetAccessExpectation Expectation(SudoPolicyMode mode = SudoPolicyMode.None, bool final = true,
        AccountAccess access = AccountAccess.Shell, bool readOnly = false, params RestrictedSudoCommand[] commands) =>
        new(access, mode, commands, readOnly, final);

    [Theory]
    [InlineData(AccountAccess.Shell)]
    [InlineData(AccountAccess.SftpOnly)]
    public async Task DualPhaseChecksFreshUsernameWithoutRequiringFinalPrivileges(AccountAccess access)
    {
        var ssh = new FakeSshFactory(); var sftp = new FakeSftpFactory();
        await new TargetAccessVerifier(ssh, sftp).VerifyAsync(Connection, Pin, Expectation(final: false, access: access), CancellationToken.None);
        Assert.Equal(1, ssh.ConnectCount); Assert.Equal(0, sftp.ConnectCount);
        Assert.Equal(("id -un", false), Assert.Single(ssh.Session.Commands));
        Assert.True(ssh.Session.Disposed);
    }

    [Theory]
    [InlineData(SudoPolicyMode.Legacy)]
    [InlineData(SudoPolicyMode.Password)]
    [InlineData(SudoPolicyMode.Passwordless)]
    public async Task FullShellModesMustProveRootWithExpectedSudoMechanism(SudoPolicyMode mode)
    {
        var ssh = new FakeSshFactory();
        await new TargetAccessVerifier(ssh, new FakeSftpFactory()).VerifyAsync(Connection, Pin, Expectation(mode), CancellationToken.None);
        Assert.Contains(ssh.Session.Commands, command => mode == SudoPolicyMode.Passwordless
            ? command.Script == "sudo -n /bin/sh -c 'id -u'" && !command.Privileged
            : command.Script == "id -u" && command.Privileged);
    }

    [Fact]
    public async Task PasswordSudoWithoutProvidedPasswordFailsAndRootResultIsStrict()
    {
        var ssh = new FakeSshFactory();
        await Assert.ThrowsAsync<InvalidOperationException>(() => new TargetAccessVerifier(ssh, new FakeSftpFactory())
            .VerifyAsync(Connection with { SudoPassword = null }, Pin, Expectation(SudoPolicyMode.Password), CancellationToken.None));
        Assert.DoesNotContain(ssh.Session.Commands, command => command.Privileged);
        ssh = new FakeSshFactory { Session = new FakeSshSession { RootOutput = "1000\n" } };
        await Assert.ThrowsAsync<InvalidOperationException>(() => new TargetAccessVerifier(ssh, new FakeSftpFactory())
            .VerifyAsync(Connection, Pin, Expectation(SudoPolicyMode.Legacy), CancellationToken.None));
    }

    [Fact]
    public async Task RestrictedChecksExactSudoListAndNeverExecutesAnAllowedServiceOperation()
    {
        var ssh = new FakeSshFactory();
        var commands = new[] { new RestrictedSudoCommand("/usr/bin/systemctl", "restart fixture.service"),
            new RestrictedSudoCommand("/usr/bin/systemctl", "--no-pager --full status fixture.service") };
        await new TargetAccessVerifier(ssh, new FakeSftpFactory()).VerifyAsync(Connection, Pin,
            Expectation(SudoPolicyMode.Restricted, commands: commands), CancellationToken.None);
        Assert.Equal(2, ssh.Session.Commands.Count(command => command.Script.StartsWith("sudo -n -l -- ", StringComparison.Ordinal)));
        Assert.Contains(ssh.Session.Commands, command => command.Script == "sudo -n -l -- '/usr/bin/systemctl' 'restart' 'fixture.service'");
        Assert.DoesNotContain(ssh.Session.Commands, command => command.Privileged || command.Script.StartsWith("sudo -n '/usr/bin/systemctl'"));
        Assert.Contains(ssh.Session.Commands, command => command.Script.Contains("SSHARDENER_SHELL_DENIED", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(SudoPolicyMode.None)]
    [InlineData(SudoPolicyMode.Restricted)]
    public async Task UnprivilegedModesRejectAnUnexpectedWorkingPrivilegedShell(SudoPolicyMode mode)
    {
        var ssh = new FakeSshFactory { Session = new FakeSshSession { ShellAllowed = true } };
        var commands = mode == SudoPolicyMode.Restricted ? new[] { new RestrictedSudoCommand("/usr/bin/systemctl", "restart fixture.service") } : [];
        await Assert.ThrowsAsync<InvalidOperationException>(() => new TargetAccessVerifier(ssh, new FakeSftpFactory()).VerifyAsync(Connection, Pin,
            Expectation(mode, commands: commands), CancellationToken.None));
    }

    [Fact]
    public async Task InvalidRestrictedInputIsRejectedBeforeAnyConnection()
    {
        var ssh = new FakeSshFactory();
        await Assert.ThrowsAsync<InvalidOperationException>(() => new TargetAccessVerifier(ssh, new FakeSftpFactory()).VerifyAsync(Connection, Pin,
            Expectation(SudoPolicyMode.Restricted, commands: [new("/usr/bin/systemctl", "restart fixture.service; id")]), CancellationToken.None));
        Assert.Equal(0, ssh.ConnectCount);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task FinalSftpUsesOnlySftpAndChecksRequestedWritePolicy(bool readOnly)
    {
        var ssh = new FakeSshFactory();
        var sftp = new FakeSftpFactory { Session = new FakeSftpSession { DenyUpload = readOnly } };
        await new TargetAccessVerifier(ssh, sftp).VerifyAsync(Connection, Pin,
            Expectation(access: AccountAccess.SftpOnly, readOnly: readOnly), CancellationToken.None);
        Assert.Equal(0, ssh.ConnectCount); Assert.Equal(1, sftp.ConnectCount);
        Assert.Equal(1, sftp.Session.UploadCount);
        Assert.Equal(readOnly ? 0 : 1, sftp.Session.DownloadCount);
        Assert.Empty(sftp.Session.Files);
        Assert.True(sftp.Session.Disposed);
    }

    [Theory]
    [InlineData("write-was-allowed")]
    [InlineData("transport-error")]
    [InlineData("denied-but-left-file")]
    public async Task ReadOnlyCannotBeConfirmedByAnUnrelatedFailureOrLeftoverFile(string scenario)
    {
        var session = new FakeSftpSession { DenyUpload = scenario != "write-was-allowed",
            UploadTransportError = scenario == "transport-error", LeaveOnDenied = scenario == "denied-but-left-file" };
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => new TargetAccessVerifier(new FakeSshFactory(),
            new FakeSftpFactory { Session = session }).VerifyAsync(Connection, Pin,
            Expectation(access: AccountAccess.SftpOnly, readOnly: true), CancellationToken.None));
        Assert.Equal("Target access verification failed.", error.Message);
        Assert.DoesNotContain("fixture-secret", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReadWriteRejectsDifferentDataAndStillDeletesOnlyItsOwnProbe()
    {
        var session = new FakeSftpSession { CorruptDownload = true };
        await Assert.ThrowsAsync<InvalidOperationException>(() => new TargetAccessVerifier(new FakeSshFactory(), new FakeSftpFactory { Session = session })
            .VerifyAsync(Connection, Pin, Expectation(access: AccountAccess.SftpOnly), CancellationToken.None));
        Assert.Empty(session.Files);
        Assert.Equal(1, session.DeleteCount);
    }

    [Fact]
    public async Task InvalidPinAndMismatchedReturnedIdentityFailClosed()
    {
        var ssh = new FakeSshFactory();
        await Assert.ThrowsAsync<InvalidOperationException>(() => new TargetAccessVerifier(ssh, new FakeSftpFactory())
            .VerifyAsync(Connection, Pin with { Fingerprint = "SHA256:invalid" }, Expectation(), CancellationToken.None));
        Assert.Equal(0, ssh.ConnectCount);
        ssh = new FakeSshFactory { Session = new FakeSshSession { Identity = Pin with { Port = 22 } } };
        await Assert.ThrowsAsync<InvalidOperationException>(() => new TargetAccessVerifier(ssh, new FakeSftpFactory())
            .VerifyAsync(Connection, Pin, Expectation(), CancellationToken.None));
        Assert.Empty(ssh.Session.Commands);
    }

    [Fact]
    public async Task CancellationPropagatesAndSessionIsDisposed()
    {
        var ssh = new FakeSshFactory { Session = new FakeSshSession { CancelExecution = true } };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new TargetAccessVerifier(ssh, new FakeSftpFactory())
            .VerifyAsync(Connection, Pin, Expectation(), CancellationToken.None));
        Assert.True(ssh.Session.Disposed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("relative/file")]
    [InlineData("/uploads/../etc/file")]
    [InlineData("/uploads/./file")]
    [InlineData("/uploads//file")]
    [InlineData("/uploads/file\n")]
    [InlineData("/uploads/file\0")]
    [InlineData("/uploads\\file")]
    [InlineData("/")]
    public async Task InvalidOrRootMutationPathsAreRejectedBeforeNetwork(string path)
    {
        await using var session = UnconnectedSftpSession();
        await Assert.ThrowsAsync<ArgumentException>(() => session.DeleteAsync(path, directory: false, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => session.UploadAsync(new MemoryStream([1]), path, false, CancellationToken.None));
    }

    [Fact]
    public async Task PathByteBoundsRejectOverlongUtf8ComponentsBeforeNetwork()
    {
        await using var session = UnconnectedSftpSession();
        await Assert.ThrowsAsync<ArgumentException>(() => session.CreateDirectoryAsync("/" + new string('a', 256), CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => session.CreateDirectoryAsync("/" + new string('я', 128), CancellationToken.None));
    }

    private static ISftpSession UnconnectedSftpSession()
    {
        var type = typeof(SftpSessionFactory).Assembly.GetType("SSHHardener.Ssh.SftpSession", true)!;
        var client = new SftpClient(new ConnectionInfo("localhost", "fixture", new PasswordAuthenticationMethod("fixture", "not-a-secret")));
        return (ISftpSession)Activator.CreateInstance(type, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            null, [client, new EmptyDisposable(), Pin], null)!;
    }

    private static HostIdentity MakeIdentity()
    {
        var bytes = Convert.FromHexString("0000000b7373682d6564323535313900000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        return new HostIdentity(Connection.Host, Connection.Port, "ssh-ed25519",
            "SHA256:" + Convert.ToBase64String(SHA256.HashData(bytes)).TrimEnd('='), Convert.ToBase64String(bytes));
    }

    private sealed class EmptyDisposable : IDisposable { public void Dispose() { } }

    private sealed class FakeSshFactory : IRemoteSessionFactory
    {
        public FakeSshSession Session { get; init; } = new();
        public int ConnectCount { get; private set; }
        public async Task<IRemoteSession> ConnectAsync(ConnectionOptions options, Func<HostIdentity, Task<bool>> trustHost, CancellationToken cancellationToken)
        {
            ConnectCount++;
            if (!await trustHost(Pin)) throw new InvalidOperationException("untrusted");
            return Session;
        }
    }

    private sealed class FakeSshSession : IRemoteSession
    {
        public ConnectionOptions Options => Connection;
        public HostIdentity Identity { get; init; } = Pin;
        public List<(string Script, bool Privileged)> Commands { get; } = [];
        public bool ShellAllowed { get; init; }
        public bool CancelExecution { get; init; }
        public string RootOutput { get; init; } = "0\n";
        public bool Disposed { get; private set; }
        public Task<CommandResult> ExecuteAsync(string script, bool privileged, CancellationToken cancellationToken)
        {
            Commands.Add((script, privileged));
            if (CancelExecution) throw new OperationCanceledException();
            return Task.FromResult(new CommandResult(0, script == "id -un" ? Connection.Username + "\n" :
                script.Contains("SSHARDENER_SHELL_DENIED", StringComparison.Ordinal) ? "SSHARDENER_SHELL_" + (ShellAllowed ? "ALLOWED" : "DENIED") + "\n" :
                script.StartsWith("sudo -n -l", StringComparison.Ordinal) ? "allowed fixture command\n" : RootOutput, ""));
        }
        public ValueTask DisposeAsync() { Disposed = true; return ValueTask.CompletedTask; }
    }

    private sealed class FakeSftpFactory : ISftpSessionFactory
    {
        public FakeSftpSession Session { get; init; } = new();
        public int ConnectCount { get; private set; }
        public async Task<ISftpSession> ConnectSftpAsync(ConnectionOptions connection, Func<HostIdentity, Task<bool>> trustHost, CancellationToken cancellationToken)
        {
            ConnectCount++;
            if (!await trustHost(Pin)) throw new InvalidOperationException("untrusted");
            return Session;
        }
    }

    private sealed class FakeSftpSession : ISftpSession
    {
        public HostIdentity Identity => Pin;
        public Dictionary<string, byte[]> Files { get; } = new(StringComparer.Ordinal);
        public bool DenyUpload { get; init; }
        public bool LeaveOnDenied { get; init; }
        public bool UploadTransportError { get; init; }
        public bool CorruptDownload { get; init; }
        public bool Disposed { get; private set; }
        public int UploadCount { get; private set; }
        public int DownloadCount { get; private set; }
        public int DeleteCount { get; private set; }
        public Task<IReadOnlyList<RemoteFileEntry>> ListAsync(string path, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<RemoteFileEntry>>(path == "/" ? [new("uploads", "/uploads", true, false, 0, DateTimeOffset.UnixEpoch)] :
                Files.Select(pair => new RemoteFileEntry(pair.Key.Split('/')[^1], pair.Key, false, false, pair.Value.Length, DateTimeOffset.UnixEpoch)).ToArray());
        public async Task UploadAsync(Stream source, string remotePath, bool overwrite, CancellationToken cancellationToken)
        {
            UploadCount++;
            if (UploadTransportError) throw new IOException("fixture-secret not a policy denial");
            if (LeaveOnDenied) Files.Add(remotePath, []);
            if (DenyUpload) throw new UnauthorizedAccessException("fixture denial");
            Assert.False(overwrite);
            using var memory = new MemoryStream(); await source.CopyToAsync(memory, cancellationToken); Files.Add(remotePath, memory.ToArray());
        }
        public async Task DownloadAsync(string remotePath, Stream destination, CancellationToken cancellationToken)
        { DownloadCount++; await destination.WriteAsync(CorruptDownload ? new byte[64] : Files[remotePath], cancellationToken); }
        public Task CreateDirectoryAsync(string path, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task RenameAsync(string source, string destination, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task DeleteAsync(string path, bool directory, CancellationToken cancellationToken) { DeleteCount++; Files.Remove(path); return Task.CompletedTask; }
        public ValueTask DisposeAsync() { Disposed = true; return ValueTask.CompletedTask; }
    }
}
