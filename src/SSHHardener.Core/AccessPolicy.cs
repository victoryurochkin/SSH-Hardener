namespace SSHHardener.Core;

public enum AccountAccess { Shell, SftpOnly }
public enum SudoPolicyMode { Legacy, None, Password, Passwordless, Restricted }
public enum SensitiveInputKind { None, AccessCredentials }

public sealed record RestrictedSudoCommand(string Executable, string Arguments);
public sealed record TargetAccessExpectation(AccountAccess Access, SudoPolicyMode SudoMode,
    IReadOnlyList<RestrictedSudoCommand> RestrictedCommands, bool SftpReadOnly, bool FinalPolicy);

public interface IRemoteSensitiveSession
{
    Task<CommandResult> ExecuteSensitiveAsync(string script, ReadOnlyMemory<byte> input,
        bool privileged, CancellationToken cancellationToken);
}

public interface ITargetAccessVerifier
{
    Task VerifyAsync(ConnectionOptions connection, HostIdentity pinnedIdentity,
        TargetAccessExpectation expectation, CancellationToken cancellationToken);
}

public sealed record RemoteFileEntry(string Name, string FullPath, bool IsDirectory, bool IsSymbolicLink,
    long Length, DateTimeOffset LastWriteTime);

public interface ISftpSession : IAsyncDisposable
{
    HostIdentity Identity { get; }
    Task<IReadOnlyList<RemoteFileEntry>> ListAsync(string path, CancellationToken cancellationToken);
    Task UploadAsync(Stream source, string remotePath, bool overwrite, CancellationToken cancellationToken);
    Task DownloadAsync(string remotePath, Stream destination, CancellationToken cancellationToken);
    Task CreateDirectoryAsync(string path, CancellationToken cancellationToken);
    Task RenameAsync(string source, string destination, CancellationToken cancellationToken);
    Task DeleteAsync(string path, bool directory, CancellationToken cancellationToken);
}

public interface ISftpSessionFactory
{
    Task<ISftpSession> ConnectSftpAsync(ConnectionOptions connection,
        Func<HostIdentity, Task<bool>> trustHost, CancellationToken cancellationToken);
}

public static class AccessPolicy
{
    public static SudoPolicyMode EffectiveSudo(HardeningOptions options) => options.SudoMode != SudoPolicyMode.Legacy
        ? options.SudoMode : options.GrantSudo ? SudoPolicyMode.Passwordless : SudoPolicyMode.Legacy;

    public static bool UsesAdvancedAccess(HardeningOptions options) => options.AccountAccess != AccountAccess.Shell ||
        options.SudoMode != SudoPolicyMode.Legacy || options.EnableTotp;

    public static bool RequiresIndependentAdministrator(HardeningOptions options) =>
        options.AccountAccess == AccountAccess.SftpOnly || EffectiveSudo(options) is SudoPolicyMode.None or SudoPolicyMode.Restricted;

    public static string SudoName(SudoPolicyMode mode) => mode switch
    {
        SudoPolicyMode.None => "none", SudoPolicyMode.Password => "password",
        SudoPolicyMode.Passwordless => "passwordless", SudoPolicyMode.Restricted => "restricted", _ => "legacy"
    };
}
