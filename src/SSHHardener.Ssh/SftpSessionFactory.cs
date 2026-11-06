using System.Security.Cryptography;
using System.Text;
using System.Net;
using System.Text.RegularExpressions;
using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;
using SSHHardener.Core;

namespace SSHHardener.Ssh;

public sealed class SftpSessionFactory(KnownHostsStore knownHosts) : ISftpSessionFactory
{
    public async Task<ISftpSession> ConnectSftpAsync(ConnectionOptions connection,
        Func<HostIdentity, Task<bool>> trustHost, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(trustHost);
        if (string.IsNullOrWhiteSpace(connection.Host) || connection.Host.Length > 253 ||
            (!IPAddress.TryParse(connection.Host, out _) && Uri.CheckHostName(connection.Host) == UriHostNameType.Unknown) ||
            connection.Host.Any(char.IsControl) || connection.Port is < 1 or > 65535 ||
            connection.Username is null || !Regex.IsMatch(connection.Username, @"\A[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("Invalid SFTP endpoint or user.");
        SshAuthenticationContext authentication;
        try { authentication = SshAuthentication.Create(connection, cancellationToken); }
        catch (OperationCanceledException) { throw; }
        catch { throw new InvalidOperationException("SFTP authentication could not be prepared."); }
        var client = new SftpClient(authentication.ConnectionInfo)
        {
            KeepAliveInterval = TimeSpan.FromSeconds(20), OperationTimeout = TimeSpan.FromSeconds(30)
        };
        HostIdentity? identity = null;
        Exception? verificationError = null;
        client.HostKeyReceived += (_, args) =>
        {
            args.CanTrust = false;
            try
            {
                var candidate = new HostIdentity(connection.Host, connection.Port, args.HostKeyName,
                    "SHA256:" + Convert.ToBase64String(SHA256.HashData(args.HostKey)).TrimEnd('='), Convert.ToBase64String(args.HostKey));
                knownHosts.VerifyAsync(candidate, trustHost, cancellationToken).GetAwaiter().GetResult();
                identity = candidate;
                args.CanTrust = true;
            }
            catch (Exception error) { verificationError = error; }
        };
        try
        {
            await Task.Run(() => client.ConnectAsync(cancellationToken), cancellationToken).ConfigureAwait(false);
            if (identity is null) throw new InvalidOperationException("SFTP server identity was not established.");
            return new SftpSession(client, authentication, identity);
        }
        catch
        {
            client.Dispose();
            var challengeError = authentication.ChallengeError;
            authentication.Dispose();
            if (cancellationToken.IsCancellationRequested) throw new OperationCanceledException(cancellationToken);
            if (challengeError is OperationCanceledException cancellation) throw cancellation;
            if (verificationError is OperationCanceledException verificationCancellation) throw verificationCancellation;
            if (verificationError is HostKeyChangedException) throw new HostKeyChangedException("The server host key differs from the trusted identity.");
            throw new InvalidOperationException(verificationError is not null
                ? "SFTP host identity verification failed." : "SFTP authentication or connection failed.");
        }
    }
}

/// <summary>
/// SFTP operations reject symlink components using READDIR attributes (SSH.NET's GetAttributes canonicalizes first).
/// SFTP v3 has no atomic openat/no-follow traversal; concurrent changes by another server process remain outside this guard.
/// </summary>
internal sealed class SftpSession(SftpClient client, IDisposable authentication, HostIdentity identity) : ISftpSession
{
    private const int MaximumEntries = 10_000;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _disposed;
    public HostIdentity Identity { get; } = identity;

    public Task<IReadOnlyList<RemoteFileEntry>> ListAsync(string path, CancellationToken cancellationToken) =>
        RunAsync(async () =>
        {
            ValidatePath(path, allowRoot: true);
            await RequirePathAsync(path, mustExist: true, directory: true, cancellationToken).ConfigureAwait(false);
            return (IReadOnlyList<RemoteFileEntry>)(await EntriesAsync(path, cancellationToken).ConfigureAwait(false))
                .Select(file => Project(path, file)).OrderByDescending(entry => entry.IsDirectory).ThenBy(entry => entry.Name, StringComparer.Ordinal).ToArray();
        }, cancellationToken);

    public Task UploadAsync(Stream source, string remotePath, bool overwrite, CancellationToken cancellationToken) =>
        RunAsync(async () =>
        {
            ArgumentNullException.ThrowIfNull(source);
            if (!source.CanRead) throw new ArgumentException("The upload source must be readable.", nameof(source));
            ValidatePath(remotePath, allowRoot: false);
            var existing = await RequirePathAsync(remotePath, mustExist: false, directory: false, cancellationToken).ConfigureAwait(false);
            if (existing is not null && !overwrite) throw new IOException("The remote destination already exists.");
            // CreateNew maps to SSH_FXF_CREAT|SSH_FXF_EXCL: an existing file cannot be overwritten by a race.
            var created = false;
            try
            {
                await using (var destination = await client.OpenAsync(remotePath,
                    overwrite && existing is not null ? FileMode.Truncate : FileMode.CreateNew, FileAccess.Write, cancellationToken).ConfigureAwait(false))
                {
                    created = existing is null;
                    await source.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
                    await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            catch
            {
                if (created)
                {
                    using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    try
                    {
                        await RequirePathAsync(remotePath, mustExist: true, directory: false, cleanup.Token).ConfigureAwait(false);
                        await client.DeleteFileAsync(remotePath, cleanup.Token).ConfigureAwait(false);
                    }
                    catch { throw new IOException("The upload failed and removal of its partial file could not be confirmed."); }
                }
                throw;
            }
        }, cancellationToken);

    public Task DownloadAsync(string remotePath, Stream destination, CancellationToken cancellationToken) =>
        RunAsync(async () =>
        {
            ArgumentNullException.ThrowIfNull(destination);
            if (!destination.CanWrite) throw new ArgumentException("The download destination must be writable.", nameof(destination));
            ValidatePath(remotePath, allowRoot: false);
            await RequirePathAsync(remotePath, mustExist: true, directory: false, cancellationToken).ConfigureAwait(false);
            await using var source = await client.OpenAsync(remotePath, FileMode.Open, FileAccess.Read, cancellationToken).ConfigureAwait(false);
            await source.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
        }, cancellationToken);

    public Task CreateDirectoryAsync(string path, CancellationToken cancellationToken) =>
        RunAsync(async () =>
        {
            ValidatePath(path, allowRoot: false);
            if (await RequirePathAsync(path, mustExist: false, directory: null, cancellationToken).ConfigureAwait(false) is not null)
                throw new IOException("The remote destination already exists.");
            await client.CreateDirectoryAsync(path, cancellationToken).ConfigureAwait(false);
        }, cancellationToken);

    public Task RenameAsync(string source, string destination, CancellationToken cancellationToken) =>
        RunAsync(async () =>
        {
            ValidatePath(source, allowRoot: false); ValidatePath(destination, allowRoot: false);
            await RequirePathAsync(source, mustExist: true, directory: null, cancellationToken).ConfigureAwait(false);
            if (await RequirePathAsync(destination, mustExist: false, directory: null, cancellationToken).ConfigureAwait(false) is not null)
                throw new IOException("The remote destination already exists.");
            // Standard SFTP rename rejects an existing target; do not use posix-rename's overwrite semantics.
            await client.RenameFileAsync(source, destination, cancellationToken).ConfigureAwait(false);
        }, cancellationToken);

    public Task DeleteAsync(string path, bool directory, CancellationToken cancellationToken) =>
        RunAsync(async () =>
        {
            ValidatePath(path, allowRoot: false);
            await RequirePathAsync(path, mustExist: true, directory, cancellationToken).ConfigureAwait(false);
            if (directory) await client.DeleteDirectoryAsync(path, cancellationToken).ConfigureAwait(false);
            else await client.DeleteFileAsync(path, cancellationToken).ConfigureAwait(false);
        }, cancellationToken);

    private async Task<ISftpFile?> RequirePathAsync(string path, bool mustExist, bool? directory, CancellationToken ct)
    {
        if (path == "/") return null;
        var parts = path[1..].Split('/');
        var parent = "/";
        for (var index = 0; index < parts.Length; index++)
        {
            var entry = (await EntriesAsync(parent, ct).ConfigureAwait(false)).SingleOrDefault(file => file.Name == parts[index]);
            var final = index == parts.Length - 1;
            if (entry is null)
            {
                if (final && !mustExist) return null;
                throw new FileNotFoundException("The remote path was not found.");
            }
            if (entry.IsSymbolicLink) throw new IOException("Symbolic link traversal is not allowed.");
            if (!final && !entry.IsDirectory || final && directory == true && !entry.IsDirectory ||
                final && directory == false && !entry.Attributes.IsRegularFile)
                throw new IOException("The remote path has an unexpected file type.");
            if (final) return entry;
            parent = Join(parent, entry.Name);
        }
        throw new IOException("The remote path is invalid.");
    }

    private async Task<List<ISftpFile>> EntriesAsync(string path, CancellationToken ct)
    {
        var entries = new List<ISftpFile>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        await foreach (var entry in client.ListDirectoryAsync(path, ct).ConfigureAwait(false))
        {
            if (entry.Name is "." or "..") continue;
            if (entries.Count >= MaximumEntries) throw new IOException("The remote directory exceeds the listing limit.");
            ValidateName(entry.Name);
            if (!names.Add(entry.Name)) throw new IOException("The remote directory contains duplicate names.");
            entries.Add(entry);
        }
        return entries;
    }

    private static RemoteFileEntry Project(string parent, ISftpFile file) => new(file.Name, Join(parent, file.Name),
        file.IsDirectory, file.IsSymbolicLink, file.Attributes.Size,
        new DateTimeOffset(DateTime.SpecifyKind(file.Attributes.LastWriteTimeUtc, DateTimeKind.Utc)));

    private static string Join(string parent, string name) => parent == "/" ? "/" + name : parent + "/" + name;

    internal static void ValidatePath(string path, bool allowRoot)
    {
        if (string.IsNullOrEmpty(path) || path[0] != '/' || path.Length > 4096 || Encoding.UTF8.GetByteCount(path) > 4096 ||
            path.Any(char.IsControl) || path.Contains('\\') || (!allowRoot && path == "/"))
            throw new ArgumentException("Use a bounded absolute POSIX path.", nameof(path));
        if (path == "/") return;
        foreach (var part in path[1..].Split('/')) ValidateName(part);
    }

    private static void ValidateName(string name)
    {
        if (string.IsNullOrEmpty(name) || name is "." or ".." || name.Length > 255 || Encoding.UTF8.GetByteCount(name) > 255 ||
            name.Any(char.IsControl) || name.IndexOfAny(['/', '\\']) >= 0)
            throw new ArgumentException("Invalid POSIX path component.");
    }

    private async Task RunAsync(Func<Task> operation, CancellationToken ct) =>
        await RunAsync(async () => { await operation().ConfigureAwait(false); return true; }, ct).ConfigureAwait(false);

    private async Task<T> RunAsync<T>(Func<Task<T>> operation, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ct.ThrowIfCancellationRequested();
            return await operation().ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (SftpPermissionDeniedException) { throw new UnauthorizedAccessException("The SFTP operation was denied."); }
        catch (SftpPathNotFoundException) { throw new FileNotFoundException("The remote path was not found."); }
        catch (SshException) { throw new IOException("The SFTP operation failed."); }
        finally { _gate.Release(); }
    }

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposed) return;
            _disposed = true;
            try { client.Dispose(); }
            finally { authentication.Dispose(); }
        }
        finally { _gate.Release(); }
    }
}
