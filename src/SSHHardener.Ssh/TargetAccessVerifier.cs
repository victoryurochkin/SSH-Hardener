using System.Security.Cryptography;
using SSHHardener.Core;

namespace SSHHardener.Ssh;

/// <summary>Checks fresh target authentication and the requested access without executing allowed administrative operations.</summary>
public sealed class TargetAccessVerifier(IRemoteSessionFactory ssh, ISftpSessionFactory sftp) : ITargetAccessVerifier
{
    public async Task VerifyAsync(ConnectionOptions connection, HostIdentity pinnedIdentity,
        TargetAccessExpectation expectation, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(pinnedIdentity);
        ArgumentNullException.ThrowIfNull(expectation);
        try { await VerifyCoreAsync(connection, pinnedIdentity, expectation, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch { throw Failure(); }
    }

    private async Task VerifyCoreAsync(ConnectionOptions connection, HostIdentity pinnedIdentity,
        TargetAccessExpectation expectation, CancellationToken cancellationToken)
    {
        ValidateExpectation(connection, pinnedIdentity, expectation);
        cancellationToken.ThrowIfCancellationRequested();
        Task<bool> Trust(HostIdentity candidate) => Task.FromResult(SameIdentity(candidate, pinnedIdentity, connection));
        if (expectation.FinalPolicy && expectation.Access == AccountAccess.SftpOnly)
        {
            await VerifySftpAsync(connection, pinnedIdentity, expectation.SftpReadOnly, Trust, cancellationToken).ConfigureAwait(false);
            return;
        }
        await using var session = await ssh.ConnectAsync(connection, Trust, cancellationToken).ConfigureAwait(false);
        if (!SameIdentity(session.Identity, pinnedIdentity, connection)) throw Failure();
        await RequireOutputAsync(session, "id -un", privileged: false, connection.Username, cancellationToken).ConfigureAwait(false);
        if (!expectation.FinalPolicy) return;
        switch (expectation.SudoMode)
        {
            case SudoPolicyMode.Password:
                if (string.IsNullOrEmpty(connection.SudoPassword)) throw Failure();
                await RequireOutputAsync(session, "id -u", privileged: true, "0", cancellationToken).ConfigureAwait(false);
                break;
            case SudoPolicyMode.Passwordless:
                await RequireOutputAsync(session, connection.Username == "root" ? "id -u" : "sudo -n /bin/sh -c 'id -u'",
                    privileged: false, "0", cancellationToken).ConfigureAwait(false);
                break;
            case SudoPolicyMode.Legacy:
                await RequireOutputAsync(session, "id -u", privileged: true, "0", cancellationToken).ConfigureAwait(false);
                break;
            case SudoPolicyMode.Restricted:
                foreach (var command in expectation.RestrictedCommands)
                {
                    AccessPolicyValidation.ValidateRestrictedCommand(command);
                    var tokens = new[] { command.Executable }.Concat(command.Arguments.Split(' '));
                    // sudo -l checks permission for this exact argv; it never runs systemctl.
                    var result = await session.ExecuteAsync("sudo -n -l -- " + string.Join(' ', tokens.Select(Quote)),
                        privileged: false, cancellationToken).ConfigureAwait(false);
                    if (result.ExitCode != 0 || result.Output.Length > 65_536) throw Failure();
                }
                await RequireNoPrivilegedShellAsync(session, cancellationToken).ConfigureAwait(false);
                break;
            case SudoPolicyMode.None:
                await RequireNoPrivilegedShellAsync(session, cancellationToken).ConfigureAwait(false);
                break;
            default: throw Failure();
        }
    }

    private async Task VerifySftpAsync(ConnectionOptions connection, HostIdentity pinned, bool readOnly,
        Func<HostIdentity, Task<bool>> trust, CancellationToken ct)
    {
        await using var session = await sftp.ConnectSftpAsync(connection, trust, ct).ConfigureAwait(false);
        if (!SameIdentity(session.Identity, pinned, connection)) throw Failure();
        var root = await session.ListAsync("/", ct).ConfigureAwait(false);
        if (!root.Any(entry => entry.Name == "uploads" && entry.FullPath == "/uploads" && entry.IsDirectory && !entry.IsSymbolicLink))
            throw Failure();
        await session.ListAsync("/uploads", ct).ConfigureAwait(false);
        var path = "/uploads/.sshhardener-access-" + Guid.NewGuid().ToString("N");
        var payload = RandomNumberGenerator.GetBytes(64);
        var created = false;
        try
        {
            using var upload = new MemoryStream(payload, writable: false);
            if (readOnly)
            {
                var denied = false;
                try { await session.UploadAsync(upload, path, overwrite: false, ct).ConfigureAwait(false); created = true; }
                catch (OperationCanceledException) { throw; }
                catch (UnauthorizedAccessException) { denied = true; }
                // A transport error alone is not evidence of read-only policy: require a fresh successful listing.
                var after = await session.ListAsync("/uploads", ct).ConfigureAwait(false);
                if (!denied || after.Any(entry => entry.FullPath == path)) throw Failure();
                return;
            }
            await session.UploadAsync(upload, path, overwrite: false, ct).ConfigureAwait(false);
            created = true;
            using var downloaded = new BoundedProbeStream(payload.Length);
            await session.DownloadAsync(path, downloaded, ct).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(downloaded.ToArray(), payload)) throw Failure();
            await session.DeleteAsync(path, directory: false, ct).ConfigureAwait(false);
            created = false;
            if ((await session.ListAsync("/uploads", ct).ConfigureAwait(false)).Any(entry => entry.FullPath == path)) throw Failure();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            if (created)
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                // The random path was created by this verification only; never remove an existing user file.
                try { await session.DeleteAsync(path, directory: false, cleanup.Token).ConfigureAwait(false); }
                catch { /* The caller still fails verification; no successful outcome is reported. */ }
            }
        }
    }

    private static async Task RequireNoPrivilegedShellAsync(IRemoteSession session, CancellationToken ct)
    {
        await RequireOutputAsync(session, "if sudo -n /bin/sh -c 'exit 0' >/dev/null 2>&1; then printf '%s\\n' SSHARDENER_SHELL_ALLOWED; else printf '%s\\n' SSHARDENER_SHELL_DENIED; fi",
            privileged: false, "SSHARDENER_SHELL_DENIED", ct).ConfigureAwait(false);
    }

    private static async Task RequireOutputAsync(IRemoteSession session, string command, bool privileged, string output, CancellationToken ct)
    {
        var result = await session.ExecuteAsync(command, privileged, ct).ConfigureAwait(false);
        if (result.ExitCode != 0 || result.Output.Length > 256 || result.Output.Trim() != output) throw Failure();
    }

    private static void ValidateExpectation(ConnectionOptions connection, HostIdentity pinned, TargetAccessExpectation expectation)
    {
        if (!Enum.IsDefined(expectation.Access) || !Enum.IsDefined(expectation.SudoMode) || expectation.RestrictedCommands is null ||
            expectation.RestrictedCommands.Count > 32 || !string.Equals(connection.Host, pinned.Host, StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(pinned.Algorithm) || string.IsNullOrWhiteSpace(pinned.KeyBase64)) throw Failure();
        try
        {
            var blob = Convert.FromBase64String(pinned.KeyBase64);
            if (blob.Length is < 16 or > 4096 || pinned.Fingerprint != "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=')) throw Failure();
        }
        catch (FormatException) { throw Failure(); }
        if (expectation.FinalPolicy)
        {
            if (expectation.SudoMode == SudoPolicyMode.Restricted)
            {
                if (expectation.RestrictedCommands.Count == 0) throw Failure();
                foreach (var command in expectation.RestrictedCommands) AccessPolicyValidation.ValidateRestrictedCommand(command);
            }
            else if (expectation.RestrictedCommands.Count != 0) throw Failure();
            if (expectation.SudoMode is SudoPolicyMode.None or SudoPolicyMode.Restricted && connection.Username == "root") throw Failure();
            if (expectation.Access == AccountAccess.SftpOnly && expectation.SudoMode != SudoPolicyMode.None) throw Failure();
        }
    }

    private static bool SameIdentity(HostIdentity actual, HostIdentity pinned, ConnectionOptions connection) =>
        string.Equals(actual.Host, connection.Host, StringComparison.OrdinalIgnoreCase) && actual.Port == connection.Port &&
        actual.Algorithm == pinned.Algorithm && actual.KeyBase64 == pinned.KeyBase64 && actual.Fingerprint == pinned.Fingerprint;

    private static string Quote(string text) => "'" + text.Replace("'", "'\"'\"'", StringComparison.Ordinal) + "'";
    private static InvalidOperationException Failure() => new("Target access verification failed.");

    private sealed class BoundedProbeStream(int limit) : MemoryStream
    {
        public override void Write(byte[] buffer, int offset, int count) { Require(count); base.Write(buffer, offset, count); }
        public override void Write(ReadOnlySpan<byte> buffer) { Require(buffer.Length); base.Write(buffer); }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        { Require(buffer.Length); return base.WriteAsync(buffer, ct); }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        { Require(count); return base.WriteAsync(buffer, offset, count, ct); }
        private void Require(int count) { if (Length + count > limit) throw Failure(); }
    }
}
