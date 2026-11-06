using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SSHHardener.Core;

namespace SSHHardener.Ssh;

/// <summary>Bounded, per-user protected recovery metadata; never a serialized plan or credential store.</summary>
public sealed class OperationHistoryStore
{
    public const int MaxRecords = 100;
    private const int MaxFileBytes = 2 * 1024 * 1024;
    private const int MaxPlaintextBytes = 1536 * 1024;
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("SSHHardener.OperationHistory.v1\0");
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SSHHardener.OperationHistory.DPAPI.CurrentUser.v1");
    private static readonly JsonSerializerOptions JsonOptions = new() { MaxDepth = 8 };
    private readonly string _directory;
    private readonly string _path;
    private readonly string _lockPath;

    public OperationHistoryStore(string? directory = null)
    {
        _directory = Path.GetFullPath(directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SSHHardener"));
        _path = Path.Combine(_directory, "operations.dat");
        _lockPath = Path.Combine(_directory, "operations.lock");
    }

    public async Task<IReadOnlyList<OperationRecord>> LoadAsync(CancellationToken ct = default)
    {
        using var heldLock = await AcquireLockAsync(ct).ConfigureAwait(false);
        return await ReadAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<OperationRecord>> UpsertAsync(OperationRecord record, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        record.Validate();
        using var heldLock = await AcquireLockAsync(ct).ConfigureAwait(false);
        var records = (await ReadAsync(ct).ConfigureAwait(false)).ToList();
        var existingIndex = records.FindIndex(item => item.TransactionId == record.TransactionId);
        if (existingIndex >= 0)
        {
            var existing = records[existingIndex];
            if (existing with { LastConfirmedState = record.LastConfirmedState, LastConfirmedAt = record.LastConfirmedAt } != record)
                throw new InvalidDataException("An existing transaction's identity and connection metadata cannot be replaced.");
            records[existingIndex] = record;
        }
        else records.Add(record);

        records = records.OrderByDescending(item => item.CreatedAt).ThenByDescending(item => item.TransactionId, StringComparer.Ordinal).ToList();
        while (records.Count > MaxRecords)
        {
            var removable = records.FindLastIndex(item => item.TransactionId != record.TransactionId &&
                (item.LastConfirmedState is OperationState.Committed or OperationState.RolledBack ||
                 item.LastConfirmedState == OperationState.NotFound && item.LastConfirmedAt is not null));
            if (removable < 0) throw new IOException("Operation history is full of unresolved transactions. Resolve an existing operation before starting another.");
            records.RemoveAt(removable);
        }
        await WriteAsync(records, ct).ConfigureAwait(false);
        return records.AsReadOnly();
    }

    private async Task<IReadOnlyList<OperationRecord>> ReadAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!File.Exists(_path))
        {
            if (Directory.Exists(_path) || IsReparsePoint(_path)) throw new InvalidDataException("Unsafe operation history path.");
            return Array.Empty<OperationRecord>();
        }
        ValidateProtectedFile(_path);
        using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length <= Magic.Length || stream.Length > MaxFileBytes) throw new InvalidDataException("Operation history has an invalid size.");
        var encrypted = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(encrypted, ct).ConfigureAwait(false);
        if (!encrypted.AsSpan(0, Magic.Length).SequenceEqual(Magic)) throw new InvalidDataException("Unknown operation history format.");
        byte[]? plaintext = null;
        try
        {
            plaintext = ProtectedData.Unprotect(encrypted.AsSpan(Magic.Length).ToArray(), Entropy, DataProtectionScope.CurrentUser);
            if (plaintext.Length is 0 or > MaxPlaintextBytes) throw new InvalidDataException("Operation history payload has an invalid size.");
            HistoryDocument document;
            try { document = JsonSerializer.Deserialize<HistoryDocument>(plaintext, JsonOptions) ?? throw new InvalidDataException("Empty operation history."); }
            catch (JsonException error) { throw new InvalidDataException("Invalid operation history data.", error); }
            if (document.Version != 1 || document.Operations is null || document.Operations.Length > MaxRecords)
                throw new InvalidDataException("Unsupported operation history version or record count.");
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var record in document.Operations)
            {
                if (record is null) throw new InvalidDataException("Null operation history record.");
                try { record.Validate(); }
                catch (ArgumentException error) { throw new InvalidDataException("Operation history contains invalid metadata.", error); }
                if (!seen.Add(record.TransactionId)) throw new InvalidDataException("Duplicate operation history identifiers.");
            }
            return Array.AsReadOnly(document.Operations.OrderByDescending(item => item.CreatedAt)
                .ThenByDescending(item => item.TransactionId, StringComparer.Ordinal).ToArray());
        }
        finally
        {
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private async Task WriteAsync(IReadOnlyList<OperationRecord> records, CancellationToken ct)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(new HistoryDocument(1, records.ToArray()), JsonOptions);
        byte[]? encrypted = null;
        var temporary = Path.Combine(_directory, "operations." + Guid.NewGuid().ToString("N") + ".tmp");
        var created = false;
        try
        {
            if (plaintext.Length > MaxPlaintextBytes) throw new IOException("Operation history exceeds the supported metadata size.");
            ct.ThrowIfCancellationRequested();
            encrypted = ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);
            if (encrypted.Length + Magic.Length > MaxFileBytes) throw new IOException("Protected operation history exceeds the supported size.");
            using (var stream = CreateProtectedFile(temporary))
            {
                created = true;
                await stream.WriteAsync(Magic, ct).ConfigureAwait(false);
                await stream.WriteAsync(encrypted, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            ct.ThrowIfCancellationRequested();
            if (File.Exists(_path)) ValidateProtectedFile(_path);
            else if (Directory.Exists(_path) || IsReparsePoint(_path)) throw new InvalidDataException("Unsafe operation history target.");
            // The encrypted temporary file is on the same filesystem. Replace only after its durable flush.
            File.Move(temporary, _path, overwrite: true);
            created = false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (encrypted is not null) CryptographicOperations.ZeroMemory(encrypted);
            if (created) File.Delete(temporary);
        }
    }

    private async Task<FileStream> AcquireLockAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        EnsureDirectory();
        var elapsed = Stopwatch.StartNew();
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            FileStream? stream = null;
            try
            {
                if (Directory.Exists(_lockPath) || IsReparsePoint(_lockPath)) throw new InvalidDataException("Unsafe operation history lock path.");
                stream = File.Exists(_lockPath)
                    ? new FileStream(_lockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None)
                    : CreateProtectedFile(_lockPath);
                ValidateProtectedFile(_lockPath);
                if (stream.Length != 0) throw new InvalidDataException("Invalid operation history lock file.");
                return stream;
            }
            catch (IOException error) when ((error.HResult & 0xffff) is 2 or 32 or 33 or 80 or 183)
            {
                stream?.Dispose();
                if (elapsed.Elapsed > TimeSpan.FromSeconds(10)) throw new IOException("Operation history is in use by another process.", error);
                await Task.Delay(50, ct).ConfigureAwait(false);
            }
            catch { stream?.Dispose(); throw; }
        }
    }

    private void EnsureDirectory()
    {
        if (IsReparsePoint(_directory) || File.Exists(_directory)) throw new InvalidDataException("Unsafe operation history directory.");
        if (!Directory.Exists(_directory))
        {
            var security = new DirectorySecurity();
            var sid = CurrentUser();
            security.SetOwner(sid);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(_directory).Create(security);
        }
        if (IsReparsePoint(_directory)) throw new InvalidDataException("Operation history directory is a reparse point.");
    }

    private static FileStream CreateProtectedFile(string path)
    {
        var sid = CurrentUser();
        var security = new FileSecurity();
        security.SetOwner(sid);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.Read | FileSystemRights.Write,
            FileShare.None, 4096, FileOptions.None, security);
    }

    private static void ValidateProtectedFile(string path)
    {
        if (IsReparsePoint(path) || Directory.Exists(path)) throw new InvalidDataException("Unsafe operation history file.");
        var security = new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        var sid = CurrentUser();
        if (!security.AreAccessRulesProtected || !sid.Equals(security.GetOwner(typeof(SecurityIdentifier))))
            throw new InvalidDataException("Operation history must be private to the current Windows user.");
        var allowed = false;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            if (!sid.Equals(rule.IdentityReference)) throw new InvalidDataException("Operation history grants access to another account.");
            allowed = true;
        }
        if (!allowed) throw new InvalidDataException("Operation history lacks a current-user access rule.");
    }

    private static SecurityIdentifier CurrentUser() => WindowsIdentity.GetCurrent().User ??
        throw new InvalidOperationException("Cannot identify the current Windows user.");

    private static bool IsReparsePoint(string path)
    {
        try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    private sealed record HistoryDocument(int Version, OperationRecord[] Operations);
}
