using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SSHHardener.Core;
using SSHHardener.Ssh;

namespace SSHHardener.Tests;

public sealed class OperationHistoryTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "sshhardener-history-tests-" + Guid.NewGuid().ToString("N"));
    private Exception? _lockHolderFailure;
    private string DataPath => Path.Combine(_directory, "operations.dat");
    private string LockPath => Path.Combine(_directory, "operations.lock");

    [Fact]
    public void MetadataProjectionCannotSerializePlanSecretsOrServerScripts()
    {
        var plan = new HardeningPlan("20261106120000-000000000001", new ServerAudit { RawReport = "raw-audit-marker" },
            new ConnectionOptions("fixture.example", 22, "root", "password-marker", "C:\\fixture\\source.pem", "source-passphrase-marker", "sudo-marker"),
            InputValidatorsTests.ValidOptions with { PrivateKeyPath = "C:\\fixture\\target.ppk", KeyPassphrase = "target-passphrase-marker" },
            [new PlannedStep("mutate", "script", "server-script-marker", "server-rollback-marker")], []);
        var record = OperationRecord.FromPlan(plan, Identity());
        var json = JsonSerializer.Serialize(record);
        foreach (var secret in new[] { "password-marker", "source-passphrase-marker", "sudo-marker", "target-passphrase-marker", "raw-audit-marker", "server-script-marker", "server-rollback-marker" })
            Assert.DoesNotContain(secret, json);
        using var parsed = JsonDocument.Parse(json);
        Assert.False(parsed.RootElement.TryGetProperty("OriginalConnection", out _));
        Assert.False(parsed.RootElement.TryGetProperty("Options", out _));
        Assert.False(parsed.RootElement.TryGetProperty("Steps", out _));
        Assert.Equal(plan.TransactionId, record.TransactionId);
    }

    [Fact]
    public async Task EncryptedHistoryRoundTripsAcrossStoreInstancesWithPrivateAcl()
    {
        var record = Record(1);
        await new OperationHistoryStore(_directory).UpsertAsync(record, CancellationToken.None);
        var bytes = await File.ReadAllBytesAsync(DataPath);
        Assert.DoesNotContain(record.Host, Encoding.UTF8.GetString(bytes));
        Assert.DoesNotContain(record.TransactionId, Encoding.UTF8.GetString(bytes));
        var restored = await new OperationHistoryStore(_directory).LoadAsync(CancellationToken.None);
        Assert.Equal(record, Assert.Single(restored));
        var acl = new FileInfo(DataPath).GetAccessControl();
        Assert.True(acl.AreAccessRulesProtected);
        var user = WindowsIdentity.GetCurrent().User;
        Assert.NotNull(user);
        var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        Assert.NotEmpty(rules);
        Assert.All(rules, rule => { Assert.Equal(user, rule.IdentityReference); Assert.False(rule.IsInherited); });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CorruptionOrCiphertextTamperingRefusesLoadInsteadOfReturningEmptyHistory(bool tamperCiphertext)
    {
        var store = new OperationHistoryStore(_directory);
        await store.UpsertAsync(Record(1), CancellationToken.None);
        var bytes = await File.ReadAllBytesAsync(DataPath);
        if (tamperCiphertext) bytes[^12] ^= 0x40;
        else bytes = Encoding.UTF8.GetBytes("{ invalid history json");
        await File.WriteAllBytesAsync(DataPath, bytes);
        var failure = await Xunit.Record.ExceptionAsync(() => store.LoadAsync(CancellationToken.None));
        Assert.True(failure is InvalidDataException or CryptographicException, "Corrupt history must be reported as invalid or cryptographically unverifiable.");
        await Assert.ThrowsAnyAsync<Exception>(() => store.UpsertAsync(Record(2), CancellationToken.None));
        Assert.Equal(bytes, await File.ReadAllBytesAsync(DataPath));
    }

    [Fact]
    public async Task UpsertUpdatesOneRecordAndRetainsNewestHundredInDateOrder()
    {
        var store = new OperationHistoryStore(_directory);
        for (var index = 0; index < 103; index++) await store.UpsertAsync(Record(index) with
        {
            LastConfirmedState = OperationState.Committed,
            LastConfirmedAt = Record(index).CreatedAt.AddMinutes(1)
        }, CancellationToken.None);
        var records = await store.LoadAsync(CancellationToken.None);
        Assert.Equal(100, records.Count);
        Assert.Equal(Record(102).TransactionId, records[0].TransactionId);
        Assert.DoesNotContain(records, item => item.TransactionId == Record(0).TransactionId);
        var updated = records[4] with { LastConfirmedState = OperationState.Committed, LastConfirmedAt = DateTimeOffset.UtcNow };
        records = await store.UpsertAsync(updated, CancellationToken.None);
        Assert.Equal(100, records.Count);
        Assert.Equal(updated, Assert.Single(records, item => item.TransactionId == updated.TransactionId));
        Assert.Equal(records.OrderByDescending(x => x.CreatedAt).Select(x => x.TransactionId), records.Select(x => x.TransactionId));
    }

    [Fact]
    public async Task RetentionNeverDiscardsAnUnresolvedOperationToMakeRoom()
    {
        var store = new OperationHistoryStore(_directory);
        for (var index = 0; index < 100; index++) await store.UpsertAsync(Record(index), CancellationToken.None);
        var before = await File.ReadAllBytesAsync(DataPath);
        await Assert.ThrowsAnyAsync<Exception>(() => store.UpsertAsync(Record(101), CancellationToken.None));
        Assert.Equal(before, await File.ReadAllBytesAsync(DataPath));
        var restored = await store.LoadAsync(CancellationToken.None);
        Assert.Equal(100, restored.Count);
        Assert.Contains(restored, item => item.TransactionId == Record(0).TransactionId);
    }

    [Fact]
    public async Task RetentionPrunesOnlyServerConfirmedNotFoundAndPreservesUnresolvedRecords()
    {
        var store = new OperationHistoryStore(_directory);
        for (var index = 0; index < 100; index++)
        {
            var record = Record(index);
            if (index == 0) record = record with { LastConfirmedState = OperationState.NotFound, LastConfirmedAt = record.CreatedAt.AddMinutes(1) };
            if (index == 1) record = record with { LastConfirmedState = OperationState.NotFound };
            if (index == 2) record = record with { LastConfirmedState = OperationState.Pending, LastConfirmedAt = record.CreatedAt.AddMinutes(1) };
            await store.UpsertAsync(record, CancellationToken.None);
        }

        var records = await store.UpsertAsync(Record(100), CancellationToken.None);
        Assert.Equal(100, records.Count);
        Assert.DoesNotContain(records, item => item.TransactionId == Record(0).TransactionId);
        foreach (var index in new[] { 1, 2, 3 })
            Assert.Contains(records, item => item.TransactionId == Record(index).TransactionId);
        var before = await File.ReadAllBytesAsync(DataPath);
        await Assert.ThrowsAnyAsync<Exception>(() => store.UpsertAsync(Record(101), CancellationToken.None));
        Assert.Equal(before, await File.ReadAllBytesAsync(DataPath));
    }

    [Theory]
    [InlineData("host")]
    [InlineData("port")]
    [InlineData("user")]
    [InlineData("key-path")]
    public async Task ExistingTransactionIdentityCannotBeReboundByAnUpsert(string change)
    {
        var store = new OperationHistoryStore(_directory);
        var original = Record(1);
        await store.UpsertAsync(original, CancellationToken.None);
        var changed = change switch
        {
            "host" => original with { Host = "other.example" },
            "port" => original with { NewPort = 2222 },
            "user" => original with { NewUsername = "otheradmin" },
            _ => original with { NewPrivateKeyPath = "C:\\fixture\\other.pem" }
        };
        var before = await File.ReadAllBytesAsync(DataPath);
        await Assert.ThrowsAnyAsync<Exception>(() => store.UpsertAsync(changed, CancellationToken.None));
        Assert.Equal(before, await File.ReadAllBytesAsync(DataPath));
        Assert.Equal(original, Assert.Single(await store.LoadAsync(CancellationToken.None)));
    }

    [Fact]
    public async Task ConcurrentStoreInstancesDoNotLoseSuccessfulUpserts()
    {
        var tasks = Enumerable.Range(0, 16).Select(index => new OperationHistoryStore(_directory).UpsertAsync(Record(index), CancellationToken.None));
        await Task.WhenAll(tasks);
        var loaded = await new OperationHistoryStore(_directory).LoadAsync(CancellationToken.None);
        Assert.Equal(16, loaded.Count);
        Assert.Equal(16, loaded.Select(x => x.TransactionId).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task PreCancelledWritePreservesPreviouslyCommittedCiphertext()
    {
        var store = new OperationHistoryStore(_directory);
        await store.UpsertAsync(Record(1), CancellationToken.None);
        var before = await File.ReadAllBytesAsync(DataPath);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.UpsertAsync(Record(2), cancellation.Token));
        Assert.Equal(before, await File.ReadAllBytesAsync(DataPath));
        Assert.Single(await store.LoadAsync(CancellationToken.None));
    }

    [Fact]
    public async Task FailedAtomicReplacementPreservesOldHistoryAndCleansTemporaryFile()
    {
        var store = new OperationHistoryStore(_directory);
        await store.UpsertAsync(Record(1), CancellationToken.None);
        var before = await File.ReadAllBytesAsync(DataPath);
        // Windows denies replacement while another reader has not shared DELETE access.
        using (var reader = new FileStream(DataPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var error = await Xunit.Record.ExceptionAsync(() => store.UpsertAsync(Record(2), CancellationToken.None));
            Assert.True(error is IOException or UnauthorizedAccessException, "The blocked replacement must fail as a filesystem error.");
        }
        Assert.Equal(before, await File.ReadAllBytesAsync(DataPath));
        Assert.Single(await store.LoadAsync(CancellationToken.None));
        Assert.All(Directory.GetFiles(_directory), path => Assert.Contains(Path.GetFileName(path), new[] { "operations.dat", "operations.lock" }));
    }

    [Fact]
    public async Task CrossProcessFileLockIsRespectedAndWaitingCanBeCancelled()
    {
        var store = new OperationHistoryStore(_directory);
        await store.UpsertAsync(Record(1), CancellationToken.None);
        var before = await File.ReadAllBytesAsync(DataPath);
        var command = "$ErrorActionPreference='Stop'; $historyLock=$null; try { $historyLock=[System.IO.File]::Open('" + LockPath.Replace("'", "''", StringComparison.Ordinal)
            + "',[System.IO.FileMode]::OpenOrCreate,[System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::None); [Console]::WriteLine('LOCKED'); [Console]::Out.Flush(); [Console]::ReadLine() | Out-Null } finally { if ($null -ne $historyLock) { $historyLock.Dispose() } }";
        var start = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command }) start.ArgumentList.Add(argument);
        using var holder = Process.Start(start) ?? throw new InvalidOperationException("Cannot start the history lock holder.");
        var stderr = holder.StandardError.ReadToEndAsync();
        Exception? primaryFailure = null;
        try
        {
            // Cold Windows PowerShell startup competes with RSA/Argon2 tests on shared CI CPUs.
            // Only readiness has a generous bound; the lock/cancellation check below remains 200 ms.
            var ready = await holder.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(60));
            var startupError = stderr.IsCompletedSuccessfully ? await stderr : "";
            Assert.True(ready == "LOCKED", "The lock holder did not confirm ownership: " + ready +
                (startupError.Length == 0 ? "" : "\n" + startupError));
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.UpsertAsync(Record(2), cancellation.Token));
            Assert.Equal(before, await File.ReadAllBytesAsync(DataPath));
        }
        catch (Exception failure)
        {
            primaryFailure = failure;
            _lockHolderFailure = failure;
            throw;
        }
        finally
        {
            try
            {
                // EOF releases ReadLine even if startup had not reached LOCKED before a failure.
                try { holder.StandardInput.Close(); }
                catch (IOException) { /* The child may already have closed its pipe. */ }
                if (!holder.HasExited)
                {
                    try { await holder.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); }
                    catch (TimeoutException)
                    {
                        if (!holder.HasExited) holder.Kill(entireProcessTree: true);
                        await holder.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
                    }
                }
                await stderr.WaitAsync(TimeSpan.FromSeconds(30));
            }
            catch (Exception cleanupFailure)
            {
                if (primaryFailure is null) { _lockHolderFailure = cleanupFailure; throw; }
                primaryFailure.Data["LockHolderCleanup"] = cleanupFailure.ToString();
            }
        }
        Assert.Equal(2, (await store.UpsertAsync(Record(2), CancellationToken.None)).Count);
    }

    private static OperationRecord Record(int index) => new($"20261106120000-{index:x12}",
        new DateTimeOffset(2026, 11, 6, 0, 0, 0, TimeSpan.Zero).AddSeconds(index), "fixture.example", 22, "root", "C:\\fixture\\source.pem",
        22022, "sshadmin", "C:\\fixture\\target.ppk", Identity().Algorithm, Identity().KeyBase64, Identity().Fingerprint);
    internal static HostIdentity Identity(string host = "fixture.example", int port = 22) => new(host, port, "ssh-ed25519",
        KeyService.Fingerprint(InputValidatorsTests.Ed25519Key), InputValidatorsTests.Ed25519Key.Split(' ')[1]);

    public void Dispose()
    {
        if (!Directory.Exists(_directory)) return;
        try
        {
            foreach (var path in Directory.GetFiles(_directory)) File.Delete(path);
            Directory.Delete(_directory);
        }
        catch (Exception cleanupFailure) when (_lockHolderFailure is not null)
        { _lockHolderFailure.Data["HistoryDirectoryCleanup"] = cleanupFailure.ToString(); }
    }
}
