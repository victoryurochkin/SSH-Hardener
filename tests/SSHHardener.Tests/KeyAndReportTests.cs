using System.Net;
using System.Text.Json;
using SSHHardener.Core;
using SSHHardener.Reports;
using SSHHardener.Ssh;

namespace SSHHardener.Tests;

public sealed class KeyAndReportTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "sshhardener-artifact-tests-" + Guid.NewGuid().ToString("N"));

    public KeyAndReportTests() => Directory.CreateDirectory(_folder);

    [Fact]
    public async Task EncryptedRsaKeyRoundTripsThroughActualSshParser()
    {
        var path = Path.Combine(_folder, "key.pem");
        var service = new KeyService();
        var publicKey = await service.GenerateRsaAsync(path, "test-passphrase-42", CancellationToken.None);
        Assert.StartsWith("ssh-rsa ", publicKey);
        InputValidators.ValidatePublicKey(publicKey);
        Assert.Equal(publicKey, service.ReadPublicKey(path, "test-passphrase-42"));
        Assert.Contains("BEGIN ENCRYPTED PRIVATE KEY", await File.ReadAllTextAsync(path, CancellationToken.None));
        Assert.ThrowsAny<Exception>(() => service.ReadPublicKey(path, "incorrect-passphrase"));
        await Assert.ThrowsAsync<IOException>(() => service.GenerateRsaAsync(path, "test-passphrase-42", CancellationToken.None));
        Assert.Equal(publicKey.Trim(), (await File.ReadAllTextAsync(path + ".pub", CancellationToken.None)).Trim());
    }

    [Fact]
    public async Task HtmlReportEncodesServerControlledTextAndOmitsConnectionSecrets()
    {
        var audit = new ServerAudit { RawReport = "<script>alert('server')</script>", OsId = "debian", OsVersion = "12" };
        var connection = new ConnectionOptions("server.example", 22, "root", Password: "distinct-password-secret", Passphrase: "distinct-passphrase-secret", SudoPassword: "distinct-sudo-secret");
        var options = InputValidatorsTests.ValidOptions with
        {
            KeyPassphrase = "distinct-new-key-secret",
            NewUserSudoPassword = "distinct-new-sudo-secret",
            PrivateKeyPath = "distinct-private-key-path.pem"
        };
        var plan = new HardeningPlan("test-transaction", audit, connection, options, [], []);
        var path = Path.Combine(_folder, "report.html");
        await new ReportExporter().ExportAsync(path, audit, plan, null, CancellationToken.None);
        var html = await File.ReadAllTextAsync(path, CancellationToken.None);
        Assert.Contains("&lt;script&gt;", html);
        Assert.DoesNotContain("<script>", html);
        Assert.DoesNotContain("distinct-password-secret", html);
        Assert.DoesNotContain("distinct-passphrase-secret", html);
        Assert.DoesNotContain("distinct-sudo-secret", html);
        Assert.DoesNotContain("distinct-new-key-secret", html);
        Assert.DoesNotContain("distinct-new-sudo-secret", html);
        Assert.DoesNotContain("distinct-private-key-path.pem", html);
    }

    [Fact]
    public async Task JsonExportDoesNotSerializePlanWithCredentials()
    {
        var audit = new ServerAudit { RawReport = "test audit" };
        var plan = new HardeningPlan("test-transaction", audit, new ConnectionOptions("server.example", 22, "root", Password: "do-not-export-password"), InputValidatorsTests.ValidOptions, [], []);
        var path = Path.Combine(_folder, "report.json");
        await new ReportExporter().ExportAsync(path, audit, plan, null, CancellationToken.None);
        var json = await File.ReadAllTextAsync(path, CancellationToken.None);
        using var parsed = JsonDocument.Parse(json);
        Assert.Equal("test-transaction", parsed.RootElement.GetProperty("Transaction").GetString());
        Assert.DoesNotContain("do-not-export-password", json);
        Assert.False(parsed.RootElement.TryGetProperty("OriginalConnection", out _));
    }

    [Theory]
    [InlineData(".md")]
    [InlineData(".html")]
    public async Task PlanAuditIsClearlyLabeledBeforeChangesAndTransactionIdCopiesExactly(string extension)
    {
        const string transactionId = "20261106104500-0123456789ab";
        var audit = new ServerAudit { RawReport = "PasswordAuthentication yes" };
        var options = InputValidatorsTests.ValidOptions with { ConfigureFail2Ban = true, MaxAuthTries = 4 };
        var plan = new HardeningPlan(transactionId, audit, new ConnectionOptions("server.example", 22, "root"), options, [], []);
        var result = new HardeningResult(transactionId, true, false, "Transaction committed", DateTimeOffset.UtcNow);
        var path = Path.Combine(_folder, "before-changes" + extension);

        await new ReportExporter().ExportAsync(path, audit, plan, result, CancellationToken.None);

        var content = WebUtility.HtmlDecode(await File.ReadAllTextAsync(path, CancellationToken.None)).Replace("\r\n", "\n");
        Assert.Contains("AuditSnapshotKind: pre-change", content);
        Assert.Contains("## Audit — before changes", content);
        Assert.Contains("captured before the changes in this plan", content);
        Assert.Contains("Export does not run a new audit", content);
        Assert.Contains("not post-change verification", content);
        Assert.Contains("\n" + transactionId + "\n", content);
        Assert.DoesNotContain(transactionId.Replace("-", "\\-"), content);
        Assert.Contains("## Requested policy", content);
        Assert.Contains("\"MaxAuthTries\": 4", content);
        Assert.Contains("not measurements of the server after applying changes", content);
    }

    [Theory]
    [InlineData(".md")]
    [InlineData(".html")]
    [InlineData(".json")]
    public async Task ValueEqualAuditFromAnotherObjectIsIndependentRatherThanPostChangeVerification(string extension)
    {
        var planAudit = new ServerAudit { RawReport = "Independent timing cannot be inferred" };
        var suppliedAudit = planAudit with { };
        Assert.Equal(planAudit, suppliedAudit);
        Assert.NotSame(planAudit, suppliedAudit);
        var plan = new HardeningPlan("independent-transaction", planAudit, new ConnectionOptions("server.example", 22, "root"), InputValidatorsTests.ValidOptions, [], []);
        var path = Path.Combine(_folder, "independent" + extension);

        await new ReportExporter().ExportAsync(path, suppliedAudit, plan, null, CancellationToken.None);

        var content = WebUtility.HtmlDecode(await File.ReadAllTextAsync(path, CancellationToken.None));
        if (extension == ".json")
        {
            using var parsed = JsonDocument.Parse(content);
            Assert.Equal("independent-audit", parsed.RootElement.GetProperty("AuditSnapshotKind").GetString());
            Assert.Contains("timing relative to changes is not verified", parsed.RootElement.GetProperty("AuditSnapshotNote").GetString());
        }
        else
        {
            Assert.Contains("AuditSnapshotKind: independent-audit", content);
            Assert.Contains("## Audit — independent snapshot", content);
            Assert.Contains("timing relative to changes is not verified", content);
        }
    }

    [Fact]
    public async Task JsonRequestedPolicyContainsCustomValuesAndNoCredentialBearingOptions()
    {
        var audit = new ServerAudit { RawReport = "pre-change audit" };
        var connection = new ConnectionOptions("server.example", 22, "root", Password: "password-secret",
            PrivateKeyPath: "connection-private-path.pem", Passphrase: "connection-key-secret", SudoPassword: "sudo-secret");
        var options = InputValidatorsTests.ValidOptions with
        {
            MaxAuthTries = 4, ConfigureFail2Ban = true, MaxRetry = 5, FindTimeSeconds = 900, BanSeconds = 7200,
            DisablePasswordAuthentication = false, CloseOldPort = true,
            KeyPassphrase = "new-key-secret", NewUserSudoPassword = "new-sudo-secret", PrivateKeyPath = "new-private-path.pem",
            TotpSecret = "totp-seed-secret", TotpRecoveryCodes = ["recovery-code-secret"],
            VerificationSudoPassword = "verification-sudo-secret"
        };
        var plan = new HardeningPlan("policy-transaction", audit, connection, options, [], []);
        var path = Path.Combine(_folder, "requested-policy.json");

        await new ReportExporter().ExportAsync(path, audit, plan, null, CancellationToken.None);

        var content = await File.ReadAllTextAsync(path, CancellationToken.None);
        using var parsed = JsonDocument.Parse(content);
        Assert.Equal("pre-change", parsed.RootElement.GetProperty("AuditSnapshotKind").GetString());
        var policy = parsed.RootElement.GetProperty("RequestedPolicy");
        Assert.Equal(new[] { "AccountAccess", "BanSeconds", "CloseOldPort", "DisablePasswordAuthentication", "Fail2banEnabled",
            "FindTimeSeconds", "MaxAuthTries", "MaxRetry", "RestrictedCommands", "SftpReadOnly", "SudoPolicy", "TotpEnabled" },
            policy.EnumerateObject().Select(x => x.Name).OrderBy(x => x, StringComparer.Ordinal).ToArray());
        Assert.Equal(4, policy.GetProperty("MaxAuthTries").GetInt32());
        Assert.True(policy.GetProperty("Fail2banEnabled").GetBoolean());
        Assert.Equal(5, policy.GetProperty("MaxRetry").GetInt32());
        Assert.Equal(900, policy.GetProperty("FindTimeSeconds").GetInt32());
        Assert.Equal(7200, policy.GetProperty("BanSeconds").GetInt32());
        Assert.False(policy.GetProperty("DisablePasswordAuthentication").GetBoolean());
        Assert.True(policy.GetProperty("CloseOldPort").GetBoolean());
        foreach (var secret in new[] { "password-secret", "connection-private-path.pem", "connection-key-secret", "sudo-secret", "new-key-secret", "new-sudo-secret", "new-private-path.pem", "totp-seed-secret", "recovery-code-secret", "verification-sudo-secret" })
            Assert.DoesNotContain(secret, content);
        Assert.False(parsed.RootElement.TryGetProperty("OriginalConnection", out _));
        Assert.False(parsed.RootElement.TryGetProperty("Options", out _));
    }

    [Fact]
    public async Task AuditOnlyJsonHasNoInventedRequestedPolicy()
    {
        var path = Path.Combine(_folder, "audit-only.json");
        await new ReportExporter().ExportAsync(path, new ServerAudit(), null, null, CancellationToken.None);
        using var parsed = JsonDocument.Parse(await File.ReadAllTextAsync(path, CancellationToken.None));
        Assert.Equal("independent-audit", parsed.RootElement.GetProperty("AuditSnapshotKind").GetString());
        Assert.Equal(JsonValueKind.Null, parsed.RootElement.GetProperty("RequestedPolicy").ValueKind);
        Assert.Equal(JsonValueKind.Null, parsed.RootElement.GetProperty("Transaction").ValueKind);
    }

    [Theory]
    [InlineData(false, "sftp -P 22022 -i <private-key-file> sshadmin@server.example", "sftp")]
    [InlineData(true, "ssh -p 2222 -i <private-key-file> controller@server.example", "ssh")]
    public async Task SftpOutcomeCommandUsesFileTransferOnlyUntilRollbackRestoresAdministrator(bool rolledBack, string command, string kind)
    {
        var audit = new ServerAudit();
        var plan = new HardeningPlan("sftp-report", audit,
            new ConnectionOptions("server.example", 2222, "controller", PrivateKeyPath: "source-secret-path"),
            InputValidatorsTests.ValidOptions with { AccountAccess = AccountAccess.SftpOnly, SudoMode = SudoPolicyMode.None }, [], []);
        var result = new HardeningResult(plan.TransactionId, !rolledBack, rolledBack, "Confirmed", DateTimeOffset.UtcNow);
        var path = Path.Combine(_folder, "sftp.md");
        await new ReportExporter().ExportAsync(path, audit, plan, result);
        Assert.Contains(command, await File.ReadAllTextAsync(path));
        await new ReportExporter().ExportAsync(Path.ChangeExtension(path, ".json"), audit, plan, result);
        using var json = JsonDocument.Parse(await File.ReadAllTextAsync(Path.ChangeExtension(path, ".json")));
        Assert.Equal(kind, json.RootElement.GetProperty("ConnectionKind").GetString());
    }

    [Fact]
    public void CredentialModelsDoNotExposeNewSecretsThroughSerializationOrRecordFormatting()
    {
        var connection = new ConnectionOptions("server.example", 22, "user", "conn-secret", Passphrase: "key-secret", SudoPassword: "sudo-secret")
        { OneTimeCodeProvider = _ => Task.FromResult("123456") };
        var options = InputValidatorsTests.ValidOptions with
        {
            KeyPassphrase = "target-key-secret", NewUserSudoPassword = "target-password-secret", VerificationSudoPassword = "verify-sudo-secret",
            EnableTotp = true, TotpSecret = "totp-seed-secret", TotpEnrollmentCode = "enrollment-code-secret", TotpRecoveryCodes = ["recovery-code-secret"],
            VerificationOneTimeCodeProvider = _ => Task.FromResult("123456")
        };
        var output = connection + "\n" + options + "\n" + JsonSerializer.Serialize(connection) + "\n" + JsonSerializer.Serialize(options);
        foreach (var secret in new[] { "conn-secret", "key-secret", "sudo-secret", "target-key-secret", "target-password-secret", "verify-sudo-secret", "totp-seed-secret", "enrollment-code-secret", "recovery-code-secret" })
            Assert.DoesNotContain(secret, output);
    }

    public void Dispose()
    {
        if (!Directory.Exists(_folder)) return;
        foreach (var file in Directory.GetFiles(_folder)) File.Delete(file);
        Directory.Delete(_folder);
    }
}
