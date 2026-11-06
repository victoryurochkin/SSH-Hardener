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
        var options = InputValidatorsTests.ValidOptions with { KeyPassphrase = "distinct-new-key-secret" };
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

    public void Dispose()
    {
        if (!Directory.Exists(_folder)) return;
        foreach (var file in Directory.GetFiles(_folder)) File.Delete(file);
        Directory.Delete(_folder);
    }
}
