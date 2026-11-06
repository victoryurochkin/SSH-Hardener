using System.Net;
using System.Text.Json;
using SSHHardener.Core;
using SSHHardener.Reports;

namespace SSHHardener.Tests;

public sealed class ReportOutcomeTests : IDisposable
{
    private const string TransactionId = "20261106120000-123456789abc";
    private const string OriginalKey = "C:\\fixture\\original-private-key-marker.pem";
    private const string TargetKey = "C:\\fixture\\target-private-key-marker.ppk";
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "sshhardener-report-outcome-tests-" + Guid.NewGuid().ToString("N"));

    public ReportOutcomeTests() => Directory.CreateDirectory(_folder);

    [Theory]
    [InlineData(".md", false)]
    [InlineData(".md", true)]
    [InlineData(".html", false)]
    [InlineData(".html", true)]
    public async Task ConfirmedRollbackConnectionUsesOriginalEndpointAndItsAuthenticationMethod(string extension, bool originalUsesKey)
    {
        var plan = Plan(originalUsesKey);
        var text = await ExportTextAsync(extension, plan, Result(committed: false, rolledBack: true));

        Assert.Contains(originalUsesKey
            ? "ssh -p 2222 -i <private-key-file> originaladmin@fixture.example"
            : "ssh -p 2222 originaladmin@fixture.example", text);
        Assert.Contains("HostName fixture.example\n    Port 2222\n    User originaladmin", text);
        Assert.DoesNotContain("ssh -p 2299", text);
        Assert.DoesNotContain("    Port 2299", text);
        Assert.DoesNotContain("    User targetadmin", text);
        if (originalUsesKey) Assert.Contains("IdentityFile <private-key-file>", text);
        else
        {
            Assert.DoesNotContain(" -i ", text);
            Assert.DoesNotContain("IdentityFile", text);
        }
        Assert.Contains("rollback", ConnectionSection(text), StringComparison.OrdinalIgnoreCase);
        AssertSecretsAbsent(text);
    }

    [Theory]
    [InlineData(".md")]
    [InlineData(".html")]
    public async Task ConfirmedCommitConnectionUsesTargetEndpointAndOnlyAKeyPlaceholder(string extension)
    {
        var text = await ExportTextAsync(extension, Plan(originalUsesKey: false), Result(committed: true, rolledBack: false));

        Assert.Contains("ssh -p 2299 -i <private-key-file> targetadmin@fixture.example", text);
        Assert.Contains("HostName fixture.example\n    Port 2299\n    User targetadmin\n    IdentityFile <private-key-file>", text);
        Assert.DoesNotContain("ssh -p 2222", text);
        AssertSecretsAbsent(text);
    }

    [Theory]
    [InlineData(".md", false)]
    [InlineData(".md", true)]
    [InlineData(".html", false)]
    [InlineData(".html", true)]
    public async Task UnknownOutcomeLabelsConnectionAsPlannedAndUnverified(string extension, bool absentResult)
    {
        var text = await ExportTextAsync(extension, Plan(originalUsesKey: false), absentResult ? null : Result(committed: false, rolledBack: false));
        var connection = ConnectionSection(text);

        Assert.Contains("planned", connection, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("unverified", connection, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ssh -p ", connection);
        Assert.DoesNotContain("```sshconfig", connection);
        Assert.DoesNotContain("IdentityFile", connection);
        AssertSecretsAbsent(text);
    }

    [Theory]
    [InlineData("rollback", false)]
    [InlineData("rollback", true)]
    [InlineData("committed", false)]
    [InlineData("unconfirmed", false)]
    [InlineData("no-result", false)]
    public async Task JsonConnectionMetadataMatchesOutcomeWithoutSerializingCredentialBearingObjects(string outcome, bool originalUsesKey)
    {
        var plan = Plan(originalUsesKey);
        var result = outcome switch
        {
            "rollback" => Result(committed: false, rolledBack: true),
            "committed" => Result(committed: true, rolledBack: false),
            "unconfirmed" => Result(committed: false, rolledBack: false),
            _ => null
        };
        var path = Path.Combine(_folder, "outcome.json");
        await new ReportExporter().ExportAsync(path, plan.Audit, plan, result);
        using var document = JsonDocument.Parse(await File.ReadAllTextAsync(path));
        var root = document.RootElement;
        var rollback = outcome == "rollback";
        var confirmed = rollback || outcome == "committed";
        var basis = confirmed ? outcome : "requested-unconfirmed";
        var port = rollback ? 2222 : 2299;
        var user = rollback ? "originaladmin" : "targetadmin";

        Assert.Equal(basis, root.GetProperty("ConnectionBasis").GetString());
        Assert.Equal(port, root.GetProperty("Port").GetInt32());
        Assert.Equal(user, root.GetProperty("User").GetString());
        var connection = root.GetProperty("Connection");
        Assert.Equal(5, connection.EnumerateObject().Count());
        Assert.Equal(confirmed, connection.GetProperty("Confirmed").GetBoolean());
        Assert.Equal("fixture.example", connection.GetProperty("Host").GetString());
        Assert.Equal(port, connection.GetProperty("Port").GetInt32());
        Assert.Equal(user, connection.GetProperty("User").GetString());
        Assert.Equal(!rollback || originalUsesKey, connection.GetProperty("UsesPrivateKey").GetBoolean());
        Assert.False(root.TryGetProperty("OriginalConnection", out _));
        Assert.False(root.TryGetProperty("Options", out _));
        var decodedJson = root.ToString();
        foreach (var property in EnumerateJsonStrings(root)) AssertSecretsAbsent(property);
        Assert.DoesNotContain("PrivateKeyPath", decodedJson);
        Assert.DoesNotContain("Passphrase", decodedJson);
    }

    [Theory]
    [InlineData(".md", false)]
    [InlineData(".md", true)]
    [InlineData(".html", false)]
    [InlineData(".html", true)]
    [InlineData(".json", false)]
    [InlineData(".json", true)]
    public async Task MismatchedResultNeverCreatesOrOverwritesAnUnrelatedReport(string extension, bool existingReport)
    {
        var plan = Plan(originalUsesKey: true);
        var path = Path.Combine(_folder, "mismatched" + extension);
        const string previousReport = "previous report must remain intact";
        if (existingReport) await File.WriteAllTextAsync(path, previousReport);
        var mismatch = Result(committed: false, rolledBack: true) with { TransactionId = "20261106120000-fedcba987654" };

        var failure = await Record.ExceptionAsync(() => new ReportExporter().ExportAsync(path, plan.Audit, plan, mismatch));

        Assert.True(failure is ArgumentException or InvalidOperationException, "A result from another transaction must be refused before report output.");
        if (existingReport) Assert.Equal(previousReport, await File.ReadAllTextAsync(path));
        else Assert.False(File.Exists(path));
    }

    private async Task<string> ExportTextAsync(string extension, HardeningPlan plan, HardeningResult? result)
    {
        var path = Path.Combine(_folder, "outcome" + extension);
        await new ReportExporter().ExportAsync(path, plan.Audit, plan, result);
        return WebUtility.HtmlDecode(await File.ReadAllTextAsync(path)).Replace("\r\n", "\n", StringComparison.Ordinal);
    }

    private static string ConnectionSection(string report)
    {
        var start = report.IndexOf("## Connection", StringComparison.Ordinal);
        Assert.True(start >= 0, "The connection section is missing.");
        var end = report.IndexOf("## Audit", start, StringComparison.Ordinal);
        return end < 0 ? report[start..] : report[start..end];
    }

    private static HardeningPlan Plan(bool originalUsesKey) => new(TransactionId, new ServerAudit { RawReport = "fixture pre-change audit" },
        new ConnectionOptions("fixture.example", 2222, "originaladmin", Password: "original-password-marker",
            PrivateKeyPath: originalUsesKey ? OriginalKey : null, Passphrase: "original-passphrase-marker", SudoPassword: "original-sudo-marker"),
        InputValidatorsTests.ValidOptions with { NewPort = 2299, Username = "targetadmin", PrivateKeyPath = TargetKey,
            KeyPassphrase = "target-passphrase-marker", NewUserSudoPassword = "target-sudo-marker" }, [], []);

    private static HardeningResult Result(bool committed, bool rolledBack) =>
        new(TransactionId, committed, rolledBack, "fixture outcome", DateTimeOffset.UtcNow);

    private static void AssertSecretsAbsent(string report)
    {
        foreach (var secret in new[] { OriginalKey, TargetKey, "original-password-marker", "original-passphrase-marker", "original-sudo-marker", "target-passphrase-marker", "target-sudo-marker" })
            Assert.DoesNotContain(secret, report);
    }

    private static IEnumerable<string> EnumerateJsonStrings(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.String) yield return element.GetString()!;
        else if (element.ValueKind == JsonValueKind.Object)
            foreach (var property in element.EnumerateObject())
                foreach (var value in EnumerateJsonStrings(property.Value)) yield return value;
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray())
                foreach (var value in EnumerateJsonStrings(item)) yield return value;
    }

    public void Dispose()
    {
        foreach (var file in Directory.GetFiles(_folder)) File.Delete(file);
        Directory.Delete(_folder);
    }
}
