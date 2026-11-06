using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SSHHardener.Core;

namespace SSHHardener.Reports;

public sealed class ReportExporter
{
    public async Task ExportAsync(string path, ServerAudit audit, HardeningPlan? plan, HardeningResult? result, CancellationToken ct = default)
    {
        if (plan is not null && result is not null && !string.Equals(plan.TransactionId, result.TransactionId, StringComparison.Ordinal))
            throw new ArgumentException("The plan and result belong to different transactions.");
        if (result is { Committed: true, RolledBack: true })
            throw new ArgumentException("A transaction cannot be reported as both committed and rolled back.");
        var rollbackConfirmed = plan is not null && result?.RolledBack == true;
        var commitConfirmed = plan is not null && result?.Committed == true;
        var connectionBasis = plan is null ? null : rollbackConfirmed ? "rollback" : commitConfirmed ? "committed" : "requested-unconfirmed";
        var connectionPort = rollbackConfirmed ? plan!.OriginalConnection.Port : plan?.Options.NewPort;
        var connectionUser = rollbackConfirmed ? plan!.OriginalConnection.Username : plan?.Options.Username;
        var usesPrivateKey = plan is not null && (!rollbackConfirmed || !string.IsNullOrWhiteSpace(plan.OriginalConnection.PrivateKeyPath));
        // Explicit allowlist: never serialize either credential-bearing connection/options object.
        var connection = plan is null ? null : new
        {
            Confirmed = rollbackConfirmed || commitConfirmed,
            Host = plan.OriginalConnection.Host, Port = connectionPort, User = connectionUser, UsesPrivateKey = usesPrivateKey
        };
        var preChangeAudit = plan is not null && ReferenceEquals(audit, plan.Audit);
        var auditSnapshotKind = preChangeAudit ? "pre-change" : "independent-audit";
        var auditHeading = preChangeAudit ? "## Audit — before changes" : "## Audit — independent snapshot";
        var auditSnapshotNote = preChangeAudit
            ? "This audit was captured before the changes in this plan. Export does not run a new audit; this snapshot is not post-change verification."
            : "This audit was supplied independently of the plan. Its timing relative to changes is not verified. Export does not run a new audit.";
        var transactionId = result?.TransactionId ?? plan?.TransactionId;
        // Export only the requested policy values, never the options object containing key secrets.
        var requestedPolicy = plan is null ? null : new
        {
            plan.Options.MaxAuthTries,
            Fail2banEnabled = plan.Options.ConfigureFail2Ban,
            plan.Options.MaxRetry,
            plan.Options.FindTimeSeconds,
            plan.Options.BanSeconds,
            plan.Options.DisablePasswordAuthentication,
            plan.Options.CloseOldPort
        };
        var lines = new StringBuilder();
        lines.AppendLine("# SSH-Hardener — report").AppendLine().AppendLine("Author: @victoryur");
        lines.AppendLine($"UTC: {DateTimeOffset.UtcNow:O}");
        lines.AppendLine($"AuditSnapshotKind: {auditSnapshotKind}");
        lines.AppendLine($"OS: {Plain(audit.OsId)} {Plain(audit.OsVersion)}; {Plain(audit.InitSystem)}; firewall={Plain(audit.Firewall)}");
        if (transactionId is not null)
        {
            lines.AppendLine("## Transaction");
            AppendCodeBlock(lines, transactionId, "text");
        }
        if (result is not null) lines.AppendLine($"Committed: {result.Committed}; rollback: {result.RolledBack}\n{Plain(result.Message)}");
        if (plan is not null)
        {
            lines.AppendLine($"Planned port change: {plan.OriginalConnection.Port} → {plan.Options.NewPort}; planned user: {plan.Options.Username}");
            lines.AppendLine("## Requested policy");
            lines.AppendLine("These are the requested plan settings, not measurements of the server after applying changes.");
            AppendCodeBlock(lines, JsonSerializer.Serialize(requestedPolicy, new JsonSerializerOptions { WriteIndented = true }), "json");
            if (rollbackConfirmed || commitConfirmed)
            {
                lines.AppendLine(rollbackConfirmed ? "## Connection — after rollback" : "## Connection — committed target");
                lines.AppendLine($"OutcomeConnection: {connectionUser}@{plan.OriginalConnection.Host}:{connectionPort} ({connectionBasis})");
                lines.AppendLine("This endpoint follows the recorded outcome. Export does not perform a fresh connection test.");
                if (usesPrivateKey)
                    lines.AppendLine("The ssh command requires an OpenSSH-compatible private-key file. PuTTY PPK files are used with a PPK-capable client such as RDM/PuTTY.");
                else
                    lines.AppendLine("Use the original authentication settings. No private-key identity was configured for the original connection.");
                lines.AppendLine("```text");
                // Connection names are validated at planning; real private-key paths are never exported.
                var identityArgument = usesPrivateKey ? " -i <private-key-file>" : "";
                lines.AppendLine($"ssh -p {connectionPort}{identityArgument} {connectionUser}@{plan.OriginalConnection.Host}");
                lines.AppendLine("```").AppendLine("```sshconfig");
                lines.AppendLine($"Host hardened-server\n    HostName {plan.OriginalConnection.Host}\n    Port {connectionPort}\n    User {connectionUser}");
                if (usesPrivateKey) lines.AppendLine("    IdentityFile <private-key-file>");
                lines.AppendLine("```");
            }
            else
            {
                lines.AppendLine("## Connection — planned, unverified");
                lines.AppendLine("The operation has no confirmed outcome. The planned endpoint is unverified; no working connection command is asserted.");
            }
            foreach (var warning in plan.Warnings) lines.AppendLine("- " + Plain(warning));
        }
        lines.AppendLine(auditHeading).AppendLine(auditSnapshotNote);
        AppendCodeBlock(lines, audit.RawReport, "text");
        var markdown = lines.ToString();
        var extension = Path.GetExtension(path).ToLowerInvariant();
        var content = extension switch
        {
            ".html" or ".htm" => "<!doctype html><html lang=\"ru\"><meta charset=\"utf-8\"><title>SSH-Hardener</title><style>body{max-width:1100px;margin:40px auto;font:16px system-ui;background:#101927;color:#e5ecf5}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><pre>" + WebUtility.HtmlEncode(markdown) + "</pre></html>",
            ".json" => JsonSerializer.Serialize(new { Author = "@victoryur", AuditSnapshotKind = auditSnapshotKind,
                AuditSnapshotNote = auditSnapshotNote, Audit = audit, Result = result, RequestedPolicy = requestedPolicy,
                Transaction = transactionId, ConnectionBasis = connectionBasis, Connection = connection,
                Port = connectionPort, User = connectionUser }, new JsonSerializerOptions { WriteIndented = true }),
            ".md" => markdown,
            _ => throw new ArgumentException("Choose .md, .html or .json. PDF can be printed from HTML.")
        };
        await File.WriteAllTextAsync(path, content, new UTF8Encoding(false), ct).ConfigureAwait(false);
    }
    private static void AppendCodeBlock(StringBuilder lines, string value, string language)
    {
        var fence = new string('`', Math.Max(3, Regex.Matches(value, "`+").Select(x => x.Length + 1).DefaultIfEmpty(3).Max()));
        lines.AppendLine(fence + language).AppendLine(value).AppendLine(fence);
    }
    private static string Plain(string value) => Regex.Replace(WebUtility.HtmlEncode(value.Replace('\r', ' ').Replace('\n', ' ')), @"([\\`*_{}\[\]()#+.!|>-])", @"\$1");
}
