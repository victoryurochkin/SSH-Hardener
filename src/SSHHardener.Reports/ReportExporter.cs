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
            lines.AppendLine($"Port: {plan.OriginalConnection.Port} → {plan.Options.NewPort}; user: {plan.Options.Username}");
            lines.AppendLine("## Requested policy");
            lines.AppendLine("These are the requested plan settings, not measurements of the server after applying changes.");
            AppendCodeBlock(lines, JsonSerializer.Serialize(requestedPolicy, new JsonSerializerOptions { WriteIndented = true }), "json");
            lines.AppendLine("## Connection").AppendLine("```text");
            // Connection names are validated at planning; host is encoded for a human-readable report only.
            lines.AppendLine($"ssh -p {plan.Options.NewPort} -i <private-key-file> {plan.Options.Username}@{plan.OriginalConnection.Host}");
            lines.AppendLine("```").AppendLine("```sshconfig");
            lines.AppendLine($"Host hardened-server\n    HostName {plan.OriginalConnection.Host}\n    Port {plan.Options.NewPort}\n    User {plan.Options.Username}\n    IdentityFile <private-key-file>");
            lines.AppendLine("```");
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
                Transaction = transactionId, Port = plan?.Options.NewPort, User = plan?.Options.Username }, new JsonSerializerOptions { WriteIndented = true }),
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
