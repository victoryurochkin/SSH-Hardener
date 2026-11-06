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
        var lines = new StringBuilder();
        lines.AppendLine("# SSH-Hardener — report").AppendLine().AppendLine("Author: @victoryur");
        lines.AppendLine($"UTC: {DateTimeOffset.UtcNow:O}");
        lines.AppendLine($"OS: {Plain(audit.OsId)} {Plain(audit.OsVersion)}; {Plain(audit.InitSystem)}; firewall={Plain(audit.Firewall)}");
        if (result is not null) lines.AppendLine($"Transaction: {Plain(result.TransactionId)}; committed={result.Committed}; rollback={result.RolledBack}\n{Plain(result.Message)}");
        if (plan is not null)
        {
            lines.AppendLine($"Port: {plan.OriginalConnection.Port} → {plan.Options.NewPort}; user: {plan.Options.Username}");
            lines.AppendLine("## Connection").AppendLine("```text");
            // Connection names are validated at planning; host is encoded for a human-readable report only.
            lines.AppendLine($"ssh -p {plan.Options.NewPort} -i <private-key-file> {plan.Options.Username}@{plan.OriginalConnection.Host}");
            lines.AppendLine("```").AppendLine("```sshconfig");
            lines.AppendLine($"Host hardened-server\n    HostName {plan.OriginalConnection.Host}\n    Port {plan.Options.NewPort}\n    User {plan.Options.Username}\n    IdentityFile <private-key-file>");
            lines.AppendLine("```");
            foreach (var warning in plan.Warnings) lines.AppendLine("- " + Plain(warning));
        }
        var fence = new string('`', Math.Max(3, Regex.Matches(audit.RawReport, "`+").Select(x => x.Length + 1).DefaultIfEmpty(3).Max()));
        lines.AppendLine("## Audit").AppendLine(fence + "text").AppendLine(audit.RawReport).AppendLine(fence);
        var markdown = lines.ToString();
        var extension = Path.GetExtension(path).ToLowerInvariant();
        var content = extension switch
        {
            ".html" or ".htm" => "<!doctype html><html lang=\"ru\"><meta charset=\"utf-8\"><title>SSH-Hardener</title><style>body{max-width:1100px;margin:40px auto;font:16px system-ui;background:#101927;color:#e5ecf5}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><pre>" + WebUtility.HtmlEncode(markdown) + "</pre></html>",
            ".json" => JsonSerializer.Serialize(new { Author = "@victoryur", Audit = audit, Result = result,
                Transaction = plan?.TransactionId, Port = plan?.Options.NewPort, User = plan?.Options.Username }, new JsonSerializerOptions { WriteIndented = true }),
            ".md" => markdown,
            _ => throw new ArgumentException("Choose .md, .html or .json. PDF can be printed from HTML.")
        };
        await File.WriteAllTextAsync(path, content, new UTF8Encoding(false), ct).ConfigureAwait(false);
    }
    private static string Plain(string value) => Regex.Replace(WebUtility.HtmlEncode(value.Replace('\r', ' ').Replace('\n', ' ')), @"([\\`*_{}\[\]()#+.!|>-])", @"\$1");
}
