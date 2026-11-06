using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SSHHardener.Core;

namespace SSHHardener.Profiles;

/// <summary>Independent per-host transactions; a batch never promises an atomic fleet-wide rollback.</summary>
public sealed partial class BulkHardeningCoordinator
{
    public const int MaximumTargets = 256;
    public const int MaximumCsvCharacters = 1_048_576;
    private readonly IRemoteSessionFactory _sessions;
    private readonly IAuditService _audits;
    private readonly IPlanBuilder _plans;
    private readonly IHardeningEngine _engine;
    private readonly Func<OperationRecord, CancellationToken, Task> _persist;

    public BulkHardeningCoordinator(IRemoteSessionFactory sessions, IAuditService audits, IPlanBuilder plans,
        IHardeningEngine engine, Func<OperationRecord, CancellationToken, Task> persist)
    {
        _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
        _audits = audits ?? throw new ArgumentNullException(nameof(audits));
        _plans = plans ?? throw new ArgumentNullException(nameof(plans));
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _persist = persist ?? throw new ArgumentNullException(nameof(persist));
    }

    [GeneratedRegex(@"\A[a-zA-Z0-9._-]{1,64}\z", RegexOptions.CultureInvariant)]
    private static partial Regex IdPattern();
    [GeneratedRegex(@"\A[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?\z", RegexOptions.CultureInvariant)]
    private static partial Regex UsernamePattern();

    public async Task<BulkPreview> PreviewAsync(IReadOnlyList<BulkTarget> targets,
        Func<BulkTarget, CancellationToken, Task<BulkHostConfiguration>> configurationProvider,
        Func<BulkTarget, HostIdentity, CancellationToken, Task<bool>> trustHost,
        BulkRunSettings? settings = null, IProgress<BulkProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configurationProvider);
        ArgumentNullException.ThrowIfNull(trustHost);
        var hosts = ValidateTargets(targets);
        var run = ValidateSettings(settings);
        var results = new BulkHostPreview?[hosts.Length];
        var enrollmentOwners = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
        var next = -1;
        async Task Worker()
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var index = Interlocked.Increment(ref next);
                if (index >= hosts.Length) break;
                var target = hosts[index];
                BulkHostConfiguration? configuration = null;
                try
                {
                    Report(progress, target, "audit", "Connect, explicitly verify host identity and audit this host", 0);
                    configuration = await configurationProvider(target, cancellationToken).ConfigureAwait(false);
                    ValidateConfiguration(target, configuration);
                    if (configuration.Options.EnableTotp)
                    {
                        var enrollment = Hash(configuration.Options.TotpSecret);
                        if (!enrollmentOwners.TryAdd(enrollment, target.Id))
                            throw new InvalidOperationException("Each host requires its own TOTP enrollment secret.");
                    }
                    await using var session = await _sessions.ConnectAsync(configuration.Connection,
                        identity => EndpointMatches(target, identity.Host, identity.Port)
                            ? trustHost(target, identity, cancellationToken) : Task.FromResult(false), cancellationToken).ConfigureAwait(false);
                    ValidateSession(target, session);
                    var audit = await _audits.AuditAsync(session, cancellationToken).ConfigureAwait(false);
                    var plan = _plans.Build(audit, configuration.Connection, CopyOptions(configuration.Options));
                    // Validate the complete pin without persisting any credentials or remote scripts.
                    _ = OperationRecord.FromPlan(plan, session.Identity);
                    var snapshot = Snapshot(plan);
                    results[index] = new BulkHostPreview(target, snapshot.Audit, snapshot, session.Identity,
                        ConfigurationFingerprint(configuration), PlanFingerprint(snapshot), null);
                    Report(progress, target, "preview-ready", "Host audit and immutable preview are ready", 100);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                { results[index] = Unavailable(target, "Cancelled before the preview completed."); }
                catch (Exception error)
                { results[index] = Unavailable(target, "Host preview failed (" + error.GetType().Name + "). " + Diagnostic(error.Message, configuration)); }
            }
        }
        await Task.WhenAll(Enumerable.Range(0, Math.Min(run.MaxConcurrency, hosts.Length)).Select(_ => Worker())).ConfigureAwait(false);
        for (var index = 0; index < hosts.Length; index++)
            results[index] ??= Unavailable(hosts[index], "Cancelled before this host was started.");
        return new BulkPreview(Array.AsReadOnly(results.Select(x => x!).ToArray()));
    }

    public async Task<BulkBatchResult> ApplyAsync(BulkPreview preview,
        Func<BulkTarget, CancellationToken, Task<BulkHostConfiguration>> configurationProvider,
        BulkRunSettings? settings = null, IProgress<BulkProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(preview);
        ArgumentNullException.ThrowIfNull(configurationProvider);
        var entries = preview.Hosts?.ToArray() ?? throw new ArgumentException("Missing bulk previews.", nameof(preview));
        _ = ValidateTargets(entries.Select(x => x.Target).ToArray());
        var run = ValidateSettings(settings);
        var startedAt = DateTimeOffset.UtcNow;
        var outcomes = new BulkHostOutcome?[entries.Length];
        var next = -1;
        var stop = 0;
        async Task Worker()
        {
            while (!cancellationToken.IsCancellationRequested && Volatile.Read(ref stop) == 0)
            {
                var index = Interlocked.Increment(ref next);
                if (index >= entries.Length) break;
                var entry = entries[index];
                var target = entry.Target;
                var engineStarted = false;
                BulkHostConfiguration? configuration = null;
                try
                {
                    if (!entry.IsReady) throw new InvalidOperationException("A successful per-host preview is required.");
                    if (!SameHash(entry.PlanFingerprint, PlanFingerprint(entry.Plan!)))
                        throw new InvalidOperationException("The approved preview was changed.");
                    configuration = await configurationProvider(target, cancellationToken).ConfigureAwait(false);
                    ValidateConfiguration(target, configuration);
                    if (!SameHash(entry.SettingsFingerprint, ConfigurationFingerprint(configuration)))
                        throw new InvalidOperationException("Host settings changed after the approved preview.");
                    var pin = entry.Identity!;
                    // The preview key is pinned before the transport can transmit credentials.
                    await using var session = await _sessions.ConnectAsync(configuration.Connection,
                        identity => Task.FromResult(EndpointMatches(target, identity.Host, identity.Port) &&
                            identity.Algorithm == pin.Algorithm && identity.KeyBase64 == pin.KeyBase64), cancellationToken).ConfigureAwait(false);
                    ValidateSession(target, session);
                    if (session.Identity.Algorithm != pin.Algorithm || session.Identity.KeyBase64 != pin.KeyBase64)
                        throw new InvalidOperationException("The server identity changed after preview.");
                    var plan = entry.Plan! with
                    {
                        OriginalConnection = configuration.Connection,
                        Options = CopyOptions(configuration.Options)
                    };
                    var record = OperationRecord.FromPlan(plan, session.Identity);
                    Report(progress, target, "history", "Persist recovery metadata before this host can change", 0);
                    await _persist(record, cancellationToken).ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    engineStarted = true;
                    var result = await _engine.ApplyAsync(session, plan,
                        new InlineProgress(value => Report(progress, target, value.Step, value.Message, value.Percent)), cancellationToken).ConfigureAwait(false);
                    if (result.TransactionId != plan.TransactionId || result.Committed && result.RolledBack)
                        throw new InvalidOperationException("The server returned an inconsistent transaction outcome.");
                    var state = result.Committed ? BulkHostState.Committed : result.RolledBack ? BulkHostState.RolledBack : BulkHostState.Unconfirmed;
                    var historyUpdated = false;
                    if (result.Committed || result.RolledBack)
                    {
                        try
                        {
                            using var historyDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                            await _persist(record with
                            {
                                LastConfirmedState = result.Committed ? OperationState.Committed : OperationState.RolledBack,
                                LastConfirmedAt = result.CompletedAt
                            }, historyDeadline.Token).WaitAsync(historyDeadline.Token).ConfigureAwait(false);
                            historyUpdated = true;
                        }
                        catch (Exception) { /* A local history update cannot reverse a confirmed remote commit. */ }
                    }
                    outcomes[index] = new BulkHostOutcome(target, state, plan.TransactionId,
                        (state switch
                        {
                            BulkHostState.Committed => "The server confirmed this host's commit.",
                            BulkHostState.RolledBack => "The server confirmed this host's rollback.",
                            _ => "This host's recovery is not confirmed; inspect its saved operation separately."
                        }) + " " + Diagnostic(result.Message, configuration), historyUpdated, result);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested && !engineStarted)
                { outcomes[index] = new BulkHostOutcome(target, BulkHostState.Skipped, entry.Plan?.TransactionId, "Cancelled before this host's engine was started."); }
                catch (Exception error)
                {
                    outcomes[index] = new BulkHostOutcome(target, engineStarted ? BulkHostState.Unconfirmed : BulkHostState.Failed,
                        entry.Plan?.TransactionId, engineStarted ? "Host outcome is unconfirmed (" + error.GetType().Name + ")." :
                        "Host stopped before its engine was started (" + error.GetType().Name + "). " + Diagnostic(error.Message, configuration));
                }
                if (run.StopOnFirstFailure && outcomes[index]!.State != BulkHostState.Committed)
                    Interlocked.Exchange(ref stop, 1);
            }
        }
        await Task.WhenAll(Enumerable.Range(0, Math.Min(run.MaxConcurrency, entries.Length)).Select(_ => Worker())).ConfigureAwait(false);
        for (var index = 0; index < entries.Length; index++)
            outcomes[index] ??= new BulkHostOutcome(entries[index].Target, BulkHostState.Skipped, entries[index].Plan?.TransactionId,
                cancellationToken.IsCancellationRequested ? "Cancelled before this host was started." : "Skipped after another host failed.");
        return new BulkBatchResult(startedAt, DateTimeOffset.UtcNow, Array.AsReadOnly(outcomes.Select(x => x!).ToArray()));
    }

    public static IReadOnlyList<BulkTarget> ParseCsv(string csv, string defaultUsername = "root", int defaultPort = 22)
    {
        ArgumentNullException.ThrowIfNull(csv);
        if (csv.Length > MaximumCsvCharacters) throw new ArgumentException("Bulk CSV exceeds 1 MiB.", nameof(csv));
        var rows = ReadCsv(csv);
        if (rows.Count == 0) throw new ArgumentException("Bulk CSV is empty.", nameof(csv));
        var header = rows[0].Select(x => x.Trim().TrimStart('\uFEFF')).ToArray();
        var allowed = new[] { "host", "port", "username", "privateKeyPath", "id", "displayName" };
        if (header.Length == 0 || header.Any(x => !allowed.Contains(x, StringComparer.OrdinalIgnoreCase)) ||
            header.Distinct(StringComparer.OrdinalIgnoreCase).Count() != header.Length || !header.Contains("host", StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException("CSV columns must be host, port, username, privateKeyPath, id or displayName; credentials are forbidden.");
        var targets = new List<BulkTarget>();
        foreach (var row in rows.Skip(1))
        {
            if (row.All(string.IsNullOrWhiteSpace)) continue;
            if (row.Length != header.Length) throw new ArgumentException("CSV row width differs from its header.");
            string Cell(string name) { var index = Array.FindIndex(header, x => x.Equals(name, StringComparison.OrdinalIgnoreCase)); return index < 0 ? "" : row[index].Trim(); }
            var host = Cell("host");
            var portText = Cell("port");
            var port = defaultPort;
            if (portText.Length > 0 && !int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out port))
                throw new ArgumentException("CSV contains an invalid port.");
            var username = Cell("username");
            var id = Cell("id");
            var label = Cell("displayName");
            var key = Cell("privateKeyPath");
            targets.Add(new BulkTarget(id.Length == 0 ? (targets.Count + 1).ToString(CultureInfo.InvariantCulture) : id,
                label.Length == 0 ? host : label, host, port, username.Length == 0 ? defaultUsername : username, key.Length == 0 ? null : key));
            if (targets.Count > MaximumTargets) throw new ArgumentException("A batch can contain at most 256 hosts.");
        }
        return Array.AsReadOnly(ValidateTargets(targets));
    }

    private static BulkRunSettings ValidateSettings(BulkRunSettings? settings)
    {
        var value = settings ?? new BulkRunSettings();
        if (value.MaxConcurrency is < 1 or > 4) throw new ArgumentOutOfRangeException(nameof(settings), "Concurrency must be 1–4 hosts.");
        return value;
    }

    private static BulkTarget[] ValidateTargets(IReadOnlyList<BulkTarget> targets)
    {
        ArgumentNullException.ThrowIfNull(targets);
        if (targets.Count is < 1 or > MaximumTargets) throw new ArgumentException("A batch must contain 1–256 hosts.");
        var hosts = new HashSet<string>(StringComparer.Ordinal);
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var copy = targets.ToArray();
        foreach (var target in copy)
        {
            if (target is null || target.Id is null || !IdPattern().IsMatch(target.Id) || !ids.Add(target.Id)) throw new ArgumentException("Target identifiers must be valid and unique.");
            if (target.DisplayName is null || target.DisplayName.Length is 0 or > 128 || target.DisplayName.Any(char.IsControl)) throw new ArgumentException("Invalid target display name.");
            var host = NormalizeHost(target.Host);
            if (!hosts.Add(host)) throw new ArgumentException("A host may occur only once in a batch, including different ports.");
            if (target.Port is < 1 or > 65535 || target.Username is null || !UsernamePattern().IsMatch(target.Username)) throw new ArgumentException("Invalid target port or username.");
            if (target.PrivateKeyPath is not null && (target.PrivateKeyPath.Length is 0 or > 32767 || target.PrivateKeyPath.Any(char.IsControl))) throw new ArgumentException("Invalid target key path.");
        }
        return copy;
    }

    private static string NormalizeHost(string host)
    {
        if (host is null || host.Length is 0 or > 253 || host != host.Trim() || host.Any(char.IsControl) || host.Contains('%')) throw new ArgumentException("Invalid target host.");
        if (IPAddress.TryParse(host, out var address)) return (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
        if (Uri.CheckHostName(host) == UriHostNameType.Unknown) throw new ArgumentException("Invalid target hostname.");
        return new IdnMapping().GetAscii(host.TrimEnd('.')).ToLowerInvariant();
    }

    private static bool EndpointMatches(BulkTarget target, string host, int port) =>
        target.Port == port && NormalizeHost(target.Host) == NormalizeHost(host);

    private static void ValidateConfiguration(BulkTarget target, BulkHostConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(configuration.Connection);
        ArgumentNullException.ThrowIfNull(configuration.Options);
        if (!EndpointMatches(target, configuration.Connection.Host, configuration.Connection.Port) || target.Username != configuration.Connection.Username ||
            target.PrivateKeyPath is not null && target.PrivateKeyPath != configuration.Connection.PrivateKeyPath)
            throw new ArgumentException("Credentials belong to another bulk target.");
    }

    private static void ValidateSession(BulkTarget target, IRemoteSession session)
    {
        if (!EndpointMatches(target, session.Options.Host, session.Options.Port) || session.Options.Username != target.Username ||
            !EndpointMatches(target, session.Identity.Host, session.Identity.Port))
            throw new InvalidOperationException("The session belongs to another bulk target.");
    }

    private static HardeningOptions CopyOptions(HardeningOptions options) => options with
    {
        IgnoreAddresses = (string[])options.IgnoreAddresses.Clone(),
        RestrictedSudoCommands = (RestrictedSudoCommand[])options.RestrictedSudoCommands.Clone(),
        TotpRecoveryCodes = (string[])options.TotpRecoveryCodes.Clone()
    };

    private static HardeningOptions PublicOptions(HardeningOptions options) => CopyOptions(options) with
    {
        KeyPassphrase = null, NewUserSudoPassword = null, TotpSecret = null,
        TotpEnrollmentCode = null, TotpEnrollmentConfirmedAt = null, TotpRecoveryCodes = [],
        VerificationSudoPassword = null, VerificationOneTimeCodeProvider = null
    };

    private static HardeningPlan Snapshot(HardeningPlan plan) => plan with
    {
        OriginalConnection = plan.OriginalConnection with { Password = null, Passphrase = null, SudoPassword = null, OneTimeCodeProvider = null },
        Options = PublicOptions(plan.Options),
        Audit = plan.Audit with { Warnings = Array.AsReadOnly(plan.Audit.Warnings.ToArray()) },
        Steps = Array.AsReadOnly(plan.Steps.ToArray()),
        Warnings = Array.AsReadOnly(plan.Warnings.ToArray())
    };

    private static string ConfigurationFingerprint(BulkHostConfiguration configuration) => Hash(new
    {
        Connection = new { Host = NormalizeHost(configuration.Connection.Host), configuration.Connection.Port, configuration.Connection.Username, configuration.Connection.PrivateKeyPath },
        Options = PublicOptions(configuration.Options),
        TotpIdentity = configuration.Options.EnableTotp ? Hash(new { configuration.Options.TotpSecret, configuration.Options.TotpRecoveryCodes }) : null
    });
    private static string PlanFingerprint(HardeningPlan plan) => Hash(plan);
    private static string Hash<T>(T value)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        try { return Convert.ToHexString(SHA256.HashData(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static bool SameHash(string? expected, string actual) => expected is not null && expected.Length == actual.Length &&
        CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(actual));
    private static string Diagnostic(string message, BulkHostConfiguration? configuration)
    {
        if (configuration is null) return ""; // A provider exception may itself contain credentials we never received.
        var secrets = new[] { configuration.Connection.Password, configuration.Connection.Passphrase,
            configuration.Connection.SudoPassword, configuration.Options.KeyPassphrase, configuration.Options.NewUserSudoPassword,
            configuration.Options.VerificationSudoPassword, configuration.Options.TotpSecret, configuration.Options.TotpEnrollmentCode }
            .Concat(configuration.Options.TotpRecoveryCodes).Where(value => !string.IsNullOrEmpty(value)).OrderByDescending(value => value!.Length);
        foreach (var secret in secrets) message = message.Replace(secret!, "[redacted]", StringComparison.Ordinal);
        message = new string(message.Select(character => char.IsControl(character) && character != '\n' ? ' ' : character).ToArray());
        return message.Length > 2048 ? message[..2048] : message;
    }
    private static BulkHostPreview Unavailable(BulkTarget target, string message) => new(target, null, null, null, null, null, message);
    private static void Report(IProgress<BulkProgress>? progress, BulkTarget target, string stage, string message, int percent)
    { try { progress?.Report(new BulkProgress(target.Id, stage, message, percent)); } catch (Exception) { /* Observers never govern a host transaction. */ } }
    private sealed class InlineProgress(Action<OperationProgress> report) : IProgress<OperationProgress>
    { public void Report(OperationProgress value) => report(value); }

    private static List<string[]> ReadCsv(string csv)
    {
        var rows = new List<string[]>();
        var row = new List<string>();
        var cell = new StringBuilder();
        var quoted = false;
        var closed = false;
        for (var index = 0; index <= csv.Length; index++)
        {
            var character = index < csv.Length ? csv[index] : '\n';
            if (quoted)
            {
                if (character == '"')
                {
                    if (index + 1 < csv.Length && csv[index + 1] == '"') { cell.Append('"'); index++; }
                    else { quoted = false; closed = true; }
                }
                else { if (index == csv.Length) throw new ArgumentException("Unclosed quoted CSV field."); cell.Append(character); }
                continue;
            }
            if (character == '"' && cell.Length == 0 && !closed) { quoted = true; continue; }
            if (character is ',' or '\r' or '\n')
            {
                row.Add(cell.ToString()); cell.Clear(); closed = false;
                if (row.Count > 6) throw new ArgumentException("CSV has too many columns.");
                if (character != ',')
                {
                    if (row.Any(x => x.Length != 0)) rows.Add(row.ToArray());
                    row.Clear();
                    if (character == '\r' && index + 1 < csv.Length && csv[index + 1] == '\n') index++;
                    if (rows.Count > MaximumTargets + 1) throw new ArgumentException("CSV has too many rows.");
                }
                continue;
            }
            if (closed || character == '"' || character == '\0') throw new ArgumentException("Malformed CSV field.");
            cell.Append(character);
        }
        return rows;
    }
}
