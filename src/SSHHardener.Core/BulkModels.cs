using System.Text.Json.Serialization;

namespace SSHHardener.Core;

/// <summary>CSV-safe target metadata. Credentials and enrollment secrets are supplied separately in memory.</summary>
public sealed record BulkTarget(string Id, string DisplayName, string Host, int Port, string Username,
    string? PrivateKeyPath = null)
{
    public override string ToString() => $"{DisplayName} · {Host}:{Port} · {Username}";
}

public sealed record BulkRunSettings(int MaxConcurrency = 1, bool StopOnFirstFailure = true);

/// <summary>Transient provider result. Neither credentials nor options are part of a serialized bulk object.</summary>
public sealed record BulkHostConfiguration(
    [property: JsonIgnore] ConnectionOptions Connection,
    [property: JsonIgnore] HardeningOptions Options)
{
    public override string ToString() => "Transient host configuration";
}

public sealed record BulkHostPreview(BulkTarget Target,
    [property: JsonIgnore] ServerAudit? Audit,
    [property: JsonIgnore] HardeningPlan? Plan,
    HostIdentity? Identity, string? SettingsFingerprint, string? PlanFingerprint, string? Error)
{
    public bool IsReady => Plan is not null && Audit is not null && Identity is not null && Error is null;
    public override string ToString() => $"{Target.DisplayName} · {(IsReady ? "Ready" : "Unavailable")}";
}

public sealed record BulkPreview(IReadOnlyList<BulkHostPreview> Hosts);
public enum BulkHostState { Skipped, Failed, Committed, RolledBack, Unconfirmed }

public sealed record BulkHostOutcome(BulkTarget Target, BulkHostState State, string? TransactionId,
    string Message, bool HistoryUpdated = false,
    [property: JsonIgnore] HardeningResult? Result = null)
{
    public override string ToString() => $"{Target.DisplayName} · {State}";
}

public sealed record BulkBatchResult(DateTimeOffset StartedAt, DateTimeOffset CompletedAt,
    IReadOnlyList<BulkHostOutcome> Hosts);
public sealed record BulkProgress(string TargetId, string Stage, string Message, int Percent);
