using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SSHHardener.Core;

public enum OperationState
{
    Unknown,
    NotFound,
    Pending,
    RollingBack,
    RecoveryDeferred,
    RecoveryFailed,
    RolledBack,
    Committed
}

public sealed record TransactionStatus(OperationState State, bool IsLastCommitted);

/// <summary>Non-secret recovery metadata. This record intentionally excludes plans, audits and credentials.</summary>
public sealed partial record OperationRecord(string TransactionId, DateTimeOffset CreatedAt,
    string Host, int OriginalPort, string OriginalUsername, string? OriginalPrivateKeyPath,
    int NewPort, string NewUsername, string? NewPrivateKeyPath,
    string HostKeyAlgorithm, string HostKeyBase64, string HostKeyFingerprint,
    OperationState LastConfirmedState = OperationState.Unknown, DateTimeOffset? LastConfirmedAt = null,
    AccountAccess TargetAccess = AccountAccess.Shell, bool TargetRequiresTotp = false)
{
    [GeneratedRegex(@"\A[0-9]{14}-[a-f0-9]{12}\z", RegexOptions.CultureInvariant)]
    private static partial Regex TransactionPattern();

    [GeneratedRegex(@"\A[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?\z", RegexOptions.CultureInvariant)]
    private static partial Regex UsernamePattern();

    [GeneratedRegex(@"\A[a-zA-Z0-9@._+\-]{1,128}\z", RegexOptions.CultureInvariant)]
    private static partial Regex AlgorithmPattern();

    public static OperationRecord FromPlan(HardeningPlan plan, HostIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(identity);
        if (!string.Equals(plan.OriginalConnection.Host, identity.Host, StringComparison.OrdinalIgnoreCase) ||
            plan.OriginalConnection.Port != identity.Port)
            throw new ArgumentException("The server identity does not belong to the planned endpoint.");
        var record = new OperationRecord(plan.TransactionId, DateTimeOffset.UtcNow,
            plan.OriginalConnection.Host, plan.OriginalConnection.Port, plan.OriginalConnection.Username,
            plan.OriginalConnection.PrivateKeyPath, plan.Options.NewPort, plan.Options.Username,
            plan.Options.PrivateKeyPath, identity.Algorithm, identity.KeyBase64, identity.Fingerprint,
            TargetAccess: plan.Options.AccountAccess, TargetRequiresTotp: plan.Options.EnableTotp);
        record.Validate();
        return record;
    }

    public void Validate()
    {
        if (TransactionId is null || !TransactionPattern().IsMatch(TransactionId)) throw new ArgumentException("Invalid transaction identifier.");
        if (CreatedAt == default) throw new ArgumentException("An operation creation time is required.");
        if (!Enum.IsDefined(LastConfirmedState)) throw new ArgumentException("Invalid operation state.");
        if (!Enum.IsDefined(TargetAccess)) throw new ArgumentException("Invalid target account access.");
        if (Host is null || Host.Length is 0 or > 253 || Host.Any(char.IsControl) || Host != Host.Trim() ||
            (!IPAddress.TryParse(Host, out _) && Uri.CheckHostName(Host) == UriHostNameType.Unknown))
            throw new ArgumentException("Invalid operation endpoint.");
        if (OriginalPort is < 1 or > 65535 || NewPort is < 1 or > 65535) throw new ArgumentException("Invalid operation port.");
        if (OriginalUsername is null || !UsernamePattern().IsMatch(OriginalUsername) ||
            NewUsername is null || !UsernamePattern().IsMatch(NewUsername)) throw new ArgumentException("Invalid operation username.");
        ValidatePath(OriginalPrivateKeyPath); ValidatePath(NewPrivateKeyPath);
        if (HostKeyAlgorithm is null || !AlgorithmPattern().IsMatch(HostKeyAlgorithm) ||
            HostKeyBase64 is null || HostKeyBase64.Length is < 16 or > 5500)
            throw new ArgumentException("Invalid pinned server key.");
        byte[] key;
        try { key = Convert.FromBase64String(HostKeyBase64); }
        catch (FormatException error) { throw new ArgumentException("Invalid pinned server key encoding.", error); }
        if (key.Length is < 8 or > 4096 || Convert.ToBase64String(key) != HostKeyBase64)
            throw new ArgumentException("Invalid pinned server key size or encoding.");
        var length = BinaryPrimitives.ReadUInt32BigEndian(key.AsSpan(0, 4));
        if (length is < 1 or > 128 || length > key.Length - 4) throw new ArgumentException("Invalid pinned server key structure.");
        var wireAlgorithm = Encoding.ASCII.GetString(key, 4, (int)length);
        var expectedAlgorithm = HostKeyAlgorithm switch
        {
            "rsa-sha2-256" or "rsa-sha2-512" => "ssh-rsa",
            "rsa-sha2-256-cert-v01@openssh.com" or "rsa-sha2-512-cert-v01@openssh.com" => "ssh-rsa-cert-v01@openssh.com",
            _ => HostKeyAlgorithm
        };
        if (wireAlgorithm != expectedAlgorithm) throw new ArgumentException("Pinned key type does not match its wire data.");
        var expectedFingerprint = "SHA256:" + Convert.ToBase64String(SHA256.HashData(key)).TrimEnd('=');
        if (!string.Equals(expectedFingerprint, HostKeyFingerprint, StringComparison.Ordinal))
            throw new ArgumentException("Pinned server fingerprint does not match the key.");
    }

    public override string ToString() => $"{CreatedAt.ToLocalTime():yyyy-MM-dd HH:mm} · {Host}:{NewPort} · {TransactionId}";

    private static void ValidatePath(string? path)
    {
        if (path is not null && (path.Length is 0 or > 32767 || path.Any(char.IsControl)))
            throw new ArgumentException("Invalid saved private-key path.");
    }
}
