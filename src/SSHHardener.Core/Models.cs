namespace SSHHardener.Core;

public sealed record ConnectionOptions(string Host, int Port, string Username,
    string? Password = null, string? PrivateKeyPath = null, string? Passphrase = null,
    string? SudoPassword = null);
public sealed record HostIdentity(string Host, int Port, string Algorithm, string Fingerprint, string KeyBase64, bool IsKnown = false);
public sealed record CommandResult(int ExitCode, string Output, string Error)
{
    public void EnsureSuccess(string operation)
    {
        if (ExitCode != 0) throw new InvalidOperationException($"{operation}: exit {ExitCode}. {Error}");
    }
}
public interface IRemoteSession : IAsyncDisposable
{
    ConnectionOptions Options { get; }
    HostIdentity Identity { get; }
    Task<CommandResult> ExecuteAsync(string script, bool privileged, CancellationToken cancellationToken);
}
public interface IRemoteSessionFactory
{
    Task<IRemoteSession> ConnectAsync(ConnectionOptions options,
        Func<HostIdentity, Task<bool>> trustHost, CancellationToken cancellationToken);
}
public sealed record ServerAudit
{
    public string OsId { get; init; } = "unknown";
    public string OsVersion { get; init; } = "unknown";
    public string Description { get; init; } = "";
    public string OpenSshVersion { get; init; } = "";
    public string InitSystem { get; init; } = "unknown";
    public string Firewall { get; init; } = "unknown";
    public string AdminAddress { get; init; } = "";
    public string Selinux { get; init; } = "unknown";
    public string EffectiveConfig { get; init; } = "";
    public string RawReport { get; init; } = "";
    public bool HasRoot { get; init; }
    public bool SocketActivated { get; init; }
    public string ServiceName { get; init; } = "sshd";
    public IReadOnlyList<string> Warnings { get; init; } = [];
}
public sealed record HardeningOptions
{
    public int NewPort { get; init; } = 22022;
    public string Username { get; init; } = "sshadmin";
    public string PublicKey { get; init; } = "";
    public string PrivateKeyPath { get; init; } = "";
    public string? KeyPassphrase { get; init; }
    public bool CreateUser { get; init; } = true;
    public bool GrantSudo { get; init; }
    public bool NoPasswordSudo { get; init; }
    public string? NewUserSudoPassword { get; init; }
    public bool DisablePasswordAuthentication { get; init; } = true;
    public string PermitRootLogin { get; init; } = "prohibit-password";
    public bool CloseOldPort { get; init; }
    public bool DisableForwarding { get; init; }
    public bool ConfigureFail2Ban { get; init; }
    public int MaxRetry { get; init; } = 3;
    public int BanSeconds { get; init; } = 3600;
    public string[] IgnoreAddresses { get; init; } = [];
    public int RollbackMinutes { get; init; } = 10;
}
public sealed record PlannedStep(string Id, string Description, string Script, string RollbackScript);
public sealed record HardeningPlan(string TransactionId, ServerAudit Audit,
    ConnectionOptions OriginalConnection, HardeningOptions Options, IReadOnlyList<PlannedStep> Steps,
    IReadOnlyList<string> Warnings)
{
    public string Preview => string.Join("\n\n", Steps.Select(x => $"# {x.Id}: {x.Description}\n{x.Script}\n# ROLLBACK\n{x.RollbackScript}"));
}
public sealed record OperationProgress(string Step, string Message, int Percent);
public sealed record HardeningResult(string TransactionId, bool Committed, bool RolledBack,
    string Message, DateTimeOffset CompletedAt);
public interface IAuditService
{
    Task<ServerAudit> AuditAsync(IRemoteSession session, CancellationToken cancellationToken);
}
public interface IPlanBuilder
{
    HardeningPlan Build(ServerAudit audit, ConnectionOptions connection, HardeningOptions options);
}
public interface IHardeningEngine
{
    Task<HardeningResult> ApplyAsync(IRemoteSession original, HardeningPlan plan,
        IProgress<OperationProgress>? progress, CancellationToken cancellationToken);
    Task RollbackAsync(IRemoteSession session, string transactionId, CancellationToken cancellationToken);
}
