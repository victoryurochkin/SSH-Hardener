using System.Text.RegularExpressions;
using SSHHardener.Core;

namespace SSHHardener.Profiles;

public sealed partial class HardeningEngine(IRemoteSessionFactory sessionFactory) : IHardeningEngine
{
    private readonly IRemoteSessionFactory _sessionFactory = sessionFactory ?? throw new ArgumentNullException(nameof(sessionFactory));

    [GeneratedRegex(@"\A[0-9]{14}-[a-f0-9]{12}\z", RegexOptions.CultureInvariant)]
    private static partial Regex TransactionPattern();

    public async Task<HardeningResult> ApplyAsync(IRemoteSession original, HardeningPlan plan,
        IProgress<OperationProgress>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(plan);
        InputValidators.Validate(plan.Options);
        ValidateTransactionId(plan.TransactionId);
        if (!File.Exists(plan.Options.PrivateKeyPath)) throw new FileNotFoundException("The private key required for verification was not found.", plan.Options.PrivateKeyPath);
        if (!string.Equals(original.Options.Host, plan.OriginalConnection.Host, StringComparison.OrdinalIgnoreCase) ||
            original.Options.Port != plan.OriginalConnection.Port || original.Options.Username != plan.OriginalConnection.Username)
            throw new InvalidOperationException("The plan belongs to a different connection. Audit and preview this connection first.");
        if (!plan.Audit.HasRoot || plan.Audit.SocketActivated || plan.Audit.InitSystem != "systemd")
            throw new InvalidOperationException("The plan is not eligible for safe application.");

        var steps = plan.Steps.ToDictionary(x => x.Id, StringComparer.Ordinal);
        foreach (var required in new[] { "preflight", "arm-rollback", "provision", "open-port", "configure-dual-port", "configure-final", "commit" })
            if (!steps.ContainsKey(required)) throw new InvalidOperationException("The plan is incomplete.");
        var pin = original.Identity;
        var armAttempted = false;
        async Task Execute(IRemoteSession session, string id, int percent)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var step = steps[id];
            progress?.Report(new OperationProgress(id, step.Description, percent));
            if (id == "arm-rollback") armAttempted = true;
            var result = await session.ExecuteAsync(step.Script, true, cancellationToken);
            result.EnsureSuccess(step.Description);
        }

        try
        {
            await Execute(original, "preflight", 5);
            await Execute(original, "arm-rollback", 15);
            await Execute(original, "provision", 30);
            await Execute(original, "open-port", 45);
            await Execute(original, "configure-dual-port", 55);
            progress?.Report(new OperationProgress("verify-dual-port", "Verify a fresh key-only session and administrative privilege while the old listener remains available", 65));
            await using var replacement = await ConnectVerifiedAsync(plan, pin, cancellationToken);
            await Execute(replacement, "configure-final", 75);
            progress?.Report(new OperationProgress("verify-final", "Verify another fresh key-only session and sudo after the final configuration", 85));
            await using var final = await ConnectVerifiedAsync(plan, pin, cancellationToken);
            await Execute(final, "commit", 95);
            var state = await ReadStateAsync(final, plan.TransactionId, cancellationToken);
            if (state != "committed") throw new InvalidOperationException("The server did not confirm the committed transaction state.");
            progress?.Report(new OperationProgress("complete", "The server confirmed the final key login, administrative privilege and commit", 100));
            return new HardeningResult(plan.TransactionId, true, false,
                "Changes committed after two independent key-only logins and administrative privilege checks.", DateTimeOffset.UtcNow);
        }
        catch (Exception error)
        {
            var cancelled = error is OperationCanceledException;
            if (!armAttempted)
                return new HardeningResult(plan.TransactionId, false, false,
                    (cancelled ? "Cancelled before changes. " : "Preflight failed; no changes were applied. ") + error.Message, DateTimeOffset.UtcNow);

            try
            {
                progress?.Report(new OperationProgress("rollback", "Recover the transaction independently of cancellation; the server deadline remains armed until recovery succeeds", 90));
            }
            catch (Exception)
            {
                // A failed observer must not prevent recovery of an already armed transaction.
            }
            using var recoveryDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            string? state = null;
            try
            {
                await RecoverAsync(original, plan.TransactionId, false, recoveryDeadline.Token);
                state = await ReadStateAsync(original, plan.TransactionId, recoveryDeadline.Token);
            }
            catch (Exception) { /* The persistent server recovery remains responsible when the transport is unavailable. */ }

            if (state == "committed")
                return new HardeningResult(plan.TransactionId, true, false,
                    "The server reports that commit succeeded before the connection or acknowledgement was lost.", DateTimeOffset.UtcNow);
            if (state == "rolled-back")
                return new HardeningResult(plan.TransactionId, false, true,
                    (cancelled ? "Cancelled; " : "Verification failed; ") + "the server confirmed recovery. " + error.Message, DateTimeOffset.UtcNow);
            return new HardeningResult(plan.TransactionId, false, false,
                "Recovery is not confirmed. The persistent server timer/boot recovery remains scheduled if arming succeeded. Keep rescue-console access available and inspect /var/lib/ssh-hardener/transactions/" + plan.TransactionId + ". " + error.Message,
                DateTimeOffset.UtcNow);
        }
    }

    public async Task RollbackAsync(IRemoteSession session, string transactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ValidateTransactionId(transactionId);
        var directory = "/var/lib/ssh-hardener/transactions/" + transactionId;
        // The recovery may revoke the invoking account's sudo grant. Read the
        // outcome in this already privileged process rather than elevating again.
        var command = "set -eu\n/bin/sh " + Shell.Quote(directory + "/rollback.sh") + " manual\nprintf 'SSHARDENER_STATE=%s\\n' \"$(cat " + Shell.Quote(directory + "/state") + ")\"";
        var result = await session.ExecuteAsync(command, true, cancellationToken);
        result.EnsureSuccess("Manually recover SSHHardener transaction");
        if (!result.Output.Split('\n').Any(line => line.Trim() == "SSHARDENER_STATE=rolled-back"))
            throw new InvalidOperationException("The server did not confirm the manually recovered transaction state.");
    }

    private static async Task RecoverAsync(IRemoteSession session, string transactionId, bool manual, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ValidateTransactionId(transactionId);
        var path = "/var/lib/ssh-hardener/transactions/" + transactionId + "/rollback.sh";
        var result = await session.ExecuteAsync("/bin/sh " + Shell.Quote(path) + (manual ? " manual" : " auto"), true, cancellationToken);
        result.EnsureSuccess("Recover SSHHardener transaction");
    }

    private async Task<IRemoteSession> ConnectVerifiedAsync(HardeningPlan plan, HostIdentity pinnedIdentity, CancellationToken cancellationToken)
    {
        var options = new ConnectionOptions(plan.OriginalConnection.Host, plan.Options.NewPort, plan.Options.Username,
            PrivateKeyPath: plan.Options.PrivateKeyPath, Passphrase: plan.Options.KeyPassphrase);
        var session = await _sessionFactory.ConnectAsync(options,
            candidate => Task.FromResult(string.Equals(candidate.Host, pinnedIdentity.Host, StringComparison.OrdinalIgnoreCase) &&
                candidate.Port == plan.Options.NewPort && candidate.Algorithm == pinnedIdentity.Algorithm &&
                candidate.KeyBase64 == pinnedIdentity.KeyBase64 && candidate.Fingerprint == pinnedIdentity.Fingerprint), cancellationToken);
        try
        {
            var identity = await session.ExecuteAsync("id -un", false, cancellationToken);
            identity.EnsureSuccess("Verify login identity");
            if (identity.Output.Trim() != plan.Options.Username) throw new InvalidOperationException("The new connection did not prove the expected login identity.");
            // Always prove root privilege, including for an existing account when GrantSudo was unchecked.
            var privilege = await session.ExecuteAsync("id -u", true, cancellationToken);
            privilege.EnsureSuccess("Verify replacement administrator privilege");
            if (privilege.Output.Trim() != "0") throw new InvalidOperationException("The replacement administrator cannot execute a privileged command.");
            return session;
        }
        catch
        {
            await session.DisposeAsync();
            throw;
        }
    }

    private static async Task<string> ReadStateAsync(IRemoteSession session, string transactionId, CancellationToken cancellationToken)
    {
        var result = await session.ExecuteAsync("cat " + Shell.Quote("/var/lib/ssh-hardener/transactions/" + transactionId + "/state"), true, cancellationToken);
        result.EnsureSuccess("Read transaction outcome");
        return result.Output.Trim();
    }

    private static void ValidateTransactionId(string transactionId)
    {
        if (transactionId is null || !TransactionPattern().IsMatch(transactionId)) throw new ArgumentException("Invalid transaction identifier.");
    }
}
