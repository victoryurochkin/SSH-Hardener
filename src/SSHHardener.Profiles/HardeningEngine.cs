using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Text;
using SSHHardener.Core;

namespace SSHHardener.Profiles;

public sealed partial class HardeningEngine(IRemoteSessionFactory sessionFactory, ITargetAccessVerifier? targetVerifier = null) : IHardeningEngine
{
    private readonly IRemoteSessionFactory _sessionFactory = sessionFactory ?? throw new ArgumentNullException(nameof(sessionFactory));
    private readonly ITargetAccessVerifier? _targetVerifier = targetVerifier;

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
        var advanced = AccessPolicy.UsesAdvancedAccess(plan.Options);
        if (AccessPolicy.RequiresIndependentAdministrator(plan.Options) &&
            (plan.Options.Username == plan.OriginalConnection.Username ||
             string.IsNullOrWhiteSpace(plan.OriginalConnection.PrivateKeyPath) ||
             !File.Exists(plan.OriginalConnection.PrivateKeyPath) ||
             plan.OriginalConnection.Username == "root" && plan.Options.PermitRootLogin == "no"))
            throw new InvalidOperationException("A separate administrator with a usable private key must remain available for this account role.");
        if (advanced && (_targetVerifier is null || original is not IRemoteSensitiveSession))
            throw new InvalidOperationException("This transport cannot verify the requested account policy or supply protected credential input.");
        if (advanced && (!steps.ContainsKey("provision-access") || !steps.ContainsKey("configure-access")))
            throw new InvalidOperationException("The account-access provisioning steps are missing.");
        foreach (var required in new[] { "preflight", "arm-rollback", "provision", "open-port", "configure-dual-port", "configure-final", "commit" })
            if (!steps.ContainsKey(required)) throw new InvalidOperationException("The plan is incomplete.");
        if (plan.Options.ConfigureFail2Ban && !steps.ContainsKey("configure-fail2ban"))
            throw new InvalidOperationException("The Fail2ban installation and configuration step is missing from the plan.");
        var pin = original.Identity;
        var oneTimeCode = plan.Options.EnableTotp ? CreateTotpProvider(plan.Options.TotpSecret!)
            : plan.Options.VerificationOneTimeCodeProvider ?? plan.OriginalConnection.OneTimeCodeProvider;
        var armAttempted = false;
        async Task Execute(IRemoteSession session, string id, int percent)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var step = steps[id];
            progress?.Report(new OperationProgress(id, step.Description, percent));
            if (id == "arm-rollback") armAttempted = true;
            CommandResult result;
            if (step.SensitiveInput == SensitiveInputKind.AccessCredentials)
            {
                if (session is not IRemoteSensitiveSession sensitive) throw new InvalidOperationException("Protected credential input is unavailable.");
                var input = CreateAccessInput(plan.Options);
                try { result = await sensitive.ExecuteSensitiveAsync(step.Script, input, true, cancellationToken); }
                finally { CryptographicOperations.ZeroMemory(input); }
            }
            else result = await session.ExecuteAsync(step.Script, true, cancellationToken);
            result.EnsureSuccess(step.Description);
        }

        try
        {
            await Execute(original, "preflight", 5);
            if (plan.Options.EnableTotp)
            {
                var clock = await original.ExecuteAsync("date -u +%s", false, cancellationToken);
                if (clock.ExitCode != 0 || !long.TryParse(clock.Output.Trim(), out var epoch) ||
                    Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - (double)epoch) > 20)
                    throw new InvalidOperationException("Synchronize the Windows and server clocks before enabling time-based authentication.");
            }
            await Execute(original, "arm-rollback", 15);
            if (plan.Options.ConfigureFail2Ban) await Execute(original, "configure-fail2ban", 20);
            await Execute(original, "provision", 30);
            if (advanced)
            {
                await Execute(original, "provision-access", 35);
                await Execute(original, "configure-access", 40);
            }
            await Execute(original, "open-port", 45);
            await Execute(original, "configure-dual-port", 55);
            progress?.Report(new OperationProgress("verify-dual-port", "Verify a fresh key-only session and administrative privilege while the old listener remains available", 65));
            string state;
            if (advanced)
            {
                await VerifyTargetAsync(plan, pin, oneTimeCode, false, cancellationToken);
                await Execute(original, "configure-final", 75);
                progress?.Report(new OperationProgress("verify-final", "Verify the final target account and authentication policy in a fresh connection", 85));
                await VerifyTargetAsync(plan, pin, oneTimeCode, true, cancellationToken);
                if (plan.Options.EnableTotp)
                {
                    progress?.Report(new OperationProgress("verify-second-factor", "Verify a second fresh two-factor login with a distinct time-based code", 90));
                    await VerifyTargetAsync(plan, pin, oneTimeCode, true, cancellationToken);
                }
                var control = await original.ExecuteAsync("id -u", true, cancellationToken);
                control.EnsureSuccess("Verify the controlling administrator");
                if (control.Output.Trim() != "0") throw new InvalidOperationException("The controlling administrator lost root access.");
                if (AccessPolicy.RequiresIndependentAdministrator(plan.Options))
                {
                    progress?.Report(new OperationProgress("verify-control-access", "Verify a fresh controlling administrator login on the final port", 93));
                    await using var freshControl = await ConnectControlAsync(plan, pin, cancellationToken);
                    await Execute(freshControl, "commit", 95);
                    state = await ReadStateAsync(freshControl, plan.TransactionId, cancellationToken);
                }
                else
                {
                    await Execute(original, "commit", 95);
                    state = await ReadStateAsync(original, plan.TransactionId, cancellationToken);
                }
            }
            else
            {
                await using var replacement = await ConnectVerifiedAsync(plan, pin, cancellationToken);
                await Execute(replacement, "configure-final", 75);
                progress?.Report(new OperationProgress("verify-final", "Verify another fresh key-only session and sudo after the final configuration", 85));
                await using var final = await ConnectVerifiedAsync(plan, pin, cancellationToken);
                await Execute(final, "commit", 95);
                state = await ReadStateAsync(final, plan.TransactionId, cancellationToken);
            }
            if (state != "committed") throw new InvalidOperationException("The server did not confirm the committed transaction state.");
            progress?.Report(new OperationProgress("complete", "The server confirmed the final key login, administrative privilege and commit", 100));
            return new HardeningResult(plan.TransactionId, true, false,
                advanced ? "Changes committed after independent target-access checks and control-administrator verification."
                    : "Changes committed after two independent key-only logins and administrative privilege checks.", DateTimeOffset.UtcNow);
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

    private static byte[] CreateAccessInput(HardeningOptions options)
    {
        static string Encode(string? text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text ?? ""));
        return Encoding.UTF8.GetBytes("SSHARDENER_ACCESS_V1\n" + Encode(options.NewUserSudoPassword) + "\n" +
            Encode(options.EnableTotp ? options.TotpSecret : null) + "\n" +
            Encode(options.EnableTotp ? string.Join('\n', options.TotpRecoveryCodes) : null) + "\n");
    }

    private async Task<IRemoteSession> ConnectControlAsync(HardeningPlan plan, HostIdentity pin, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(plan.OriginalConnection.PrivateKeyPath))
            throw new InvalidOperationException("An independently verified administrator key is required.");
        var connection = plan.OriginalConnection with { Port = plan.Options.NewPort, Password = null };
        bool Matches(HostIdentity identity) => string.Equals(identity.Host, pin.Host, StringComparison.OrdinalIgnoreCase) &&
            identity.Port == connection.Port && identity.Algorithm == pin.Algorithm &&
            identity.Fingerprint == pin.Fingerprint && identity.KeyBase64 == pin.KeyBase64;
        var control = await _sessionFactory.ConnectAsync(connection, identity => Task.FromResult(Matches(identity)), ct);
        try
        {
            if (!Matches(control.Identity)) throw new InvalidOperationException("The controlling server identity was not proved.");
            var name = await control.ExecuteAsync("id -un", false, ct);
            var root = await control.ExecuteAsync("id -u", true, ct);
            if (name.ExitCode != 0 || name.Output.Trim() != connection.Username || root.ExitCode != 0 || root.Output.Trim() != "0")
                throw new InvalidOperationException("The independent administrator's final access was not proved.");
            return control;
        }
        catch { await control.DisposeAsync(); throw; }
    }

    private Task VerifyTargetAsync(HardeningPlan plan, HostIdentity pin,
        Func<CancellationToken, Task<string>>? codeProvider, bool final, CancellationToken ct)
    {
        var target = new ConnectionOptions(plan.OriginalConnection.Host, plan.Options.NewPort, plan.Options.Username,
            PrivateKeyPath: plan.Options.PrivateKeyPath, Passphrase: plan.Options.KeyPassphrase,
            SudoPassword: plan.Options.SudoMode == SudoPolicyMode.Password ? plan.Options.NewUserSudoPassword : plan.Options.VerificationSudoPassword)
            { OneTimeCodeProvider = codeProvider };
        return _targetVerifier!.VerifyAsync(target, pin,
            new TargetAccessExpectation(plan.Options.AccountAccess, AccessPolicy.EffectiveSudo(plan.Options),
                plan.Options.RestrictedSudoCommands, plan.Options.SftpReadOnly, final), ct);
    }

    private static Func<CancellationToken, Task<string>> CreateTotpProvider(string secret)
    {
        long previousCounter = -1;
        return async ct =>
        {
            var limit = DateTimeOffset.UtcNow.AddSeconds(65);
            while (DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30 <= previousCounter)
            {
                if (DateTimeOffset.UtcNow > limit) throw new InvalidOperationException("The client clock changed during two-factor verification.");
                await Task.Delay(250, ct).ConfigureAwait(false);
            }
            ct.ThrowIfCancellationRequested();
            var now = DateTimeOffset.UtcNow;
            previousCounter = now.ToUnixTimeSeconds() / 30;
            return TotpService.GenerateCode(secret, now);
        };
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
            PrivateKeyPath: plan.Options.PrivateKeyPath, Passphrase: plan.Options.KeyPassphrase,
            SudoPassword: plan.Options.VerificationSudoPassword ??
                (plan.Options.Username == plan.OriginalConnection.Username ? plan.OriginalConnection.SudoPassword ?? plan.OriginalConnection.Password : null))
            { OneTimeCodeProvider = plan.Options.VerificationOneTimeCodeProvider ?? plan.OriginalConnection.OneTimeCodeProvider };
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
