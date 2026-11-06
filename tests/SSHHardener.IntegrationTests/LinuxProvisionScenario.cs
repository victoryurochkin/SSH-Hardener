using SSHHardener.Core;
using SSHHardener.Profiles;

internal static class LinuxProvisionScenario
{
    public static async Task VerifyAsync(IRemoteSession existing, IRemoteSessionFactory factory,
        ServerAudit audit, string privateKey, string publicKey, CancellationToken ct)
    {
        // Only called against this project's disposable Docker fixtures. The service probe is
        // mocked; useradd/runuser/permissions/sudoers/authorized_keys and recovery are real.
        var plan = new PlanBuilder().Build(audit with { InitSystem = "systemd", SocketActivated = false, Firewall = "none" },
            existing.Options, new HardeningOptions
            {
                Username = "integrationadmin", PublicKey = publicKey, PrivateKeyPath = privateKey,
                GrantSudo = true, NoPasswordSudo = true, CreateUser = true
            });
        var transaction = "/var/lib/ssh-hardener/transactions/" + plan.TransactionId;
        var scaffold = """
            set -eu
            install -d -m 0700 /var/lib/ssh-hardener /var/lib/ssh-hardener/transactions /tmp/sshhardener-fixture-bin
            printf '#!/bin/sh\nexit 0\n' > /tmp/sshhardener-fixture-bin/systemctl
            chmod 0700 /tmp/sshhardener-fixture-bin/systemctl
            """ + "\nmkdir -m 0700 " + Shell.Quote(transaction)
            + "\nprintf '%s\\n' " + Shell.Quote(plan.TransactionId) + " > /var/lib/ssh-hardener/active"
            + "\nprintf pending > " + Shell.Quote(transaction + "/state") + "\n";
        (await existing.ExecuteAsync(scaffold, true, ct)).EnsureSuccess("Prepare disposable script fixture");
        var prefix = "PATH=/tmp/sshhardener-fixture-bin:$PATH\nexport PATH\n";
        var provision = plan.Steps.Single(x => x.Id == "provision");
        (await existing.ExecuteAsync(prefix + provision.Script, true, ct)).EnsureSuccess("Run real provisioning script");
        var options = new ConnectionOptions(existing.Options.Host, existing.Options.Port, "integrationadmin",
            PrivateKeyPath: privateKey, Passphrase: "integration-key-passphrase");
        await using (var created = await factory.ConnectAsync(options,
            identity => Task.FromResult(identity.KeyBase64 == existing.Identity.KeyBase64), ct))
        {
            var identity = await created.ExecuteAsync("id -un", false, ct);
            var privilege = await created.ExecuteAsync("id -u", true, ct);
            if (identity.Output.Trim() != "integrationadmin" || privilege.Output.Trim() != "0" || privilege.ExitCode != 0)
                throw new InvalidOperationException("Generated user/key/sudo provisioning did not prove access.");
            var recoveryData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(provision.RollbackScript.Replace("\r\n", "\n")));
            var commitFixture = "set -eu\nprintf '%s' " + Shell.Quote(recoveryData) + " | base64 -d > " + Shell.Quote(transaction + "/rollback.sh")
                + "\nchmod 0700 " + Shell.Quote(transaction + "/rollback.sh")
                + "\ninstall -d -m 0755 /usr/local/bin\ncp /tmp/sshhardener-fixture-bin/systemctl /usr/local/bin/systemctl"
                + "\nprintf '%s\\n' 'Defaults:integrationadmin secure_path=\"/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"' > /etc/sudoers.d/89-integration-fixture-path\nchmod 0440 /etc/sudoers.d/89-integration-fixture-path\nvisudo -c >/dev/null"
                + "\nsha256sum /etc/ssh/sshd_config | awk '{print $1}' > " + Shell.Quote(transaction + "/main.sha256")
                + "\n(for include in /etc/ssh/sshd_config.d/*.conf; do [ -f \"$include\" ] || continue; sha256sum \"$include\"; done) > " + Shell.Quote(transaction + "/includes.sha256")
                + "\nprintf '%s\\n' " + Shell.Quote(plan.TransactionId) + " > /var/lib/ssh-hardener/last-committed"
                + "\nprintf committed > " + Shell.Quote(transaction + "/state")
                + "\nrm -f /var/lib/ssh-hardener/active\n";
            (await existing.ExecuteAsync(commitFixture, true, ct)).EnsureSuccess("Prepare committed fixture state");
            // The outcome must be read by the same privileged process: recovery revokes this
            // exact account's sudo grant and key, so a second elevation would fail.
            await new HardeningEngine(factory).RollbackAsync(created, plan.TransactionId, ct);
        }
        var state = await existing.ExecuteAsync("cat " + Shell.Quote(transaction + "/state")
            + "; test ! -e /etc/sudoers.d/90-sshhardener-integrationadmin; getent passwd integrationadmin >/dev/null", true, ct);
        if (state.ExitCode != 0 || state.Output.Trim() != "rolled-back")
            throw new InvalidOperationException("Recovery did not confirm state, remove sudo grant and preserve user data.");
        var rejected = false;
        try
        {
            await using var unexpected = await factory.ConnectAsync(options,
                identity => Task.FromResult(identity.KeyBase64 == existing.Identity.KeyBase64), ct);
        }
        catch (Renci.SshNet.Common.SshAuthenticationException) { rejected = true; }
        if (!rejected) throw new InvalidOperationException("Recovered user still accepts the transaction key.");
    }
}
