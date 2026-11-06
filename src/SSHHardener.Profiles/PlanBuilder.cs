using System.Globalization;
using SSHHardener.Core;

namespace SSHHardener.Profiles;

public sealed class PlanBuilder : IPlanBuilder
{
    public HardeningPlan Build(ServerAudit audit, ConnectionOptions connection, HardeningOptions options)
    {
        InputValidators.Validate(options);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(connection);
        if (!audit.HasRoot) throw new InvalidOperationException("Verified root or sudo access is required.");
        if (audit.InitSystem != "systemd") throw new NotSupportedException("Applying changes requires systemd. This server supports audit only.");
        if (audit.SocketActivated) throw new NotSupportedException("SSH socket activation requires a dedicated implementation. This server supports audit only.");
        if (audit.Firewall is not ("ufw" or "firewalld" or "none")) throw new NotSupportedException("Only an unambiguous ufw/firewalld setup or no active firewall is supported.");
        var supported = audit.OsId switch
        {
            "debian" => audit.OsVersion is "12" or "13",
            "ubuntu" => audit.OsVersion is "22.04" or "24.04",
            "rocky" or "almalinux" => audit.OsVersion.Split('.')[0] == "9",
            _ => false
        };
        if (!supported) throw new NotSupportedException("Changes are limited to Debian 12/13, Ubuntu 22.04/24.04 and Rocky/AlmaLinux 9. Other systems support audit only.");
        if (connection.Port is < 1 or > 65535 || string.IsNullOrWhiteSpace(connection.Host)) throw new ArgumentException("Invalid original endpoint.");
        if (options.CreateUser && !options.GrantSudo) throw new ArgumentException("The recovery administrator must have verified sudo. Create the account with explicit NOPASSWD permission.");
        if (options.CloseOldPort && options.NewPort == connection.Port) throw new ArgumentException("The old and new ports must differ when closing the old port.");
        if (string.IsNullOrWhiteSpace(audit.AdminAddress)) throw new InvalidOperationException("The server-visible administrator address was not detected. Reconnect and audit again.");
        InputValidators.ValidateAddress(audit.AdminAddress);
        if (audit.ServiceName is not ("ssh" or "sshd")) throw new NotSupportedException("Unknown SSH service.");

        var id = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N")[..12];
        var values = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["ID"] = id, ["USER"] = options.Username, ["PORT"] = options.NewPort.ToString(CultureInfo.InvariantCulture),
            ["OLDPORT"] = connection.Port.ToString(CultureInfo.InvariantCulture), ["SERVICE"] = audit.ServiceName,
            ["FIREWALL"] = audit.Firewall, ["SELINUX"] = audit.Selinux, ["MINUTES"] = options.RollbackMinutes.ToString(CultureInfo.InvariantCulture),
            ["CREATE"] = options.CreateUser ? "yes" : "no", ["SUDO"] = options.GrantSudo ? "yes" : "no",
            ["KEY"] = options.PublicKey.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)[0] + " " + options.PublicKey.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)[1],
            ["ADMINADDR"] = audit.AdminAddress, ["PASSWORD"] = options.DisablePasswordAuthentication ? "no" : "preserve",
            ["ROOTLOGIN"] = options.PermitRootLogin, ["FORWARDING"] = options.DisableForwarding ? "no" : "preserve",
            ["CLOSEOLD"] = options.CloseOldPort ? "yes" : "no", ["FAIL2BAN"] = options.ConfigureFail2Ban ? "yes" : "no",
            ["RETRIES"] = options.MaxRetry.ToString(CultureInfo.InvariantCulture), ["BANTIME"] = options.BanSeconds.ToString(CultureInfo.InvariantCulture),
            ["FINDTIME"] = options.FindTimeSeconds.ToString(CultureInfo.InvariantCulture),
            ["MAXAUTHTRIES"] = options.MaxAuthTries.ToString(CultureInfo.InvariantCulture),
            ["PACKAGE_MANAGER"] = audit.OsId is "debian" or "ubuntu" ? "apt" : "unsupported",
            ["IGNORE"] = string.Join(" ", new[] { "127.0.0.1/8", "::1", audit.AdminAddress }.Concat(options.IgnoreAddresses).Distinct(StringComparer.Ordinal))
        };
        string Expand(string text)
        {
            foreach (var (key, value) in values) text = text.Replace("@@" + key + "@@", Shell.Quote(value), StringComparison.Ordinal);
            return text;
        }
        var rollback = Expand(Scripts.Header + Scripts.RollbackBody);
        var arm = Expand(Scripts.Header + Scripts.ArmBody).Replace("@@ROLLBACK_BODY@@", rollback, StringComparison.Ordinal);
        var steps = new List<PlannedStep>
        {
            new PlannedStep("preflight", "Validate server capabilities and configuration without changing the system", Expand(Scripts.Header + Scripts.PreflightBody), "# Read-only; no rollback required."),
            new PlannedStep("arm-rollback", "Back up SSH configuration and install a persistent recovery timer and boot recovery", arm, rollback)
        };
        if (options.ConfigureFail2Ban)
            steps.Add(new PlannedStep("configure-fail2ban", "Install missing Fail2ban dependencies and verify the managed SSH jail and administrator whitelist", Expand(Scripts.Header + Scripts.ConfigureFail2BanBody), rollback));
        steps.AddRange(new[]
        {
            new PlannedStep("provision", "Install the administrator public key and explicitly requested sudo permission", Expand(Scripts.Header + Scripts.ProvisionBody), rollback),
            new PlannedStep("open-port", "Open only the new TCP port in the existing firewall and SELinux policy", Expand(Scripts.Header + Scripts.OpenPortBody), rollback),
            new PlannedStep("configure-dual-port", "Keep both SSH ports and apply the requested authentication policy", Expand(Scripts.Header + Scripts.ConfigFunctions + "\nconfigure dual\n"), rollback),
            new PlannedStep("configure-final", "After a fresh key and sudo login, apply the final listeners and optional old-port rejection", Expand(Scripts.Header + Scripts.ConfigFunctions + Scripts.FinalBody), rollback),
            new PlannedStep("commit", "After another fresh key and sudo login, atomically mark the transaction committed", Expand(Scripts.Header + Scripts.CommitBody), rollback)
        });
        var warnings = audit.Warnings.Concat(new[]
        {
            "Experimental release: supported combinations still require VM acceptance tests before use on a production server.",
            "Keep the provider console or rescue access available. Cloud security groups and NAT port mappings are not managed.",
            "Recovery requires a functioning disk, systemd and root-owned recovery files. Installed packages and dependencies are never removed by rollback.",
            "Rollback removes the application key and sudo grant from a newly created account, but preserves the account and its files to avoid deleting user data.",
            "A newly created administrator uses explicitly requested NOPASSWD sudo; password-based sudo provisioning is not implemented.",
            "Match blocks, nonstandard includes, explicit ListenAddress and SSH command-line overrides block changes.",
            "Firewall changes are individual rules; an inactive firewall is never enabled automatically."
        }).ToList();
        if (options.BanSeconds == -1 && options.ConfigureFail2Ban) warnings.Add("Permanent bans require explicit review. This release has not certified restoration across all fail2ban versions.");
        if (options.ConfigureFail2Ban)
        {
            warnings.Add("Missing Fail2ban, Python systemd bindings and iptables are installed automatically on Debian/Ubuntu from configured repositories. Other distributions require preinstalled dependencies.");
            warnings.Add("Fail2ban counts matching failed-authentication events across connections; MaxAuthTries is a separate limit within one SSH connection. The server-visible administrator IP is excluded from bans.");
            warnings.Add("SSH LogLevel VERBOSE is enabled with Fail2ban so individual failed-key authentications are recorded for the journal filter.");
            warnings.Add("Rollback restores the managed jail and service state but leaves downloaded packages installed. Interrupted package installation may require package-manager repair. Conflicting SSH jails are rejected before changes.");
        }
        return new HardeningPlan(id, audit, connection, options, steps, warnings);
    }
}
