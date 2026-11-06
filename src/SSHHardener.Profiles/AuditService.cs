using SSHHardener.Core;

namespace SSHHardener.Profiles;

public sealed class AuditService : IAuditService
{
    public async Task<ServerAudit> AuditAsync(IRemoteSession session, CancellationToken cancellationToken)
    {
        var warnings = new List<string>();
        var addressProbe = await session.ExecuteAsync("printf '%s' \"${SSH_CONNECTION:-${SSH_CLIENT:-}}\" | awk '{print $1}'", false, cancellationToken);
        var sourceAddress = addressProbe.ExitCode == 0 ? addressProbe.Output.Trim() : "";
        var root = false;
        try
        {
            var probe = await session.ExecuteAsync("id -u", true, cancellationToken);
            root = probe.ExitCode == 0 && probe.Output.Trim() == "0";
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { warnings.Add("Root/sudo could not be verified. Audit is read-only; applying changes is disabled."); }

        var result = await session.ExecuteAsync(AuditScript, root, cancellationToken);
        result.EnsureSuccess("Read server audit");
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in result.Output.Split('\n'))
        {
            if (!line.StartsWith("SSHARDENER_", StringComparison.Ordinal)) continue;
            var separator = line.IndexOf('=');
            if (separator > 0) fields[line["SSHARDENER_".Length..separator]] = line[(separator + 1)..].Trim();
        }
        string Get(string key, string fallback = "unknown") => fields.GetValueOrDefault(key, fallback);
        var effective = Between(result.Output, "SSHARDENER_CONFIG_BEGIN\n", "SSHARDENER_CONFIG_END");
        if (!root) warnings.Add("No verified administrative privileges; privileged audit fields may be unavailable.");
        if (Get("SOCKET") == "yes") warnings.Add("Socket activation is detected. Applying changes is disabled in this release.");
        if (Get("FIREWALL") is not ("ufw" or "firewalld" or "none")) warnings.Add("The firewall topology is unsupported for changes.");
        if (Get("SELINUX") is "Enforcing" or "Permissive") warnings.Add("SELinux is active; a verified semanage port mapping is required.");
        warnings.Add("The address seen by the server may be a NAT, VPN or bastion address. Confirm whitelist entries.");
        return new ServerAudit
        {
            OsId = Get("OSID"), OsVersion = Get("OSVERSION"), Description = Get("DESCRIPTION", ""),
            OpenSshVersion = Get("OPENSSH", ""), InitSystem = Get("INIT"), Firewall = Get("FIREWALL"),
            AdminAddress = sourceAddress, Selinux = Get("SELINUX"), EffectiveConfig = effective,
            RawReport = result.Output, HasRoot = root, SocketActivated = Get("SOCKET") == "yes",
            ServiceName = Get("SERVICE", "sshd"), Warnings = warnings
        };
    }

    private static string Between(string value, string start, string end)
    {
        var a = value.IndexOf(start, StringComparison.Ordinal);
        if (a < 0) return "";
        a += start.Length;
        var b = value.IndexOf(end, a, StringComparison.Ordinal);
        return b < 0 ? "" : value[a..b].Trim();
    }

    internal const string AuditScript = """
        set -eu
        export LC_ALL=C
        osfield() { awk -F= -v key="$1" '$1==key {v=substr($0,index($0,"=")+1);gsub(/^"|"$/,"",v);print v;exit}' /etc/os-release 2>/dev/null || true; }
        printf 'SSHARDENER_OSID=%s\n' "$(osfield ID)"
        printf 'SSHARDENER_OSVERSION=%s\n' "$(osfield VERSION_ID)"
        printf 'SSHARDENER_DESCRIPTION=%s\n' "$(osfield PRETTY_NAME)"
        printf 'SSHARDENER_OPENSSH=%s\n' "$(/usr/sbin/sshd -V 2>&1 || ssh -V 2>&1 || true)"
        init=unknown
        [ ! -d /run/systemd/system ] || init=systemd
        [ ! -d /run/openrc ] || init=OpenRC
        printf 'SSHARDENER_INIT=%s\n' "$init"
        service=sshd
        socket=no
        if [ "$init" = systemd ]; then
          if systemctl cat ssh.service >/dev/null 2>&1; then service=ssh; fi
          for unit in ssh.socket sshd.socket; do
            if systemctl is-active --quiet "$unit" || systemctl is-enabled --quiet "$unit" 2>/dev/null; then socket=yes; fi
          done
        fi
        printf 'SSHARDENER_SERVICE=%s\nSSHARDENER_SOCKET=%s\n' "$service" "$socket"
        address=$(printf '%s' "${SSH_CONNECTION:-${SSH_CLIENT:-}}" | awk '{print $1}')
        printf 'SSHARDENER_ADDRESS=%s\n' "$address"
        selinux=Disabled
        if command -v getenforce >/dev/null 2>&1; then selinux=$(getenforce); fi
        printf 'SSHARDENER_SELINUX=%s\n' "$selinux"
        firewall=none
        if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then firewall=ufw; fi
        if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
          if [ "$firewall" = ufw ]; then firewall=mixed; else firewall=firewalld; fi
        fi
        if [ "$firewall" = none ]; then
          if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q '[^[:space:]]'; then firewall=nftables; fi
          if command -v iptables-save >/dev/null 2>&1 && iptables-save 2>/dev/null | grep -Eq '^-A |^:[^ ]+ DROP'; then firewall=iptables; fi
          if command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save 2>/dev/null | grep -Eq '^-A |^:[^ ]+ DROP'; then firewall=iptables; fi
        fi
        printf 'SSHARDENER_FIREWALL=%s\n' "$firewall"
        printf 'SSHARDENER_CONFIG_BEGIN\n'
        sshd=$(command -v sshd || true)
        [ -n "$sshd" ] || sshd=/usr/sbin/sshd
        "$sshd" -T 2>/dev/null || true
        printf 'SSHARDENER_CONFIG_END\n'
        printf '\n=== Uptime ===\n'; uptime || true
        printf '\n=== Listening TCP/UDP ports ===\n'; ss -tulpn 2>/dev/null || true
        printf '\n=== Users (no password hashes or key contents) ===\n'; getent passwd | awk -F: '{print $1 ":" $3 ":" $6 ":" $7}' || true
        printf '\n=== Administrative groups ===\n'; getent group sudo wheel docker 2>/dev/null || true
        printf '\n=== Firewall ===\n'
        case "$firewall" in
          ufw) ufw status verbose || true;;
          firewalld) firewall-cmd --get-active-zones || true; firewall-cmd --list-all-zones || true;;
          nftables) nft list ruleset || true;;
          iptables) iptables-save || true; ip6tables-save || true;;
        esac
        printf '\n=== Fail2ban ===\n'; if command -v fail2ban-client >/dev/null 2>&1; then fail2ban-client status 2>/dev/null || true; else printf 'not installed\n'; fi
        printf '\n=== AppArmor ===\n'; if command -v aa-status >/dev/null 2>&1; then aa-status 2>/dev/null || true; fi
        printf '\n=== Failed authentication events over 24 hours (best effort) ===\n'
        if command -v journalctl >/dev/null 2>&1; then journalctl --since '24 hours ago' -u "$service" --no-pager -o cat 2>/dev/null | awk '/Failed password|Failed publickey|authentication failure/ {n++} END {print n+0}'; fi
        """;
}
