namespace SSHHardener.Profiles;

internal static partial class Scripts
{
    internal const string Fail2BanFunctions = """
        fail2ban_foreign_policy_check() {
          for directory in /etc/fail2ban /etc/fail2ban/jail.d /etc/fail2ban/action.d /etc/fail2ban/filter.d; do
            [ -e "$directory" ] || continue
            [ -d "$directory" ] && [ ! -L "$directory" ] && [ "$(stat -c %u "$directory")" = 0 ] || return 1
            permissions=$(stat -c %a "$directory") || return 1
            case "$permissions" in *[2367][0-7]|*[0-7][2367]) return 1;; esac
          done
          if command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client status sshd >/dev/null 2>&1; then
            printf 'A foreign sshd jail is active; review it before enabling SSHHardener protection.\n' >&2
            return 1
          fi
          for policy in /etc/fail2ban/jail.local /etc/fail2ban/jail.d/*.local /etc/fail2ban/jail.d/*.conf; do
            [ -e "$policy" ] || continue
            [ -f "$policy" ] && [ ! -L "$policy" ] || return 1
            [ "$(stat -c %u "$policy")" = 0 ] || return 1
            permissions=$(stat -c %a "$policy") || return 1
            case "$permissions" in *[2367][0-7]|*[0-7][2367]) return 1;; esac
            case "$policy" in
              /etc/fail2ban/jail.d/sshhardener-sshd.local)
                head -n 1 "$policy" | grep -qx '# SSHHardener managed fail2ban jail v1' || return 1
                [ "$(stat -c %u "$policy")" = 0 ] && [ "$(stat -c %a "$policy")" = 644 ] || return 1
                [ -f "$base/fail2ban-managed.sha256" ] && [ ! -L "$base/fail2ban-managed.sha256" ] || return 1
                [ "$(stat -c %u "$base/fail2ban-managed.sha256")" = 0 ] && [ "$(stat -c %a "$base/fail2ban-managed.sha256")" = 600 ] || return 1
                proof=$(cat "$base/fail2ban-managed.sha256")
                printf '%s\n' "$proof" | grep -Eq '^[a-f0-9]{64}$' || return 1
                digest=$(sha256sum "$policy") || return 1
                [ "${digest%% *}" = "$proof" ] || return 1
                continue;;
              /etc/fail2ban/jail.d/defaults-debian.conf)
                normalized=$(awk '!/^[[:space:]]*[#;]/ {gsub(/[[:space:]]/, "");if(length($0))print tolower($0)}' "$policy")
                [ "$normalized" = "$(printf '[sshd]\nenabled=true')" ] || return 1
                continue;;
            esac
            if grep -Eiq '^[[:space:]]*\[sshd\]|^[[:space:]]*filter[[:space:]]*=[[:space:]]*sshd([[:space:]\[]|$)' "$policy"; then
              printf 'A custom SSH Fail2ban policy requires manual review.\n' >&2
              return 1
            fi
          done
          if [ -f /etc/fail2ban/jail.conf ]; then
            [ ! -L /etc/fail2ban/jail.conf ] && [ "$(stat -c %u /etc/fail2ban/jail.conf)" = 0 ] || return 1
            permissions=$(stat -c %a /etc/fail2ban/jail.conf) || return 1
            case "$permissions" in *[2367][0-7]|*[0-7][2367]) return 1;; esac
            awk 'tolower($0)~/^[[:space:]]*\[/{section=tolower($0);gsub(/[[:space:]]/,"",section)} section=="[sshd]" && tolower($0)~/^[[:space:]]*enabled[[:space:]]*=[[:space:]]*(true|yes|1)([[:space:]#;]|$)/{exit 1}' /etc/fail2ban/jail.conf || return 1
          fi
        }
        fail2ban_remove_owned_mask() {
          [ -f "$tx/fail2ban.mask-intent" ] || return 0
          if [ -L /run/systemd/system/fail2ban.service ]; then
            [ "$(readlink /run/systemd/system/fail2ban.service)" = /dev/null ] || return 1
            rm -f /run/systemd/system/fail2ban.service || return 1
            systemctl daemon-reload || return 1
          elif [ -e /run/systemd/system/fail2ban.service ]; then return 1
          fi
        }
        restore_nftables_service_baseline() {
          [ -f "$tx/nftables.mask-intent" ] || return 0
          nft_was_active=$(cat "$tx/nftables.was-active") || return 1
          nft_was_enabled=$(cat "$tx/nftables.was-enabled") || return 1
          if [ "$nft_was_active" = no ] && systemctl is-active --quiet nftables.service; then
            printf 'nftables.service unexpectedly became active; it was not stopped because its stop action may flush unrelated firewall rules.\n' >&2
            return 1
          fi
          if [ "${1:-auto}" = boot ] && [ "$nft_was_active" = no ]; then systemctl --no-block stop nftables.service >/dev/null 2>&1 || return 1; fi
          if [ -L /run/systemd/system/nftables.service ]; then
            [ "$(readlink /run/systemd/system/nftables.service)" = /dev/null ] || return 1
            rm -f /run/systemd/system/nftables.service || return 1
            systemctl daemon-reload || return 1
          elif [ -e /run/systemd/system/nftables.service ]; then return 1
          fi
          nft_unit_exists=no
          if [ -f /lib/systemd/system/nftables.service ] || [ -f /usr/lib/systemd/system/nftables.service ]; then nft_unit_exists=yes; fi
          [ "$nft_unit_exists" = yes ] || return 0
          case "$nft_was_enabled" in
            enabled) systemctl enable nftables.service >/dev/null 2>&1;;
            enabled-runtime) systemctl enable --runtime nftables.service >/dev/null 2>&1;;
            disabled|not-found) systemctl disable nftables.service >/dev/null 2>&1;;
            static) :;;
            *) return 1;;
          esac
        }
        fail2ban_package_recovery_ready() {
          [ -f "$tx/fail2ban.install-intent" ] || return 0
          touch "$tx/fail2ban.package-cancelled" || return 1
          sync -f "$tx/fail2ban.package-cancelled" || return 1
          exec 8>"$tx/fail2ban.package.lock"
          if flock -n 8; then return 0; fi
          printf '%s\n' recovery-deferred > "$tx/state"
          sync -f "$tx/state" || true
          retry_unit="ssh-hardener-$id-package-retry-$(date +%s)"
          systemd-run --quiet --unit="$retry_unit" --on-active=20s --timer-property=AccuracySec=1s /bin/sh "$tx/rollback.sh" auto >/dev/null 2>&1 || true
          printf 'Package installation is still running; recovery is deferred. The owned service mask and protected configuration are retained.\n' >&2
          return 1
        }
        recover_fail2ban() {
          [ -f "$tx/fail2ban.baseline-ready" ] || return 0
          mode="$1"
          recovery_error=0
          jailfile=/etc/fail2ban/jail.d/sshhardener-sshd.local
          was_active=$(cat "$tx/fail2ban.was-active") || return 1
          was_enabled=$(cat "$tx/fail2ban.was-enabled") || return 1
          if [ -f "$tx/fail2ban.jail-intent" ]; then
            restore_jail=yes
            if [ -e "$jailfile" ]; then
              if [ -L "$jailfile" ]; then return 1
              elif same_file_contents "$tx/fail2ban.jail.applied" "$jailfile"; then :
              elif [ -f "$tx/fail2ban.jail.original" ] && same_file_contents "$tx/fail2ban.jail.original" "$jailfile"; then restore_jail=no
              else
                printf 'The managed Fail2ban configuration changed concurrently; it was preserved for manual review.\n' >&2
                return 1
              fi
            fi
            if [ "$restore_jail" = no ]; then :
            elif [ -f "$tx/fail2ban.jail.original" ]; then
              install -o root -g root -m 0644 "$tx/fail2ban.jail.original" "$jailfile" || return 1
            else rm -f "$jailfile" || return 1
            fi
          fi
          if [ -f "$tx/fail2ban.owner-intent" ]; then
            restore_proof=yes
            if [ -L "$base/fail2ban-managed.sha256" ]; then return 1
            elif [ -f "$base/fail2ban-managed.sha256" ]; then
              if same_file_contents "$tx/fail2ban.owner.applied" "$base/fail2ban-managed.sha256"; then :
              elif [ -f "$tx/fail2ban.owner.original" ] && same_file_contents "$tx/fail2ban.owner.original" "$base/fail2ban-managed.sha256"; then restore_proof=no
              else return 1; fi
            fi
            if [ "$restore_proof" = no ]; then :
            elif [ -f "$tx/fail2ban.owner.original" ]; then install -o root -g root -m 0600 "$tx/fail2ban.owner.original" "$base/fail2ban-managed.sha256" || return 1
            else rm -f "$base/fail2ban-managed.sha256" || return 1; fi
          fi
          unit_exists=no
          if [ -f /lib/systemd/system/fail2ban.service ] || [ -f /usr/lib/systemd/system/fail2ban.service ]; then unit_exists=yes; fi
          if [ "$was_active" = no ] && [ "$unit_exists" = yes ]; then
            if [ "$mode" = boot ]; then systemctl --no-block stop fail2ban.service >/dev/null 2>&1 || recovery_error=1
            else systemctl stop fail2ban.service >/dev/null 2>&1 || recovery_error=1
            fi
          fi
          fail2ban_remove_owned_mask || recovery_error=1
          case "$was_enabled" in
            enabled) systemctl enable fail2ban.service >/dev/null 2>&1 || recovery_error=1;;
            enabled-runtime) systemctl enable --runtime fail2ban.service >/dev/null 2>&1 || recovery_error=1;;
            disabled|not-found) if [ "$unit_exists" = yes ]; then systemctl disable fail2ban.service >/dev/null 2>&1 || recovery_error=1; fi;;
            static) :;;
            *) recovery_error=1;;
          esac
          restore_nftables_service_baseline "$mode" || recovery_error=1
          if [ "$was_active" = yes ]; then
            if [ "$mode" = boot ]; then systemctl --no-block start fail2ban.service >/dev/null 2>&1 || recovery_error=1
            elif systemctl is-active --quiet fail2ban.service; then
              fail2ban-client -t >/dev/null 2>&1 && fail2ban-client reload >/dev/null 2>&1 || recovery_error=1
            else systemctl start fail2ban.service >/dev/null 2>&1 || recovery_error=1
            fi
          fi
          [ "$recovery_error" = 0 ]
        }

        """;

    internal const string ConfigureFail2BanBody = """
        guard
        [ "$use_fail2ban" = yes ] || exit 0
        fail2ban_foreign_policy_check || fail 'Existing Fail2ban SSH policy conflicts with the managed jail; no policy was overwritten.'
        for directory in /etc/fail2ban /etc/fail2ban/jail.d; do
          [ ! -L "$directory" ] || fail 'Unsafe Fail2ban configuration directory.'
          if [ -e "$directory" ]; then
            [ -d "$directory" ] && [ "$(stat -c %u "$directory")" = 0 ] || fail 'Unexpected Fail2ban directory owner.'
            case "$(stat -c %a "$directory")" in 700|750|755) :;; *) fail 'The Fail2ban configuration directory is writable by other accounts.';; esac
          else install -d -o root -g root -m 0755 "$directory"; fi
        done
        jailfile=/etc/fail2ban/jail.d/sshhardener-sshd.local
        [ ! -L "$jailfile" ] || fail 'Unsafe managed Fail2ban file.'
        installed=no
        if command -v fail2ban-client >/dev/null 2>&1; then installed=yes; fi
        printf '%s\n' "$installed" > "$tx/fail2ban.was-installed"
        if systemctl is-active --quiet fail2ban.service; then printf 'yes\n' > "$tx/fail2ban.was-active"; else printf 'no\n' > "$tx/fail2ban.was-active"; fi
        enabled=$(systemctl is-enabled fail2ban.service 2>/dev/null || true)
        [ -n "$enabled" ] || enabled=not-found
        case "$enabled" in enabled|enabled-runtime|disabled|not-found|static) :;; *) fail 'Unsupported Fail2ban service enablement state.';; esac
        printf '%s\n' "$enabled" > "$tx/fail2ban.was-enabled"
        if [ -f "$jailfile" ]; then cp -p "$jailfile" "$tx/fail2ban.jail.original"; fi
        [ ! -L "$base/fail2ban-managed.sha256" ] || fail 'Unsafe managed Fail2ban ownership proof.'
        if [ -e "$base/fail2ban-managed.sha256" ]; then
          [ -f "$base/fail2ban-managed.sha256" ] && [ "$(stat -c %u "$base/fail2ban-managed.sha256")" = 0 ] && [ "$(stat -c %a "$base/fail2ban-managed.sha256")" = 600 ] || fail 'Unexpected managed Fail2ban ownership proof.'
          cp -p "$base/fail2ban-managed.sha256" "$tx/fail2ban.owner.original"
        fi
        touch "$tx/fail2ban.baseline-ready"
        sync -f "$tx/fail2ban.baseline-ready"
        needs_packages=no
        if [ "$installed" = no ] || ! command -v iptables >/dev/null 2>&1 || ! command -v ip6tables >/dev/null 2>&1 || ! command -v nft >/dev/null 2>&1 || ! /usr/bin/python3 -c 'from systemd import journal' >/dev/null 2>&1; then needs_packages=yes; fi
        if [ "$needs_packages" = yes ]; then
          [ "$package_manager" = apt ] || fail 'Required Fail2ban dependencies are unavailable. This release does not enable repositories or install RPM packages automatically.'
          [ "$minutes" -ge 10 ] || fail 'Package installation requires a recovery deadline of at least 10 minutes.'
          [ ! -e /run/systemd/system/fail2ban.service ] && [ ! -L /run/systemd/system/fail2ban.service ] || fail 'A Fail2ban runtime mask already exists.'
          touch "$tx/fail2ban.mask-intent"
          sync -f "$tx/fail2ban.mask-intent"
          systemctl mask --runtime fail2ban.service >/dev/null
          [ -L /run/systemd/system/fail2ban.service ] && [ "$(readlink /run/systemd/system/fail2ban.service)" = /dev/null ] || fail 'The temporary Fail2ban activation mask could not be verified.'
          if systemctl is-active --quiet nftables.service; then printf 'yes\n' > "$tx/nftables.was-active"; else printf 'no\n' > "$tx/nftables.was-active"; fi
          nft_enabled=$(systemctl is-enabled nftables.service 2>/dev/null || true)
          [ -n "$nft_enabled" ] || nft_enabled=not-found
          printf '%s\n' "$nft_enabled" > "$tx/nftables.was-enabled"
          case "$nft_enabled" in
            masked|masked-runtime) :;;
            enabled|enabled-runtime|disabled|not-found|static)
              for unitfile in /run/systemd/system/nftables.service /etc/systemd/system/nftables.service; do [ ! -e "$unitfile" ] && [ ! -L "$unitfile" ] || fail 'A custom nftables unit requires manual review.'; done
              touch "$tx/nftables.mask-intent"
              sync -f "$tx/nftables.mask-intent"
              systemctl mask --runtime nftables.service >/dev/null
              [ -L /run/systemd/system/nftables.service ] && [ "$(readlink /run/systemd/system/nftables.service)" = /dev/null ] || fail 'The temporary nftables activation mask could not be verified.'
              ;;
            *) fail 'Unsupported nftables service enablement state.';;
          esac
        fi
        cat > "$tx/fail2ban.jail.applied" <<EOF
        # SSHHardener managed fail2ban jail v1
        # Transaction: $id
        [sshd]
        enabled = false
        [sshhardener-sshd]
        enabled = true
        filter = sshd[mode=normal,publickey=any]
        backend = systemd
        journalmatch = _SYSTEMD_UNIT=$service.service + _COMM=sshd + _COMM=sshd-session
        port = $port,$oldport
        protocol = tcp
        maxretry = $maxretry
        findtime = $findtime
        bantime = $bantime
        ignoreip = $ignore_addresses
        usedns = no
        action = iptables-multiport[name=sshhardener-sshd, port="$port,$oldport", protocol=tcp, chain=INPUT]
        EOF
        touch "$tx/fail2ban.jail-intent"
        sync -f "$tx/fail2ban.jail-intent"
        sync -f "$tx/fail2ban.jail.applied"
        candidate=$(mktemp /etc/fail2ban/jail.d/.sshhardener.XXXXXX)
        install -o root -g root -m 0644 "$tx/fail2ban.jail.applied" "$candidate"
        mv -f "$candidate" "$jailfile"
        sync -f "$jailfile"
        if [ "$needs_packages" = yes ]; then
          touch "$tx/fail2ban.install-intent"
          sync -f "$tx/fail2ban.install-intent"
          if (
            exec 9>&-
            exec 8>"$tx/fail2ban.package.lock"
            flock -n 8 || exit 1
            [ ! -e "$tx/fail2ban.package-cancelled" ] || exit 1
            printf 'running\n' > "$tx/fail2ban.package-state"
            sync -f "$tx/fail2ban.package-state"
            if timeout --signal=TERM --kill-after=10s 140s /bin/sh -c '
              export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
              apt-get -o DPkg::Lock::Timeout=30 -o Acquire::Retries=1 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update &&
              apt-get -y --no-remove --no-upgrade --no-install-recommends -o DPkg::Lock::Timeout=30 -o Dpkg::Options::=--force-confold install fail2ban python3-systemd iptables nftables
            ' > "$tx/fail2ban.packages.log" 2>&1; then
              printf 'completed\n' > "$tx/fail2ban.package-state"
            else printf 'failed\n' > "$tx/fail2ban.package-state"; exit 1
            fi
          ); then :; else fail 'Fail2ban package installation did not complete. Packages remain installed; interrupted dpkg may require administrator repair. See the root-only transaction package log.'; fi
          [ ! -e "$tx/fail2ban.package-cancelled" ] || fail 'Package installation was cancelled by server recovery.'
        fi
        command -v fail2ban-client >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1 && command -v ip6tables >/dev/null 2>&1 || fail 'Required Fail2ban commands are unavailable after installation.'
        /usr/bin/python3 -c 'from systemd import journal' || fail 'The systemd journal backend is unavailable.'
        iptables -w 5 -S >/dev/null || fail 'The server cannot manage its IPv4 packet filter.'
        ip6tables -w 5 -S >/dev/null || fail 'The server cannot manage its IPv6 packet filter.'
        fail2ban-client -t || fail 'The protected Fail2ban configuration is invalid.'
        restore_nftables_service_baseline auto || fail 'The nftables inspection dependency could not be returned to its previous service state.'
        fail2ban_remove_owned_mask || fail 'The temporary activation mask could not be removed safely.'
        if systemctl is-active --quiet fail2ban.service; then fail2ban-client reload || fail 'Fail2ban could not reload the managed jail.'
        else systemctl start fail2ban.service || fail 'Fail2ban could not start.'; fi
        systemctl enable fail2ban.service >/dev/null
        ready=no
        attempt=0
        while [ "$attempt" -le 10 ]; do
          if fail2ban-client status sshhardener-sshd >/dev/null 2>&1; then ready=yes; break; fi
          [ "$attempt" -lt 10 ] || break
          sleep 1; attempt=$((attempt + 1))
        done
        [ "$ready" = yes ] || fail 'The managed Fail2ban jail did not become ready.'
        [ "$(fail2ban-client get sshhardener-sshd maxretry)" = "$maxretry" ] || fail 'Fail2ban maxretry does not match the plan.'
        [ "$(fail2ban-client get sshhardener-sshd findtime)" = "$findtime" ] || fail 'Fail2ban findtime does not match the plan.'
        [ "$(fail2ban-client get sshhardener-sshd bantime)" = "$bantime" ] || fail 'Fail2ban bantime does not match the plan.'
        sha256sum "$jailfile" | awk '{print $1}' > "$tx/fail2ban.owner.applied"
        sync -f "$tx/fail2ban.owner.applied"
        touch "$tx/fail2ban.owner-intent"
        sync -f "$tx/fail2ban.owner-intent"
        proof_candidate=$(mktemp "$base/.fail2ban-proof.XXXXXX")
        install -o root -g root -m 0600 "$tx/fail2ban.owner.applied" "$proof_candidate"
        mv -f "$proof_candidate" "$base/fail2ban-managed.sha256"
        sync -f "$base/fail2ban-managed.sha256"
        printf 'Managed jail sshhardener-sshd is active: maxretry=%s findtime=%s bantime=%s. Installed packages are retained on rollback.\n' "$maxretry" "$findtime" "$bantime"
        """;
}
