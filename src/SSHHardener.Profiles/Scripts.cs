namespace SSHHardener.Profiles;

internal static class Scripts
{
    internal const string Header = """
        set -eu
        export LC_ALL=C
        umask 077
        id=@@ID@@
        user=@@USER@@
        port=@@PORT@@
        oldport=@@OLDPORT@@
        service=@@SERVICE@@
        firewall=@@FIREWALL@@
        selinux=@@SELINUX@@
        create_user=@@CREATE@@
        grant_sudo=@@SUDO@@
        pubkey=@@KEY@@
        adminaddr=@@ADMINADDR@@
        password_policy=@@PASSWORD@@
        root_policy=@@ROOTLOGIN@@
        forwarding_policy=@@FORWARDING@@
        close_old=@@CLOSEOLD@@
        use_fail2ban=@@FAIL2BAN@@
        ignore_addresses=@@IGNORE@@
        maxretry=@@RETRIES@@
        bantime=@@BANTIME@@
        minutes=@@MINUTES@@
        base=/var/lib/ssh-hardener
        tx="$base/transactions/$id"
        timer="ssh-hardener-$id.timer"
        recovery="ssh-hardener-$id.service"
        boot="ssh-hardener-$id-boot.service"
        fail() { printf '%s\n' "$*" >&2; exit 1; }
        same_file_contents() {
          [ -f "$1" ] && [ -f "$2" ] || return 1
          first_digest=$(sha256sum "$1") || return 1
          second_digest=$(sha256sum "$2") || return 1
          [ "${first_digest%% *}" = "${second_digest%% *}" ]
        }
        ssh_include_manifest() {
          for include_file in /etc/ssh/sshd_config.d/*.conf; do
            [ -e "$include_file" ] || continue
            [ -f "$include_file" ] && [ ! -L "$include_file" ] || return 1
            sha256sum "$include_file" || return 1
          done
        }
        ufw_has_tuple() {
          awk -v action="$1" -v p="$2" '$1=="###" && $2=="tuple" && $4==action && ($5=="tcp" || $5=="any") && $6==p {found=1} END {exit !found}' /etc/ufw/user.rules /etc/ufw/user6.rules
        }
        ufw_delete_owned() {
          marker=$1
          ufw status numbered > "$tx/ufw-status" || return 1
          numbers=$(awk -v comment="$marker" '{s=$0;sub(/[[:space:]]+$/,"",s);if(substr(s,length(s)-length(comment)-1)=="# "comment){n=$0;sub(/^\[[[:space:]]*/,"",n);sub(/\].*/,"",n);if(n~/^[0-9]+$/)print n}}' "$tx/ufw-status" | sort -rn)
          for number in $numbers; do
            ufw status numbered > "$tx/ufw-status" || return 1
            awk -v number="$number" -v comment="$marker" '{s=$0;n=$0;sub(/^\[[[:space:]]*/,"",n);sub(/\].*/,"",n);sub(/[[:space:]]+$/,"",s);if(n==number && substr(s,length(s)-length(comment)-1)=="# "comment)found=1}END{exit !found}' "$tx/ufw-status" || return 1
            ufw --force delete "$number" || return 1
          done
        }
        guard() {
          [ "$(id -u)" = 0 ] || fail 'Root privilege is required.'
          [ ! -L "$base" ] && [ ! -L "$tx" ] || fail 'Unsafe transaction path.'
          exec 9>/run/ssh-hardener.lock
          flock -n 9 || fail 'Another hardening/recovery operation is active.'
          [ "$(cat "$base/active" 2>/dev/null)" = "$id" ] || fail 'Transaction ownership mismatch.'
          [ "$(cat "$tx/state" 2>/dev/null)" = pending ] || fail 'Transaction is no longer pending.'
          systemctl is-active --quiet "$timer" || fail 'Recovery timer is no longer active.'
        }

        """;

    internal const string PreflightBody = """
        [ "$(id -u)" = 0 ] || fail 'Root privilege is required.'
        [ -d /run/systemd/system ] || fail 'systemd is required.'
        [ -x /usr/sbin/sshd ] || fail 'Expected /usr/sbin/sshd is unavailable.'
        for cmd in flock install stat readlink sha256sum awk grep cp mv systemctl getent ss runuser sync; do command -v "$cmd" >/dev/null 2>&1 || fail "Missing required command: $cmd"; done
        for unit in ssh.socket sshd.socket; do
          if systemctl is-active --quiet "$unit" || systemctl is-enabled --quiet "$unit" 2>/dev/null; then fail 'SSH socket activation is unsupported.'; fi
        done
        systemctl is-active --quiet "$service.service" || fail 'SSH service is not active.'
        start=$(systemctl show "$service.service" -p ExecStart --value)
        printf '%s' "$start" | grep -Eq 'sshd([[:space:];]|$)' || fail 'Custom SSH service executable is unsupported.'
        if printf '%s' "$start" | grep -Eq -- '(^|[[:space:]])-[pfo]([[:space:]=]|[^[:space:]])'; then fail 'SSH service command-line overrides are unsupported.'; fi
        for envfile in /etc/default/ssh /etc/sysconfig/sshd; do
          if [ -f "$envfile" ]; then
            awk -F= '/^[[:space:]]*(SSHD_OPTS|OPTIONS)[[:space:]]*=/ {v=substr($0,index($0,"=")+1);gsub(/[[:space:]"\047]/,"",v);if(v!="")exit 1}' "$envfile" || fail 'Nonempty SSH service options are unsupported.'
          fi
        done
        [ -f /etc/ssh/sshd_config ] && [ ! -L /etc/ssh/sshd_config ] || fail 'Unsafe or missing sshd_config.'
        [ -w /etc/ssh/sshd_config ] && [ -w /etc/ssh ] || fail 'SSH configuration is not writable.'
        [ ! -L /etc/ssh/sshd_config.d ] || fail 'Symlinked SSH drop-in directory is unsupported.'
        for file in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
          [ -e "$file" ] || continue
          [ -f "$file" ] && [ ! -L "$file" ] || fail 'Unsafe SSH include file.'
          if grep -Eiq '^[[:space:]]*(Match|ListenAddress)[[:space:]]' "$file"; then fail 'Match blocks and explicit ListenAddress require manual handling.'; fi
          if [ "$file" = /etc/ssh/sshd_config ]; then
            awk 'tolower($1)=="include" {if(NF!=2 || $2!="/etc/ssh/sshd_config.d/*.conf")exit 1}' "$file" || fail 'Unsupported SSH Include topology.'
          else
            if grep -Eiq '^[[:space:]]*(Include|Port)[[:space:]]' "$file"; then fail 'Nested includes and Port in drop-ins are unsupported.'; fi
          fi
        done
        /usr/sbin/sshd -t || fail 'The existing SSH configuration is invalid.'
        /usr/sbin/sshd -T | grep -qx 'usepam yes' || fail 'This release requires UsePAM yes for verified key-only accounts.'
        existing_ports=$(/usr/sbin/sshd -T | awk '$1=="port"{print $2}' | sort -nu | tr '\n' ' ')
        [ "$existing_ports" = "$oldport " ] || fail 'Multiple original SSH listeners or a translated endpoint require manual handling.'
        if ss -H -ltn "sport = :$port" | grep -q .; then
          [ "$port" = "$oldport" ] || fail 'The requested TCP port is already in use.'
        fi
        if [ "$create_user" = yes ]; then
          if getent passwd "$user" >/dev/null; then fail 'The new username already exists. Select existing-user mode explicitly.'; fi
          command -v useradd >/dev/null 2>&1 || fail 'useradd is unavailable.'
          [ -x /bin/bash ] || fail '/bin/bash is unavailable.'
        else
          getent passwd "$user" >/dev/null || fail 'The existing user was not found.'
        fi
        if [ "$grant_sudo" = yes ]; then command -v visudo >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1 || fail 'sudo and visudo must already be installed.'; visudo -c >/dev/null || fail 'Existing sudoers is invalid.'; fi
        [ ! -L "$base" ] || fail 'Unsafe transaction directory.'
        if [ -d "$base" ]; then
          [ "$(stat -c %u "$base")" = 0 ] || fail 'Transaction directory must be owned by root.'
          [ "$(stat -c %a "$base")" = 700 ] || fail 'Transaction directory must have mode 0700.'
          [ ! -e "$base/active" ] || fail 'An unfinished transaction already exists. Recover it first.'
        fi
        live_firewall=none
        if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then live_firewall=ufw; fi
        if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then [ "$live_firewall" = none ] || fail 'Multiple firewall managers are active.'; live_firewall=firewalld; fi
        [ "$live_firewall" = "$firewall" ] || fail 'Firewall changed since audit.'
        if [ "$firewall" = none ]; then
          if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q '[^[:space:]]'; then fail 'Unmanaged nftables rules detected.'; fi
          for tool in iptables-save ip6tables-save; do
            if command -v "$tool" >/dev/null 2>&1 && "$tool" | grep -Eq '^-A |^:[^ ]+ DROP'; then fail 'Unmanaged iptables rules detected.'; fi
          done
        fi
        if [ "$firewall" = firewalld ]; then
          zones=$(firewall-cmd --get-active-zones | awk '/^[^[:space:]]/{print $1}')
          [ "$(printf '%s\n' "$zones" | grep -c .)" -le 1 ] || fail 'Multiple firewalld zones require manual handling.'
        fi
        if [ "$firewall" = ufw ]; then
          for file in /etc/ufw/user.rules /etc/ufw/user6.rules; do [ -f "$file" ] && [ ! -L "$file" ] || fail 'Unsupported UFW rule storage.'; done
        fi
        if [ "$selinux" = Enforcing ] || [ "$selinux" = Permissive ]; then command -v semanage >/dev/null 2>&1 && command -v restorecon >/dev/null 2>&1 || fail 'SELinux changes require preinstalled semanage and restorecon.'; fi
        if [ "$use_fail2ban" = yes ]; then
          command -v fail2ban-client >/dev/null 2>&1 || fail 'Fail2ban must already be installed.'
          fail2ban-client ping >/dev/null || fail 'Fail2ban must already be running.'
          fail2ban-client status | awk -F: '/Jail list/ {v=$2;gsub(/[[:space:]]/,"",v);if(v!="")exit 1}' || fail 'Existing fail2ban jails require manual policy and whitelist review.'
          [ ! -e /etc/fail2ban/jail.d/zz-sshhardener.local ] || fail 'A managed fail2ban jail already exists.'
          [ ! -L /etc/fail2ban/jail.d ] && [ -d /etc/fail2ban/jail.d ] || fail 'Unsafe fail2ban jail directory.'
        fi
        printf 'Read-only preflight passed.\n'
        """;

    internal const string ArmBody = """
        [ "$(id -u)" = 0 ] || fail 'Root privilege is required.'
        exec 9>/run/ssh-hardener.lock
        flock -n 9 || fail 'Another operation is active.'
        [ ! -L "$base" ] || fail 'Unsafe transaction path.'
        [ ! -L "$base/transactions" ] || fail 'Unsafe transaction parent.'
        install -d -o root -g root -m 0700 "$base" "$base/transactions"
        [ ! -e "$base/active" ] || fail 'An unfinished transaction exists.'
        mkdir -m 0700 "$tx"
        cp -p /etc/ssh/sshd_config "$tx/sshd_config.original"
        sha256sum /etc/ssh/sshd_config | awk '{print $1}' > "$tx/main.sha256"
        ssh_include_manifest > "$tx/includes.sha256"
        printf '%s\n' pending > "$tx/state"
        printf '%s\n' "$id" > "$base/active"
        cat > "$tx/rollback.sh" <<'SSHARDENER_ROLLBACK_SCRIPT'
        @@ROLLBACK_BODY@@
        SSHARDENER_ROLLBACK_SCRIPT
        chmod 0700 "$tx/rollback.sh"
        /bin/sh -n "$tx/rollback.sh"
        cat > "/etc/systemd/system/$recovery" <<EOF
        [Unit]
        Description=SSHHardener transaction recovery $id
        [Service]
        Type=oneshot
        ExecStart=/bin/sh $tx/rollback.sh
        TimeoutStartSec=300
        EOF
        cat > "/etc/systemd/system/$timer" <<EOF
        [Unit]
        Description=SSHHardener recovery deadline $id
        [Timer]
        OnActiveSec=${minutes}min
        AccuracySec=1s
        Unit=$recovery
        [Install]
        WantedBy=timers.target
        EOF
        cat > "/etc/systemd/system/$boot" <<EOF
        [Unit]
        Description=Recover unfinished SSHHardener transaction $id at boot
        After=local-fs.target firewalld.service ufw.service
        Before=ssh.service sshd.service fail2ban.service
        [Service]
        Type=oneshot
        ExecStart=/bin/sh $tx/rollback.sh boot
        TimeoutStartSec=300
        [Install]
        WantedBy=multi-user.target
        EOF
        systemctl daemon-reload
        systemctl enable "$boot" >/dev/null
        systemctl enable --now "$timer" >/dev/null
        systemctl is-enabled --quiet "$boot"
        systemctl is-active --quiet "$timer"
        sync -f "$tx/sshd_config.original"
        sync -f "$tx/rollback.sh"
        sync -f "$tx/state"
        sync -f "/etc/systemd/system/$recovery"
        sync -f "/etc/systemd/system/$timer"
        sync -f "/etc/systemd/system/$boot"
        sync -f "$base/active"
        printf 'Persistent recovery armed: %s\n' "$id"
        """;

    internal const string ProvisionBody = """
        guard
        if [ "$create_user" = yes ]; then
          useradd -m -s /bin/bash "$user"
          touch "$tx/user-created"
        fi
        entry=$(getent passwd "$user")
        home=$(printf '%s' "$entry" | cut -d: -f6)
        uid=$(printf '%s' "$entry" | cut -d: -f3)
        gid=$(printf '%s' "$entry" | cut -d: -f4)
        case "$home" in /home/*) ;; /root) [ "$user" = root ] || fail 'Unexpected root home.';; *) fail 'Only local homes under /home or /root are supported.';; esac
        printf '%s\n' "$home" > "$tx/home"
        printf '%s\n' "$uid" > "$tx/user.uid"
        touch "$tx/key-provision-intent"
        # All access to a user-owned path runs as that user. A concurrent symlink
        # replacement therefore cannot turn a root read/write into privilege escalation.
        runuser -u "$user" -- /bin/sh -s -- "$home" "$pubkey" "$id" > "$tx/key.metadata" <<'SSHARDENER_USER_KEY'
        set -eu
        umask 077
        home=$1; pubkey=$2; id=$3
        [ -d "$home" ] && [ "$(readlink -f "$home")" = "$home" ] || exit 1
        [ "$(stat -c %u "$home")" = "$(id -u)" ] || exit 1
        sshdir="$home/.ssh"
        [ ! -L "$sshdir" ] && [ ! -L "$sshdir/authorized_keys" ] || exit 1
        if [ -e "$sshdir" ]; then
          [ -d "$sshdir" ] && [ "$(stat -c %u "$sshdir")" = "$(id -u)" ] || exit 1
          printf 'ssh_mode=%s\n' "$(stat -c %a "$sshdir")"
        else printf 'ssh_created=yes\n'; mkdir -m 0700 "$sshdir"; fi
        chmod 0700 "$sshdir"
        auth="$sshdir/authorized_keys"
        if [ -e "$auth" ]; then
          [ -f "$auth" ] && [ "$(stat -c %u "$auth")" = "$(id -u)" ] || exit 1
          printf 'auth_mode=%s\n' "$(stat -c %a "$auth")"
        else printf 'auth_created=yes\n'; fi
        keydata=$(printf '%s' "$pubkey" | awk '{print $2}')
        if [ ! -f "$auth" ] || ! awk -v key="$keydata" '{for(i=1;i<=NF;i++)if($i==key)found=1}END{exit !found}' "$auth"; then
          tmp=$(mktemp "$sshdir/.sshhardener.XXXXXX")
          trap 'rm -f "$tmp"' EXIT HUP INT TERM
          [ ! -f "$auth" ] || cat "$auth" > "$tmp"
          printf '\n%s SSHHardener:%s\n' "$pubkey" "$id" >> "$tmp"
          chmod 0600 "$tmp"
          mv -f "$tmp" "$auth"
          trap - EXIT HUP INT TERM
        fi
        chmod 0600 "$auth"
        if command -v restorecon >/dev/null 2>&1; then restorecon -R "$sshdir"; fi
        SSHARDENER_USER_KEY
        sync -f "$tx/key.metadata"
        if [ "$grant_sudo" = yes ]; then
          file="/etc/sudoers.d/90-sshhardener-$user"
          [ ! -L "$file" ] || fail 'Unsafe sudoers file.'
          printf '%s ALL=(ALL:ALL) NOPASSWD: ALL\n' "$user" > "$tx/sudoers.new"
          visudo -cf "$tx/sudoers.new" >/dev/null
          if [ -e "$file" ]; then
            same_file_contents "$tx/sudoers.new" "$file" || fail 'A different sudo policy already exists for this user.'
          else
            touch "$tx/sudoers-added"
            install -o root -g root -m 0440 "$tx/sudoers.new" "$file"
          fi
          visudo -c >/dev/null
        fi
        printf 'Administrator public key installed.\n'
        """;

    internal const string OpenPortBody = """
        guard
        if [ "$selinux" = Enforcing ] || [ "$selinux" = Permissive ]; then
          if ! semanage port -l -n | awk -v p="$port" '$1=="ssh_port_t" && $2=="tcp" {gsub(/,/," ");for(i=3;i<=NF;i++){split($i,r,"-");if((r[2]=="" && p==r[1]) || (r[2]!="" && p>=r[1] && p<=r[2]))found=1}}END{exit !found}'; then
            touch "$tx/selinux-intent"
            sync -f "$tx/selinux-intent"
            semanage port -a -t ssh_port_t -p tcp "$port"
          fi
        fi
        case "$firewall" in
          ufw)
            if [ "$port" != "$oldport" ] && ! ufw_has_tuple allow "$port"; then
              touch "$tx/ufw-open-intent"
              sync -f "$tx/ufw-open-intent"
              ufw allow "$port/tcp" comment "SSHHardener:$id"
              ufw status | grep -Fq "# SSHHardener:$id" || fail 'UFW did not confirm ownership of the added rule.'
            fi
            ;;
          firewalld)
            zone=$(firewall-cmd --get-active-zones | awk '/^[^[:space:]]/{print $1}')
            [ -n "$zone" ] || zone=$(firewall-cmd --get-default-zone)
            case "$zone" in *[!a-zA-Z0-9_-]*|'') fail 'Unsafe firewalld zone.';; esac
            printf '%s\n' "$zone" > "$tx/firewalld.zone"
            if ! firewall-cmd --zone="$zone" --query-port="$port/tcp" >/dev/null; then
              touch "$tx/firewalld-open-runtime"
              sync -f "$tx/firewalld-open-runtime"
              firewall-cmd --zone="$zone" --add-port="$port/tcp"
            fi
            if ! firewall-cmd --permanent --zone="$zone" --query-port="$port/tcp" >/dev/null; then
              touch "$tx/firewalld-open-permanent"
              sync -f "$tx/firewalld-open-permanent"
              firewall-cmd --permanent --zone="$zone" --add-port="$port/tcp"
            fi
            ;;
          none) printf 'No firewall is active; no firewall is enabled.\n';;
        esac
        if [ "$use_fail2ban" = yes ]; then
          touch "$tx/fail2ban-added"
          sync -f "$tx/fail2ban-added"
          cat > /etc/fail2ban/jail.d/zz-sshhardener.local <<EOF
        [sshd]
        enabled = true
        filter = sshd
        port = $port,$oldport
        backend = systemd
        maxretry = $maxretry
        findtime = 600
        bantime = $bantime
        ignoreip = $ignore_addresses
        EOF
          fail2ban-client -t
          fail2ban-client reload
          fail2ban-client status sshd
        fi
        """;

    internal const string ConfigFunctions = """
        configure() {
          phase="$1"
          current=$(sha256sum /etc/ssh/sshd_config | awk '{print $1}')
          [ "$current" = "$(cat "$tx/main.sha256")" ] || fail 'SSH config changed concurrently. Recovery remains armed.'
          ssh_include_manifest > "$tx/includes.current"
          same_file_contents "$tx/includes.sha256" "$tx/includes.current" || fail 'SSH include files changed concurrently. Recovery remains armed.'
          candidate=$(mktemp /etc/ssh/.sshhardener.XXXXXX)
          printf '# SSHHardener managed transaction %s\nPort %s\n' "$id" "$port" > "$candidate"
          if [ "$phase" = dual ] || [ "$close_old" = no ]; then [ "$port" = "$oldport" ] || printf 'Port %s\n' "$oldport" >> "$candidate"; fi
          printf 'PubkeyAuthentication yes\n' >> "$candidate"
          if [ "$phase" = final ]; then
            printf 'PermitEmptyPasswords no\nPermitRootLogin %s\n' "$root_policy" >> "$candidate"
            if [ "$password_policy" = no ]; then printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' >> "$candidate"; fi
            if [ "$forwarding_policy" = no ]; then printf 'X11Forwarding no\nAllowAgentForwarding no\nAllowTcpForwarding no\n' >> "$candidate"; fi
          fi
          awk 'tolower($1)!="port" && $0 !~ /^# SSHHardener managed transaction / {print}' "$tx/sshd_config.original" >> "$candidate"
          chmod --reference=/etc/ssh/sshd_config "$candidate"
          chown --reference=/etc/ssh/sshd_config "$candidate"
          /usr/sbin/sshd -t -f "$candidate" || { rm -f "$candidate"; fail 'Candidate SSH configuration failed validation.'; }
          context="user=$user,addr=$adminaddr,host=$adminaddr,lport=$port"
          /usr/sbin/sshd -T -f "$candidate" -C "$context" > "$tx/effective-$phase"
          grep -qx 'pubkeyauthentication yes' "$tx/effective-$phase" || fail 'Public-key authentication is not effective.'
          if [ "$phase" = final ] && [ "$password_policy" = no ]; then
            grep -qx 'passwordauthentication no' "$tx/effective-$phase" && grep -qx 'kbdinteractiveauthentication no' "$tx/effective-$phase" || fail 'Password authentication remains effective.'
          fi
          ports=$(awk '$1=="port"{print $2}' "$tx/effective-$phase" | sort -nu | tr '\n' ' ')
          expected="$port "
          if [ "$phase" = dual ] || [ "$close_old" = no ]; then expected=$(printf '%s\n%s\n' "$port" "$oldport" | sort -nu | tr '\n' ' '); fi
          [ "$ports" = "$expected" ] || fail 'Effective SSH listener ports differ from the plan.'
          touch "$tx/main-changed"
          sync -f "$tx/main-changed"
          mv -f "$candidate" /etc/ssh/sshd_config
          sync -f /etc/ssh/sshd_config
          if command -v restorecon >/dev/null 2>&1; then restorecon /etc/ssh/sshd_config; fi
          sha256sum /etc/ssh/sshd_config | awk '{print $1}' > "$tx/main.sha256"
          /usr/sbin/sshd -t
          systemctl reload "$service.service"
          systemctl is-active --quiet "$service.service"
          ss -H -ltn "sport = :$port" | grep -q . || fail 'sshd did not begin listening on the new port.'
        }
        guard

        """;

    internal const string FinalBody = """
        configure final
        if [ "$close_old" = yes ]; then
          case "$firewall" in
            ufw)
              if ! ufw_has_tuple deny "$oldport"; then
                touch "$tx/ufw-old-deny-intent"
                sync -f "$tx/ufw-old-deny-intent"
                ufw insert 1 deny "$oldport/tcp" comment "SSHHardener-old:$id"
                ufw status | grep -Fq "# SSHHardener-old:$id" || fail 'UFW did not confirm ownership of the old-port deny rule.'
              fi
              ;;
            firewalld)
              zone=$(cat "$tx/firewalld.zone")
              rule="rule priority=\"-100\" port port=\"$oldport\" protocol=\"tcp\" reject"
              if ! firewall-cmd --zone="$zone" --query-rich-rule="$rule" >/dev/null; then
                touch "$tx/firewalld-deny-runtime"
                sync -f "$tx/firewalld-deny-runtime"
                firewall-cmd --zone="$zone" --add-rich-rule="$rule"
              fi
              if ! firewall-cmd --permanent --zone="$zone" --query-rich-rule="$rule" >/dev/null; then
                touch "$tx/firewalld-deny-permanent"
                sync -f "$tx/firewalld-deny-permanent"
                firewall-cmd --permanent --zone="$zone" --add-rich-rule="$rule"
              fi
              ;;
          esac
        fi
        """;

    internal const string CommitBody = """
        guard
        printf '%s\n' committed > "$tx/state.new"
        sync -f "$tx/state.new"
        mv -f "$tx/state.new" "$tx/state"
        sync -f "$tx/state"
        printf '%s\n' "$id" > "$base/last-committed.new"
        sync -f "$base/last-committed.new"
        mv -f "$base/last-committed.new" "$base/last-committed"
        sync -f "$base/last-committed"
        if [ "$(cat "$base/active" 2>/dev/null)" = "$id" ]; then rm -f "$base/active"; fi
        systemctl disable --now "$timer" >/dev/null 2>&1 || true
        systemctl disable "$boot" >/dev/null 2>&1 || true
        printf 'Transaction committed: %s\n' "$id"
        """;

    internal const string RollbackBody = """
        trap '' HUP
        [ "$(id -u)" = 0 ] || fail 'Root privilege is required for recovery.'
        exec 9>/run/ssh-hardener.lock
        flock -w 120 9 || fail 'Could not acquire the recovery lock.'
        [ -d "$tx" ] && [ ! -L "$tx" ] || fail 'Unknown or unsafe transaction.'
        state=$(cat "$tx/state" 2>/dev/null || true)
        [ "$state" != rolled-back ] || exit 0
        if [ "$state" = committed ]; then
          # Lost commit acknowledgements must never trigger automatic undo.
          [ "${1:-auto}" = manual ] || exit 0
          [ ! -e "$base/active" ] || fail 'A newer pending transaction exists. Recover it first.'
          [ "$(cat "$base/last-committed" 2>/dev/null)" = "$id" ] || fail 'Only the most recent committed transaction can be manually recovered.'
          [ "$(sha256sum /etc/ssh/sshd_config | awk '{print $1}')" = "$(cat "$tx/main.sha256")" ] || fail 'SSH configuration changed after commit. Manual recovery requires console review.'
          ssh_include_manifest > "$tx/includes.current"
          same_file_contents "$tx/includes.sha256" "$tx/includes.current" || fail 'SSH include files changed after commit. Manual recovery requires console review.'
          printf '%s\n' "$id" > "$base/active"
          sync -f "$base/active"
          systemctl enable "$boot" >/dev/null
          systemctl enable --now "$timer" >/dev/null
        fi
        [ "$(cat "$base/active" 2>/dev/null)" = "$id" ] || fail 'Transaction ownership mismatch.'
        printf '%s\n' rolling-back > "$tx/state" || true
        sync -f "$tx/state" || true
        failed=0
        # Recovery attempts every independent restoration even if the disk is full
        # or a less important cleanup step fails.
        set +e
        if [ -f "$tx/main-changed" ]; then
          restore=$(mktemp /etc/ssh/.sshhardener-restore.XXXXXX)
          if cp -p "$tx/sshd_config.original" "$restore" && /usr/sbin/sshd -t -f "$restore"; then
            mv -f "$restore" /etc/ssh/sshd_config || failed=1
            if command -v restorecon >/dev/null 2>&1; then restorecon /etc/ssh/sshd_config || failed=1; fi
          else failed=1; rm -f "$restore"; fi
        fi
        if [ -f "$tx/ufw-old-deny-intent" ]; then ufw_delete_owned "SSHHardener-old:$id" || failed=1; fi
        if [ -f "$tx/ufw-open-intent" ]; then ufw_delete_owned "SSHHardener:$id" || failed=1; fi
        if [ -f "$tx/firewalld.zone" ]; then
          zone=$(cat "$tx/firewalld.zone")
          rule="rule priority=\"-100\" port port=\"$oldport\" protocol=\"tcp\" reject"
          if [ -f "$tx/firewalld-deny-runtime" ]; then firewall-cmd --zone="$zone" --remove-rich-rule="$rule" || failed=1; fi
          if [ -f "$tx/firewalld-deny-permanent" ]; then firewall-cmd --permanent --zone="$zone" --remove-rich-rule="$rule" || failed=1; fi
          if [ -f "$tx/firewalld-open-runtime" ]; then firewall-cmd --zone="$zone" --remove-port="$port/tcp" || failed=1; fi
          if [ -f "$tx/firewalld-open-permanent" ]; then firewall-cmd --permanent --zone="$zone" --remove-port="$port/tcp" || failed=1; fi
        fi
        if [ -f "$tx/selinux-intent" ]; then
          if semanage port -l -n | awk -v p="$port" '$1=="ssh_port_t" && $2=="tcp" {gsub(/,/," ");for(i=3;i<=NF;i++)if($i==p)found=1}END{exit !found}'; then semanage port -d -p tcp "$port" || failed=1; fi
        fi
        if [ -f "$tx/fail2ban-added" ]; then
          rm -f /etc/fail2ban/jail.d/zz-sshhardener.local || failed=1
          if [ "${1:-}" != boot ]; then fail2ban-client reload || failed=1; fi
        fi
        if [ -f "$tx/sudoers-added" ]; then
          file="/etc/sudoers.d/90-sshhardener-$user"
          if same_file_contents "$file" "$tx/sudoers.new"; then rm -f "$file" || failed=1; else failed=1; fi
        fi
        if [ -f "$tx/key-provision-intent" ]; then
          home=$(cat "$tx/home")
          expected_uid=$(cat "$tx/user.uid")
          current_uid=$(id -u "$user" 2>/dev/null || true)
          if [ "$current_uid" = "$expected_uid" ]; then
            sshmode=$(awk -F= '$1=="ssh_mode" && length($2)>=3 && length($2)<=4 && $2!~/[^0-7]/{print $2;exit}' "$tx/key.metadata" 2>/dev/null || true)
            authmode=$(awk -F= '$1=="auth_mode" && length($2)>=3 && length($2)<=4 && $2!~/[^0-7]/{print $2;exit}' "$tx/key.metadata" 2>/dev/null || true)
            sshcreated=$(awk -F= '$1=="ssh_created" && $2=="yes"{print "yes";exit}' "$tx/key.metadata" 2>/dev/null || true)
            authcreated=$(awk -F= '$1=="auth_created" && $2=="yes"{print "yes";exit}' "$tx/key.metadata" 2>/dev/null || true)
            if ! runuser -u "$user" -- /bin/sh -s -- "$home" "$id" "$sshmode" "$authmode" "$sshcreated" "$authcreated" <<'SSHARDENER_USER_RECOVERY'
        set -eu
        umask 077
        home=$1; id=$2; sshmode=$3; authmode=$4; sshcreated=$5; authcreated=$6
        [ -d "$home" ] && [ "$(readlink -f "$home")" = "$home" ] || exit 1
        sshdir="$home/.ssh"; auth="$sshdir/authorized_keys"
        [ ! -L "$sshdir" ] && [ ! -L "$auth" ] || exit 1
        if [ -f "$auth" ]; then
          clean=$(mktemp "$sshdir/.sshhardener-recover.XXXXXX")
          trap 'rm -f "$clean"' EXIT HUP INT TERM
          awk -v marker="SSHHardener:$id" '$NF!=marker' "$auth" > "$clean"
          chmod --reference="$auth" "$clean"
          mv -f "$clean" "$auth"
          trap - EXIT HUP INT TERM
          [ -z "$authmode" ] || chmod "$authmode" "$auth"
          if [ "$authcreated" = yes ] && ! grep -q '[^[:space:]]' "$auth"; then rm -f "$auth"; fi
        fi
        if [ -d "$sshdir" ]; then
          [ -z "$sshmode" ] || chmod "$sshmode" "$sshdir"
          if [ "$sshcreated" = yes ]; then rmdir "$sshdir" 2>/dev/null || true; fi
        fi
        SSHARDENER_USER_RECOVERY
            then failed=1; fi
          else failed=1; fi
        fi
        if [ "${1:-}" != boot ] && [ -f "$tx/main-changed" ]; then /usr/sbin/sshd -t && systemctl reload "$service.service" || failed=1; fi
        if [ "$failed" = 0 ]; then
          printf '%s\n' rolled-back > "$tx/state"
          sync -f "$tx/state"
          rm -f "$base/active"
          systemctl disable --now "$timer" >/dev/null 2>&1 || true
          systemctl disable "$boot" >/dev/null 2>&1 || true
          printf 'Recovery completed. Newly created user accounts and files are retained.\n'
        else
          printf '%s\n' recovery-failed > "$tx/state"
          fail "Some recovery steps failed. Use the provider console and inspect $tx."
        fi
        """;
}
