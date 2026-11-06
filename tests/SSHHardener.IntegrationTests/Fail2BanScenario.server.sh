#!/bin/sh
set -eu
export LC_ALL=C
exec > /probe/server-console.log 2>&1
. /probe/scenario.env
tx=/var/lib/ssh-hardener/transactions/$txid
mkdir -p /run/systemd/journal /run/log/journal /run/sshd /run/fail2ban
/lib/systemd/systemd-journald > /probe/journald.log 2>&1 &
journal_pid=$!
trap 'kill "$journal_pid" 2>/dev/null || true' EXIT HUP INT TERM
attempt=0
until [ -S /run/systemd/journal/dev-log ]; do
  attempt=$((attempt+1)); [ "$attempt" -lt 100 ] || { cat /probe/journald.log >&2; exit 1; }; sleep 0.1
done
ln -sf /run/systemd/journal/dev-log /dev/log
install -d -m 0755 /usr/local/bin
install -m 0755 /probe/service-control.sh /usr/local/bin/systemctl
install -d -m 0700 /var/lib/ssh-hardener /var/lib/ssh-hardener/transactions "$tx"
printf '%s\n' "$txid" > /var/lib/ssh-hardener/active
printf pending > "$tx/state"
cp /probe/rollback.sh "$tx/rollback.sh"
chmod 0700 "$tx/rollback.sh"

if command -v fail2ban-client >/dev/null 2>&1; then
  printf 'FAIL: fresh fixture unexpectedly already contains fail2ban.\n' >&2
  exit 1
fi
[ ! -e /var/log/auth.log ] || { printf 'FAIL: fixture must test journal-only logging.\n' >&2; exit 1; }
mkdir -p /etc/fail2ban/jail.d
printf '[unrelated-fixture]\nenabled = false\nfilter = apache-auth\n' > /etc/fail2ban/jail.d/00-unrelated-fixture.local
sha256sum /etc/fail2ban/jail.d/00-unrelated-fixture.local > /probe/unrelated.sha256
printf 'PASS: fresh Debian fixture has no fail2ban and no auth.log.\n'
/bin/sh /probe/configure-fail2ban.sh
cp "$tx/fail2ban.packages.log" /probe/packages.log
dpkg-query -W fail2ban python3-systemd iptables nftables > /probe/package-versions.txt
python3 -c 'from systemd import journal; assert journal.Reader'
fail2ban-client ping
fail2ban-client status "$jail"
fail2ban-client get "$jail" maxretry
fail2ban-client get "$jail" findtime
fail2ban-client get "$jail" bantime
fail2ban-client get "$jail" ignoreip
[ "$(fail2ban-client get "$jail" maxretry)" = 3 ]
[ "$(fail2ban-client get "$jail" findtime)" = 600 ]
[ "$(fail2ban-client get "$jail" bantime)" = 3600 ]
fail2ban-client get "$jail" ignoreip | grep -F '192.0.2.10' >/dev/null
printf 'PASS: production step installed package/backend and configured managed threshold/whitelist.\n'

# Docker's embedded DNS injects unrelated NAT objects into this isolated namespace.
# The production classifier must reject them. Package downloads are now complete;
# preserve a snapshot and remove only this fixture-owned DNS table before testing
# a host with exclusively managed Fail2ban filter rules. Client DNS is unaffected.
if nft -j list table ip nat > /probe/docker-dns-before.json 2>/dev/null; then
  iptables -t nat -S > /probe/docker-dns-before.txt
  awk '
    /^-P (PREROUTING|INPUT|OUTPUT|POSTROUTING) ACCEPT$/ {next}
    /^-N DOCKER_(OUTPUT|POSTROUTING)$/ {next}
    /^-A (OUTPUT|POSTROUTING) -d 127[.]0[.]0[.]11\/32 -j DOCKER_(OUTPUT|POSTROUTING)$/ {next}
    /^-A DOCKER_OUTPUT -d 127[.]0[.]0[.]11\/32 / {next}
    /^-A DOCKER_POSTROUTING -s 127[.]0[.]0[.]11\/32 / {next}
    {exit 1}
  ' /probe/docker-dns-before.txt || { printf 'FAIL: unexpected fixture NAT state; refusing fixture DNS cleanup.\n' >&2; exit 1; }
  nft delete table ip nat
fi

# A controlled fixture has one password prompt and no PAM duplicate event per attempt.
cat > /tmp/fail2ban-fixture-sshd.conf <<'EOF'
Port 22022
ListenAddress 0.0.0.0
PidFile /run/fail2ban-fixture-sshd.pid
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
UsePAM no
MaxAuthTries 3
LogLevel VERBOSE
SyslogFacility AUTH
EOF
/usr/sbin/sshd -t -f /tmp/fail2ban-fixture-sshd.conf
/usr/sbin/sshd -D -f /tmp/fail2ban-fixture-sshd.conf > /probe/sshd.log 2>&1 &
sshd_pid=$!
printf '%s\n' "$sshd_pid" > /run/fail2ban-fixture-sshd.pid
trap 'kill "$sshd_pid" "$journal_pid" 2>/dev/null || true' EXIT HUP INT TERM
attempt=0
until ss -H -ltn 'sport = :22022' | grep -q .; do
  attempt=$((attempt+1)); [ "$attempt" -lt 100 ] || exit 1; sleep 0.1
done
touch /probe/server-ready
wait "$sshd_pid"
