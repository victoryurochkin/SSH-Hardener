#!/bin/sh
set -eu
. /probe/scenario.env
tx=/var/lib/ssh-hardener/transactions/$txid
lock=$tx/fail2ban.package.lock
rm -f /probe/package-lock-held /probe/package-lock-release
sha256sum /etc/fail2ban/jail.d/sshhardener-sshd.local > /probe/busy-jail.sha256
sha256sum /var/lib/ssh-hardener/fail2ban-managed.sha256 > /probe/busy-owner.sha256
mkdir -p /run/systemd/system /usr/local/bin
ln -sf /dev/null /run/systemd/system/fail2ban.service
ln -sf /dev/null /run/systemd/system/nftables.service
cat > /usr/local/bin/systemd-run <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> /probe/deferred-retry.log
exit 0
EOF
chmod 0755 /usr/local/bin/systemd-run
(
  exec 8>"$lock"
  flock 8
  touch /probe/package-lock-held
  while [ ! -f /probe/package-lock-release ]; do sleep 0.1; done
) </dev/null > /probe/package-lock-holder.log 2>&1 &
holder=$!
release() { touch /probe/package-lock-release; wait "$holder" 2>/dev/null || true; }
trap release EXIT HUP INT TERM
attempt=0
until [ -f /probe/package-lock-held ]; do
  attempt=$((attempt+1)); [ "$attempt" -lt 100 ] || exit 1; sleep 0.1
done
if /bin/sh "$tx/rollback.sh" auto; then
  printf 'FAIL: recovery claimed success while a package operation owned the package lock.\n' >&2
  exit 1
fi
[ "$(cat "$tx/state")" = recovery-deferred ]
[ "$(readlink /run/systemd/system/fail2ban.service)" = /dev/null ]
[ "$(readlink /run/systemd/system/nftables.service)" = /dev/null ]
sha256sum -c /probe/busy-jail.sha256
sha256sum -c /probe/busy-owner.sha256
grep -F -- '--on-active=20s' /probe/deferred-retry.log >/dev/null
printf 'PASS: busy package lock deferred actual rollback, preserved owned policy/proof/masks and requested a delayed retry.\n'
release
trap - EXIT HUP INT TERM
flock -n "$lock" true
printf 'PASS: package lock released; the next production rollback may complete cleanup.\n'
