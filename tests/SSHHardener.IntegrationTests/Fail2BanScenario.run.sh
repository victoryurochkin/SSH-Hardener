#!/bin/sh
set -eu
export LC_ALL=C
probe=${1:?Pass the absolute Linux path of the exported disposable fixture directory.}
case "$probe" in /*) ;; *) printf 'An absolute fixture path is required.\n' >&2; exit 1;; esac
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -f "$probe/configure-fail2ban.sh" ] && [ -f "$probe/rollback.sh" ] && [ -f "$probe/scenario.env" ]
cp "$here/Fail2BanScenario.service-control.sh" "$probe/service-control.sh"
cp "$here/Fail2BanScenario.server.sh" "$probe/server.sh"
cp "$here/Fail2BanScenario.finish.sh" "$probe/finish.sh"
cp "$here/Fail2BanScenario.firewall-check.sh" "$probe/firewall-check.sh"
cp "$here/Fail2BanScenario.package-lock.sh" "$probe/package-lock.sh"
chmod 0755 "$probe/service-control.sh"
rm -f "$probe/server-ready"
suffix="$(date +%s)-$$"
network="sshhardener-fail2ban-$suffix"
server="sshhardener-fail2ban-server-$suffix"
client="sshhardener-fail2ban-client-$suffix"
cleanup() {
  docker logs "$server" > "$probe/server.log" 2>&1 || true
  docker rm -f "$server" >/dev/null 2>&1 || true
  docker rm -f "$client" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
docker network create "$network" >/dev/null
docker run -d --rm --name "$server" --network "$network" --network-alias fail2ban-fixture --cap-add NET_ADMIN -v "$probe:/probe" sshhardener-fail2ban-probe:local /probe/server.sh >/dev/null
count=0
until [ -f "$probe/server-ready" ]; do
  count=$((count+1))
  if [ "$count" -ge 180 ] || [ "$(docker inspect -f '{{.State.Running}}' "$server" 2>/dev/null || true)" != true ]; then
    docker logs "$server" >&2 || true
    cat "$probe/server-console.log" >&2 || true
    printf 'FAIL: disposable fail2ban fixture did not prepare successfully.\n' >&2
    exit 1
  fi
  sleep 1
done
client_ip=
for attempt in 1 2 3; do
  # Keep one client namespace/address for all three attempts; each command allows one prompt.
  if [ "$attempt" = 1 ]; then
    client="sshhardener-fail2ban-client-$suffix"
    docker run -d --rm --name "$client" --network "$network" sshhardener-fail2ban-probe:local -c 'sleep 300' >/dev/null
    client_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$client")
    printf '%s\n' "$client" > "$probe/client-container"
  else client=$(cat "$probe/client-container"); fi
  if docker exec "$client" sshpass -p IntentionallyWrongFixturePassword ssh -o LogLevel=ERROR -o ConnectTimeout=3 -o ConnectionAttempts=1 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 -p 22022 testadmin@fail2ban-fixture true; then
    printf 'FAIL: deliberately incorrect fixture password was accepted.\n' >&2
    exit 1
  fi
  count=0
  while :; do
    total=$(docker exec "$server" fail2ban-client status sshhardener-sshd | awk '/Total failed:/ {print $NF}')
    [ "$total" -ge "$attempt" ] && break
    count=$((count+1)); [ "$count" -lt 30 ] || { docker exec "$server" journalctl --no-pager >&2; exit 1; }; sleep 0.2
  done
  banned=$(docker exec "$server" fail2ban-client get sshhardener-sshd banip)
  if [ "$attempt" -lt 3 ]; then
    [ -z "$banned" ] || { printf 'FAIL: ban occurred before three fixture failures.\n' >&2; exit 1; }
    printf 'PASS: failure %s matched; client %s remains unbanned.\n' "$attempt" "$client_ip"
  fi
done
count=0
until docker exec "$server" fail2ban-client get sshhardener-sshd banip | grep -F "$client_ip" >/dev/null; do
  count=$((count+1)); [ "$count" -lt 30 ] || exit 1; sleep 0.2
done
docker exec "$server" iptables -S | grep -F "$client_ip" >/dev/null
printf 'PASS: three actual password failures caused a journal-backend ban and an actual isolated iptables rule.\n'
docker exec "$server" /bin/sh /probe/firewall-check.sh
if docker exec "$client" sshpass -p 'TestOnly-SSHHardener-2026!' ssh -o LogLevel=ERROR -o ConnectTimeout=3 -o ConnectionAttempts=1 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 -p 22022 testadmin@fail2ban-fixture true; then
  printf 'FAIL: banned client still authenticated.\n' >&2; exit 1
fi
docker exec "$server" fail2ban-client set sshhardener-sshd unbanip "$client_ip" >/dev/null
docker exec "$client" sshpass -p 'TestOnly-SSHHardener-2026!' ssh -o LogLevel=ERROR -o ConnectTimeout=3 -o ConnectionAttempts=1 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 -p 22022 testadmin@fail2ban-fixture true
printf 'PASS: unban restored successful fixture authentication.\n'
docker exec "$client" ssh-keygen -q -t ed25519 -N '' -f /tmp/unknown-fixture-key
for attempt in 1 2 3; do
  if docker exec "$client" ssh -o LogLevel=ERROR -o ConnectTimeout=3 -o ConnectionAttempts=1 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -i /tmp/unknown-fixture-key -p 22022 testadmin@fail2ban-fixture true; then
    printf 'FAIL: an unknown fixture key was accepted.\n' >&2; exit 1
  fi
  count=0
  while :; do
    total=$(docker exec "$server" fail2ban-client status sshhardener-sshd | awk '/Total failed:/ {print $NF}')
    [ "$total" -ge "$((3+attempt))" ] && break
    count=$((count+1)); [ "$count" -lt 30 ] || { docker exec "$server" journalctl --no-pager >&2; exit 1; }; sleep 0.2
  done
  if [ "$attempt" -lt 3 ]; then
    [ -z "$(docker exec "$server" fail2ban-client get sshhardener-sshd banip)" ] || { printf 'FAIL: key ban occurred before three fixture failures.\n' >&2; exit 1; }
  fi
done
count=0
until docker exec "$server" fail2ban-client get sshhardener-sshd banip | grep -F "$client_ip" >/dev/null; do
  count=$((count+1)); [ "$count" -lt 30 ] || exit 1; sleep 0.2
done
docker exec "$server" iptables -S | grep -F "$client_ip" >/dev/null
docker exec "$server" fail2ban-client set sshhardener-sshd unbanip "$client_ip" >/dev/null
printf 'PASS: three actual unknown-key failures also triggered the managed jail and packet-filter action.\n'
docker exec "$server" /bin/sh /probe/package-lock.sh
docker exec "$server" /bin/sh /probe/finish.sh
docker exec "$server" journalctl --no-pager > "$probe/journal.txt"
docker exec "$server" iptables -S > "$probe/iptables-after-rollback.txt"
docker rm -f "$client" >/dev/null
printf 'PASS: fresh package install, systemd journal backend, three-event threshold, enforcement, unban and own-state rollback.\n'
