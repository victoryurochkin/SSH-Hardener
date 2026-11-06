#!/bin/sh
set -eu
. /probe/scenario.env
tx=/var/lib/ssh-hardener/transactions/$txid
[ -f /etc/fail2ban/jail.d/sshhardener-sshd.local ]
/bin/sh "$tx/rollback.sh" auto
[ "$(cat "$tx/state")" = rolled-back ]
[ ! -e /etc/fail2ban/jail.d/sshhardener-sshd.local ]
dpkg-query -W -f='${Status}' fail2ban | grep -F 'install ok installed' >/dev/null
if fail2ban-client ping >/dev/null 2>&1; then
  printf 'FAIL: rollback left an originally inactive service running.\n' >&2
  exit 1
fi
[ ! -e /run/fail2ban-fixture-state/enabled ]
[ ! -L /etc/systemd/system/multi-user.target.wants/fail2ban.service ]
[ ! -L /etc/systemd/system/multi-user.target.wants/nftables.service ]
[ ! -L /run/systemd/system/nftables.service ]
[ ! -e /var/lib/ssh-hardener/fail2ban-managed.sha256 ]
sha256sum -c /probe/unrelated.sha256
. /probe/managed-firewall-helper.sh
if only_managed_fail2ban_firewall; then
  printf 'FAIL: removed owner proof still classified as managed firewall state.\n' >&2
  exit 1
fi
printf 'PASS: production rollback removed only managed jail, restored inactive/disabled service and retained installed packages.\n'
