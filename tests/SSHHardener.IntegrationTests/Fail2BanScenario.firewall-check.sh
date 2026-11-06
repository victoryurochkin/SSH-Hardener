#!/bin/sh
set -eu
[ -f /probe/managed-firewall-helper.sh ] || { printf 'The actual managed-firewall helper export is missing.\n' >&2; exit 1; }
. /probe/managed-firewall-helper.sh
iptables-save > /probe/iptables-after-ban.txt
nft -j list ruleset > /probe/nft-after-ban.json
only_managed_fail2ban_firewall || { printf 'FAIL: actual owned Fail2ban chains were rejected.\n' >&2; exit 1; }
printf 'PASS: actual shared firewall helper accepts only owned Fail2ban state after a real ban.\n'

iptables -I INPUT 1 -s 198.51.100.254/32 -j ACCEPT
if only_managed_fail2ban_firewall; then
  iptables -D INPUT -s 198.51.100.254/32 -j ACCEPT
  printf 'FAIL: a foreign INPUT ACCEPT rule was accepted.\n' >&2
  exit 1
fi
iptables -D INPUT -s 198.51.100.254/32 -j ACCEPT
only_managed_fail2ban_firewall || { printf 'FAIL: owned state was not accepted after removing foreign INPUT rule.\n' >&2; exit 1; }

nft add table inet sshhardener_foreign_probe
if only_managed_fail2ban_firewall; then
  nft delete table inet sshhardener_foreign_probe
  printf 'FAIL: a foreign nftables table was accepted.\n' >&2
  exit 1
fi
nft delete table inet sshhardener_foreign_probe
only_managed_fail2ban_firewall || { printf 'FAIL: owned state was not accepted after removing the foreign nftables table.\n' >&2; exit 1; }
printf 'PASS: foreign INPUT rule and nftables table are rejected; removing each restores eligibility.\n'
