#!/bin/sh
# Fixture-only control of actual fail2ban processes without a systemd PID 1.
# This is not a test of systemd unit persistence or boot recovery.
set -eu
state=/run/fail2ban-fixture-state
mkdir -p "$state"
printf '%s\n' "$*" >> /probe/service-control.log
operation=${1:-}
shift || true
case "$operation" in
  daemon-reload|reset-failed) exit 0;;
  is-active)
    case "$*" in
      *ssh-hardener-*.timer*) exit 0;;
      *fail2ban*) fail2ban-client ping >/dev/null 2>&1; exit $?;;
      *ssh.service*) kill -0 "$(cat /run/fail2ban-fixture-sshd.pid)"; exit $?;;
    esac
    exit 1;;
  is-enabled)
    case "$*" in
      *nftables*) if [ -L /etc/systemd/system/multi-user.target.wants/nftables.service ]; then printf 'enabled\n'; exit 0; else printf 'disabled\n'; exit 1; fi;;
      *fail2ban*) [ -f "$state/enabled" ];; *) exit 0;;
    esac
    exit $?;;
  enable)
    case "$*" in *nftables*) printf 'FAIL: nftables service must never be enabled by this fixture.\n' >&2; exit 1;; esac
    case "$*" in *fail2ban*) touch "$state/enabled"; mkdir -p /etc/systemd/system/multi-user.target.wants; ln -sf /lib/systemd/system/fail2ban.service /etc/systemd/system/multi-user.target.wants/fail2ban.service;; *) exit 0;; esac
    case "$*" in *--now*) /probe/service-control.sh start fail2ban.service;; esac
    exit 0;;
  disable)
    case "$*" in *nftables*) rm -f /etc/systemd/system/multi-user.target.wants/nftables.service; exit 0;; esac
    case "$*" in *fail2ban*) rm -f "$state/enabled" /etc/systemd/system/multi-user.target.wants/fail2ban.service;; *) exit 0;; esac
    case "$*" in *--now*) /probe/service-control.sh stop fail2ban.service;; esac
    exit 0;;
  start|restart|reload-or-restart|try-restart)
    case "$*" in *nftables*) printf 'FAIL: nftables service must never be started by this fixture.\n' >&2; exit 1;; esac
    case "$*" in
      *fail2ban*)
        mkdir -p /run/fail2ban
        if fail2ban-client ping >/dev/null 2>&1; then
          if [ "$operation" = restart ]; then fail2ban-client stop >/dev/null; else fail2ban-client reload >/dev/null; exit 0; fi
        fi
        # A real systemd-launched service inherits no descriptor from the caller.
        # Close the transaction/package locks before spawning the fixture daemon too.
        (exec 9>&-; exec 8>&-; exec fail2ban-server -xf start) >> /probe/fail2ban-server.log 2>&1 &
        printf '%s\n' "$!" > "$state/pid"
        count=0
        until fail2ban-client ping >/dev/null 2>&1; do
          count=$((count+1)); [ "$count" -lt 100 ] || exit 1; sleep 0.1
        done
        exit 0;;
    esac
    exit 0;;
  stop)
    case "$*" in *fail2ban*) if fail2ban-client ping >/dev/null 2>&1; then fail2ban-client stop >/dev/null; fi;; esac
    exit 0;;
  reload)
    case "$*" in *fail2ban*) fail2ban-client reload;; *ssh.service*) kill -HUP "$(cat /run/fail2ban-fixture-sshd.pid)";; esac
    exit 0;;
  mask)
    mkdir -p /run/systemd/system
    case "$*" in *nftables*) unit=nftables.service;; *) unit=fail2ban.service;; esac
    ln -sf /dev/null "/run/systemd/system/$unit"
    exit 0;;
  unmask)
    case "$*" in *nftables*) unit=nftables.service;; *) unit=fail2ban.service;; esac
    rm -f "/run/systemd/system/$unit"
    exit 0;;
  show)
    case "$*" in *fail2ban*) printf 'LoadState=loaded\nUnitFileState=disabled\n';; esac
    exit 0;;
esac
printf 'Unsupported fixture systemctl invocation: %s %s\n' "$operation" "$*" >&2
exit 1
