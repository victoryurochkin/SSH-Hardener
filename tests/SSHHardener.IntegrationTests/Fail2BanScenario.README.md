# Disposable fresh-install and ban test

This explicit fixture uses Debian 12, a real `sshd`, standalone `systemd-journald`, the real Fail2ban journal backend and real iptables rules inside a dedicated container network namespace. The server receives only `NET_ADMIN`; it has no published ports, host network, Docker socket, host cgroup mount or access to a production VM.

After package downloads, the fixture snapshots and removes Docker's embedded-DNS NAT table inside its own server namespace. Such unrelated NAT rules are correctly rejected by the production classifier. This fixture-only cleanup models a server whose only packet-filter rules belong to its managed jail; it does not relax the application classifier or touch host rules.

The fixture image deliberately omits Fail2ban and Python systemd bindings. The exported production `configure-fail2ban` step must install them through apt. The test verifies no `/var/log/auth.log` exists, checks the configured retry/window/ban values and administrator whitelist, sends three actual wrong-password authentications, proves the first two do not ban and the third does, checks an actual firewall rule and blocked authentication, then unbans and proves a successful login. It repeats the threshold test with an unknown public key, exercising `publickey=any`.

After a real ban, the actual exported firewall classifier must accept the owned chains, reject a foreign INPUT ACCEPT rule and a foreign nftables table, then accept again when each foreign addition is removed. A held package lock must defer the actual rollback, preserve owned configuration/proof/runtime masks and request a delayed retry; the retry request is recorded by a fixture-only `systemd-run` shim. After lock release, the real production rollback script must remove its own jail and owner proof, preserve an unrelated configuration file, return the originally inactive service to inactive/disabled and retain installed packages. The nftables service must remain inactive/disabled; only its CLI is used. Removed owner proof must no longer classify as managed firewall state. A fixture-only `systemctl` shim controls the actual Fail2ban process and records calls. This tests service-state decisions, but **does not certify real systemd unit persistence or reboot recovery**. Those remain VM acceptance scenarios.

From Windows, export scripts from the current build:

```powershell
dotnet run --project tests/SSHHardener.IntegrationTests -c Release -- --export-fail2ban D:\Projects\SSH-Hardener\artifacts\fail2ban-probe
```

From WSL Ubuntu, adjust the checkout path if necessary:

```sh
cd /mnt/d/Projects/SSH-Hardener/tests/SSHHardener.IntegrationTests
docker compose -p sshhardener_integration build debian
docker build -f Fail2BanScenario.Dockerfile -t sshhardener-fail2ban-probe:local .
/bin/sh Fail2BanScenario.run.sh /mnt/d/Projects/SSH-Hardener/artifacts/fail2ban-probe
```

The runner exits nonzero on failure and removes its own server, client and dedicated network through a cleanup trap. Apt may need internet access inside the disposable server. Fixture credentials are intentionally public test values and must never be used outside these containers.

Evidence is written beneath the exported fixture directory: `server-console.log`, `service-control.log`, `fail2ban-server.log`, `journal.txt`, `iptables-after-ban.txt`, `nft-after-ban.json`, `iptables-after-rollback.txt`, `packages.log` and `package-versions.txt`. No production SSH credentials are used or recorded.
