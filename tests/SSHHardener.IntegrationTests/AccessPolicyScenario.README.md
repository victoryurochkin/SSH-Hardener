# Disposable server access policy checks

This fixture executes the **actual `AccessPolicyPython` constant** exported from
`AccessPolicyScripts.cs`, then uses Debian 12 OpenSSH, Google Authenticator PAM,
sudo and SFTP. It uses public fixture credentials and generated disposable keys.
It never reads application profiles, user keys or VM credentials.

From the repository root on Windows:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests/SSHHardener.IntegrationTests/AccessPolicyScenario.prepare.ps1
wsl -d Ubuntu --exec sh /mnt/d/Projects/SSH-Hardener/tests/SSHHardener.IntegrationTests/AccessPolicyScenario.run.sh /mnt/d/Projects/SSH-Hardener/artifacts/access-policy
```

Adjust the WSL mount path for another checkout. Docker must run inside that WSL
distribution. Image building downloads Debian packages; execution uses
`--network none`, SSH on container loopback only, and no published ports. The
container is removed after execution. Diagnostic files in `artifacts/access-policy`
contain fixture data only; its production helper export contains no credentials.

The scenario checks actual key+TOTP authentication, missing/incorrect/reused code
rejection, one-use recovery codes, chroot SFTP read/write/delete and escape denial,
read-only SFTP write denial, preservation of another account, and explicit rejection
of reapplying an existing SFTP target before arming, preserving its existing MFA and
consumed-code state. It also checks actual
sudoers parsing and exact command permission checks, forbidden root shells,
writable unit and shell injection rejection, existing full-admin rejection,
existing password validation without hash replacement, locking an owned new
password on rollback, and preservation of concurrent policy/secret changes.

`systemctl show` unit metadata is stubbed inside the disposable container; the
`systemctl` executable, unit file ownership checks and sudo permission checks are
real. This does **not** prove service restart safety for arbitrary service
implementations. An administrator must trust each approved service and its
configuration. The fixture does not run systemd as PID 1 and does not validate
transaction timers, reboot recovery or the complete Apply pipeline. Image
installation of the PAM package does not validate the production bounded apt
installation branch. Those require separate integration/VM acceptance.

The fixture deliberately waits about 31 seconds for the real PAM rate-limit
window to expire before testing recovery codes. Failures return nonzero; there
is no silent skip when Docker or a dependency is unavailable.

The former same-account SFTP reconfiguration sequence is intentionally rejected by
the public preflight: a dual-phase SSH-shell probe cannot verify an account that is
already forced to SFTP without temporarily dropping its restrictions. Supported
preservation of an existing shell account's MFA, its effective dual/final `Match`
policy, mutable replay/recovery state through rollback, and rejection of enrollment
reset are covered by the separate seven-case
[`OwnedAccessPolicyPreservation`](OwnedAccessPolicyPreservation.README.md) fixture.
