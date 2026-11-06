# Framed stdin transport regression

```powershell
pwsh -File tests/SSHHardener.IntegrationTests/FramedTransportScenario.run.ps1
```

This explicit acceptance requires Windows .NET 10, WSL Ubuntu/Docker and the existing
`sshhardener-access-policy:local` Debian image. It runs production SSH.NET sessions against
one disposable container bound only to loopback, using a fresh encrypted synthetic Ed25519
key. No user host, keys or AppData trust records are used. The fixture has root, plain,
NOPASSWD sudo and PASSWD sudo accounts; all log in with that key. The PASSWD test supplies
only the sudo password, independently of SSH authentication.

Each mode executes more than 256 KiB of actual script through both normal and sensitive
methods, checks Unicode stdout/stderr, nonzero exit codes, execution UID, private helper
permissions, exact binary payload including leading newlines and NUL/non-UTF8 bytes, and
scans real ancestor process arguments for script/payload/password leakage. It also cancels
a running long command and checks client cancellation, named helper cleanup and session reuse. The test refuses to
silently call a pre-cancelled operation instead of cancelling actual remote work.

The production wrapper opens the validated mode-0600 script on descriptor 3, unlinks its
temporary name **before execution**, then runs `/bin/sh /proc/self/fd/3` with the untouched
remaining stdin. A stopped client operation does **not** prove immediate termination of
remote descendants: OpenSSH can refuse signal requests for a root session, and sudo can
alter signal propagation. The fixture observed those cases and initially failed on retained
named helpers before the descriptor/unlink fix. The recovery engine must rely on confirmed
server transaction state and its independent timer, not on a local cancellation result.
The fixture container is removed at the end, including any remaining test descendants.

Primary references: [SSH.NET command cancellation](https://github.com/sshnet/SSH.NET/blob/2026.0.0/src/Renci.SshNet/SshCommand.cs#L382-L440),
[OpenSSH 9.2 signal request handling](https://github.com/openssh/openssh-portable/blob/V_9_2_P1/session.c#L2010-L2045).

The runner removes only its own UUID-named container in `finally`. Synthetic encrypted
keys, public host key and results remain under ignored `artifacts/framed-transport`. The
default integration modes are unchanged; this regression performs no system hardening.
