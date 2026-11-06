# Disposable SFTP/browser acceptance

Run from the repository on Windows with .NET 10/WPF, WSL Ubuntu and the already-built
`sshhardener-access-policy:local` Debian fixture image:

```powershell
pwsh -File tests/SSHHardener.UiTests/SftpLiveScenario.run.ps1
```

The default UI harness remains offline. This explicit runner creates a synthetic encrypted
Ed25519 key, starts one disposable Docker SSH server bound only to `127.0.0.1` on a random
port, and tests production `SftpSessionFactory`, `TargetAccessVerifier` and
`SftpBrowserViewModel`. It exercises actual upload/download/rename/mkdir/delete,
read/write and `internal-sftp -R` access, static parent/leaf/dangling symlink rejection,
no-overwrite behavior, cancellation and cleanup of its own partial upload, and host-pin
rejection. The server chroots two fixture accounts; no shell command is used by the final
SFTP-only verifier. The container is removed in `finally`.

All keys/passphrases/data are public disposable fixtures, never user credentials. There
are no privileged containers, user VM connections or user AppData trust/history writes.
Evidence and synthetic keys remain only under the ignored repository `artifacts/sftp-live`
directory. Server packages and configuration are changed only in the container rootfs.

SFTP v3 cannot provide atomic `openat`/`O_NOFOLLOW` for an entire path. The application
rejects observed symlinks with parent directory entries; this test does not claim protection
against a concurrent independent process replacing path components between protocol requests.
