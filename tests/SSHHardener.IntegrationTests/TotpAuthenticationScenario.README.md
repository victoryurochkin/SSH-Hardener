# Actual SSH.NET key plus TOTP authentication

Opt-in Windows/WSL Docker integration. It generates a **new encrypted Ed25519 test key**, starts the existing `sshhardener-access-policy:local` image with only a synthetic public key mounted, and publishes SSH on an automatically allocated **127.0.0.1** port. No user profile, key, VM or host SSH configuration is accessed. The container is removed in `finally`.

```powershell
dotnet run --project tests/SSHHardener.IntegrationTests -c Release -- --totp-auth D:\Projects\SSH-Hardener\artifacts\totp-auth-fresh
```

Use a fresh folder; existing private files are never overwritten. Build `AccessPolicyScenario.Dockerfile` first if its image is unavailable.

The runner uses the **production `SshRemoteSessionFactory`, `SftpSessionFactory`, `SshAuthentication` keyboard-interactive callback and `KeyService`**. Actual sshd/PAM must reject a missing second-factor provider, an incorrect TOTP code, replay under `DISALLOW_REUSE`, and a consumed eight-digit recovery code. Correct TOTP/recovery authentication must run `id -un`. Actual SFTP requires the code callback and performs a bounded synthetic transfer in a chroot. Both factories must propagate cancellation of a pending code callback.

The fixture PAM stack uses the same `pam_google_authenticator.so user=root secret=.../${USER}` options as the managed server policy. Its isolated account/session stack and higher attempt-rate allowance keep transport tests independent of production PAM editing and rate-limit behavior. Those are covered separately by `AccessPolicyScenario.*`. Evidence is saved as `result.txt` and sanitized `sshd-fixture.log`. Successful Docker integration is separate from acceptance on a user VM.
