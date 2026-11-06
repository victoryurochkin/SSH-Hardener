# Existing account policy preservation

```powershell
pwsh -File tests/SSHHardener.IntegrationTests/OwnedAccessPolicyPreservation.run.ps1
```

This focused acceptance exports the **current production Python helper directly from its
C# raw-string source**, requiring no .NET build. It runs only inside a disposable Debian
container from `sshhardener-access-policy:local`, with `--network none`, two read-only
fixture mounts, no published ports, no additional capabilities and no user VM/keys.

It uses real account files, ownership proofs and `sshd -t/-T` to demonstrate:

- A pre-existing managed MFA fragment remains effective during the dual phase, using the
  verified arm-time snapshot, even while a new SFTP restriction is staged for final activation.
- Leaving MFA enrollment unchecked preserves the seed, consumed recovery codes, replay/rate
  timestamps and PAM's mode0400 rewrite, including across rollback after arm-time consumption.
- Existing MFA re-enrollment/reset and repeat/transition of an existing SFTP target fail
  read-only before arming, preserving all policy hashes and modes. These transitions require
  a separate reviewed implementation instead of temporarily dropping authentication/chroot.
- A brand-new target policy waits until final while other owned account fragments remain;
  rollback removes only its own first-enrollment file after legitimate mutable state updates.

The source helper and results remain under the ignored repository artifacts directory. The
container is removed by `--rm`. All synthetic seeds/recovery codes in this fixture are public
test values, never user authentication material. These are helper/configuration acceptance
checks; independent SSH.NET/SFTP and TOTP login fixtures cover actual network authentication.
