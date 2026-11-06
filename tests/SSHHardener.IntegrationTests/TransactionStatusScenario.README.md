# Disposable transaction-status probe

This fixture exercises the exact `TransactionStatusService.ProbeScript` exported from the current source. It runs in a fresh Debian container with `--network none`, no published ports, no additional capabilities, no host socket, and no production credentials. Only the production script and fixture are mounted, read-only. Fixture setup changes only that disposable container's root filesystem.

It checks all stored transaction states, latest-commit matching, missing transaction/base, malformed/oversized data, symlink/owner/mode rejection, an unprivileged session, a real shared/exclusive file-lock conflict and a zero-length root-only runtime lock. A lock conflict must be rejected before reporting absence during arming. This is a real Linux filesystem/probe check; it does not certify timer execution or reboot recovery.

From Windows PowerShell, export the production raw-string constant without reimplementing it:

```powershell
$directory = Join-Path $PWD 'artifacts/recovery-probe'
New-Item -ItemType Directory -Force -Path $directory | Out-Null
$source = Get-Content src/SSHHardener.Profiles/TransactionStatusService.cs -Raw
$match = [regex]::Match($source, '(?s)private const string ProbeScript = """\r?\n(.*?)\r?\n        """;')
if (-not $match.Success) { throw 'Production probe constant was not found.' }
$script = (($match.Groups[1].Value -replace '\r\n', "`n") -split "`n" | ForEach-Object { $_ -replace '^ {8}', '' }) -join "`n"
$script = $script.Replace('@@ID@@', "'20261106120000-abcdef123456'") + "`n"
[IO.File]::WriteAllText((Join-Path $directory 'production-probe.sh'), $script, [Text.UTF8Encoding]::new($false))
```

From WSL Ubuntu, after building the existing Debian integration image:

```sh
docker run --rm --pull=never --network none --entrypoint /bin/sh \
  -e SSH_HARDENER_DISPOSABLE_FIXTURE=yes \
  -v /mnt/d/Projects/SSH-Hardener/artifacts/recovery-probe/production-probe.sh:/probe/production.sh:ro \
  -v /mnt/d/Projects/SSH-Hardener/tests/SSHHardener.IntegrationTests/TransactionStatusScenario.sh:/probe/scenario.sh:ro \
  sshhardener_integration-debian:latest /probe/scenario.sh /probe/production.sh
```

Expected result: every case prints `PASS`, followed by `PASS total=24`. A nonzero shell probe is mapped to `OperationState.Unknown` by the production C# service; only safe, positively observed absence maps to `NotFound`.
