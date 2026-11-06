# Real SSH transport tests

These disposable fixtures contain **public test credentials** and bind only to loopback. Never deploy them on an internet-facing server. They do not certify systemd, firewall, SELinux or reboot recovery.

From the repository root on Windows:

```powershell
dotnet run --project tests/SSHHardener.IntegrationTests -- --prepare D:\Projects\SSH-Hardener\artifacts\integration
wsl -d Ubuntu --cd /mnt/d/Projects/SSH-Hardener/tests/SSHHardener.IntegrationTests --exec docker compose -p sshhardener_integration up -d --build --force-recreate
dotnet run --project tests/SSHHardener.IntegrationTests -- D:\Projects\SSH-Hardener\artifacts\integration
wsl -d Ubuntu --cd /mnt/d/Projects/SSH-Hardener/tests/SSHHardener.IntegrationTests --exec docker compose -p sshhardener_integration down --volumes
```

Adjust absolute paths to the checkout. Docker Desktop users can run `docker compose -f tests/SSHHardener.IntegrationTests/compose.yml -p sshhardener_integration ...` directly. The runner exits nonzero if any OS fixture or scenario fails. A fresh local trust directory is used on each run because the fixtures generate disposable host identities.

The provisioning scenario executes the generated user/key/sudo and rollback scripts against the container filesystem. Only the systemd service probe is mocked; account creation, permissions, key login and removal of access are real. This is not a systemd, firewall or reboot acceptance test. Recreate the disposable containers before repeating the runner because rollback intentionally retains newly created accounts and their files.
