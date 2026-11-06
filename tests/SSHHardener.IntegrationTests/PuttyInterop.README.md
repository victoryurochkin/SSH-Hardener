# Encrypted PuTTY PPKv3 interoperability

This explicit fixture generates a **new test-only RSA key** in encrypted PKCS#8, exports that same key to encrypted PPKv3 and proves interoperability without touching any user key or production server. Both representations remain encrypted. Child-process arguments contain no passphrase; the public fixture passphrase is supplied directly to the independent tool through redirected stdin, with no password file.

Prepare a fresh empty fixture directory:

```powershell
dotnet run --project tests/SSHHardener.IntegrationTests -c Release -- --prepare-putty D:\Projects\SSH-Hardener\artifacts\putty-interop
```

Build the independent PuTTYgen tool image using the previously built Debian SSH fixture image:

```sh
cd /mnt/d/Projects/SSH-Hardener/tests/SSHHardener.IntegrationTests
docker compose -p sshhardener_integration build debian
docker build -f PuttyInterop.Dockerfile -t sshhardener-putty-interop:local .
```

Run the independent oracle from Windows:

```powershell
dotnet run --project tests/SSHHardener.IntegrationTests -c Release -- --oracle-putty D:\Projects\SSH-Hardener\artifacts\putty-interop
```

The tool container has no network and mounts the encrypted source fixtures read-only. It forces a **private** conversion through actual PuTTYgen into an encrypted OpenSSH key inside the disposable container; exporting only a PPK's public half would not prove private decryption/MAC verification. It verifies the output remains encrypted, compares the public identity exactly and rejects an incorrect passphrase. No plaintext private key is written. Evidence is saved in `tool-output/oracle.txt`.

For real SSH.NET authentication, start an isolated Debian fixture publishing only a loopback port and mounting **only the test public key**:

```sh
docker run -d --rm --name sshhardener-putty-ssh -p 127.0.0.1::22 \
  -v /mnt/d/Projects/SSH-Hardener/artifacts/putty-interop/expected.pub:/fixture.pub:ro \
  sshhardener_integration-debian:latest
docker port sshhardener-putty-ssh 22/tcp
```

Use the assigned port from the previous command:

```powershell
dotnet run --project tests/SSHHardener.IntegrationTests -c Release -- --verify-putty D:\Projects\SSH-Hardener\artifacts\putty-interop 127.0.0.1 <assigned-port>
```

The verifier permits only loopback endpoints. It authenticates with both encrypted representations against unchanged `authorized_keys`, checks the identity and confirms the source file hash remains unchanged. Save any desired container logs, then remove the fixture:

```sh
docker rm -f sshhardener-putty-ssh
```

PuTTYgen 0.78 from Debian 12 independently accepted the application export. Actual import in the user's installed Remote Desktop Manager remains a separate compatibility check. Devolutions documents PPK3 support since 2021.2.13.0 and PPKv3 fixes in 2025.2.14.0/2025.2.16.0; this is not a claim that every SSH engine or older RDM build accepts every format. See [official RDM release notes](https://devolutions.net/remote-desktop-manager/release-notes/) and [PuTTY key format settings](https://the.earth.li/~sgtatham/putty/0.85/htmldoc/Chapter8.html#puttygen-ppkparams).
