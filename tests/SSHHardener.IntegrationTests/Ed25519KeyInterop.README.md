# Encrypted Ed25519 interoperability

This explicit, synthetic-only fixture creates two new Ed25519 identities: an encrypted PuTTY PPK v3 and an encrypted RFC 8410 PKCS#8. It exports both to same-key PPK v3, checks independent private decryption and MAC verification in PuTTYgen, and can authenticate all four encrypted files using the real application SSH transport. It never reads a user key or connects to a user VM.

Use a fresh, empty directory. From the repository root:

```powershell
dotnet run --project tests/SSHHardener.IntegrationTests -c Release -- --prepare-ed25519 D:\Projects\SSH-Hardener\artifacts\ed25519-interop
dotnet run --project tests/SSHHardener.IntegrationTests -c Release -- --oracle-ed25519 D:\Projects\SSH-Hardener\artifacts\ed25519-interop
```

The oracle uses the existing `sshhardener-putty-interop:local` image; build it with [PuttyInterop.Dockerfile](PuttyInterop.Dockerfile) if needed. Docker runs with `--network none`, mounts source fixtures read-only, and receives the public fixture passphrase over stdin. PuTTYgen must decrypt and MAC-verify each PPK to re-export an encrypted OpenSSH private key. The script validates encryption, compares the exact public identity, and rejects an incorrect passphrase plus a modified MAC-covered comment. Private OpenSSH exports exist only, encrypted, in the disposable container. Evidence is written under `tool-output`.

For actual SSH.NET authentication, start a disposable Debian SSH fixture with only the test public keys and a loopback port:

```sh
docker run -d --rm --name sshhardener-ed25519-ssh -p 127.0.0.1::22 \
  -v /mnt/d/Projects/SSH-Hardener/artifacts/ed25519-interop/expected.pub:/fixture.pub:ro \
  sshhardener_integration-debian:latest
docker port sshhardener-ed25519-ssh 22/tcp
```

Use the assigned port:

```powershell
dotnet run --project tests/SSHHardener.IntegrationTests -c Release -- --verify-ed25519 D:\Projects\SSH-Hardener\artifacts\ed25519-interop 127.0.0.1 <assigned-port>
```

The verifier rejects non-loopback endpoints, pins the first fixture host key for subsequent connections, authenticates with each encrypted file against unchanged `authorized_keys`, and checks source hashes. Remove only the named disposable fixture when done:

```sh
docker rm -f sshhardener-ed25519-ssh
```

Relevant primary sources: [PuTTY PPK v3 envelope](https://the.earth.li/~sgtatham/putty/0.85/htmldoc/AppendixC.html), [RFC 8410 Ed25519 private key encoding](https://www.rfc-editor.org/rfc/rfc8410#section-7), and [SSH.NET 2026 PuTTY parser](https://github.com/sshnet/SSH.NET/blob/2026.0.0/src/Renci.SshNet/PrivateKeyFile.PuTTY.cs). PuTTY's current prose calls Ed25519 private data an `mpint`, but its actual PPK encoding is a length-prefixed, fixed 32-byte seed. The application's independent PuTTYgen test is intentional coverage of that distinction. A successful fixture is separate from an actual import in the user's installed Remote Desktop Manager.
