#!/bin/sh
set -eu
umask 077
IFS= read -r fixture_passphrase
[ -n "$fixture_passphrase" ]
puttygen --version
head -n 2 /probe/exported.ppk | grep -E '^(PuTTY-User-Key-File-3: ssh-rsa|Encryption: aes256-cbc)$'

# Exporting only the public half of a PPK does not prove successful private-key
# decryption/MAC verification. Force a real private conversion, retaining encryption.
printf '%s\n' "$fixture_passphrase" | puttygen /probe/exported.ppk --old-passphrase /dev/stdin -O private-openssh-new -o /tmp/reexported.openssh
python3 - <<'PY'
import base64, struct
with open('/tmp/reexported.openssh', encoding='ascii') as source:
    data = base64.b64decode(''.join(line for line in source if not line.startswith('-----')))
magic = b'openssh-key-v1\0'
assert data.startswith(magic)
offset = len(magic)
size, = struct.unpack_from('>I', data, offset)
cipher = data[offset + 4:offset + 4 + size]
offset += 4 + size
size, = struct.unpack_from('>I', data, offset)
kdf = data[offset + 4:offset + 4 + size]
assert cipher != b'none' and kdf != b'none'
print('PASS: independent PuTTYgen decrypted/MAC-verified PPK and re-exported an encrypted OpenSSH private key.')
PY
printf '%s\n' "$fixture_passphrase" | puttygen /tmp/reexported.openssh --old-passphrase /dev/stdin -O public-openssh -o /out/puttygen.pub
expected=$(awk '{print $1" "$2}' /probe/expected.pub)
actual=$(awk '{print $1" "$2}' /out/puttygen.pub)
[ "$expected" = "$actual" ]
puttygen /out/puttygen.pub -l -E sha256 > /out/fingerprint.txt
printf 'PASS: independent public key matches the source RSA identity exactly.\n'
if printf 'deliberately-incorrect-public-fixture-passphrase\n' | puttygen /probe/exported.ppk --old-passphrase /dev/stdin -O private-openssh-new -o /tmp/wrong-pass.openssh; then
  printf 'FAIL: independent PuTTYgen accepted an incorrect passphrase.\n' >&2
  exit 1
fi
[ ! -e /tmp/wrong-pass.openssh ]
printf 'PASS: independent PuTTYgen rejects the incorrect passphrase.\n'
