#!/bin/sh
set -eu
umask 077
IFS= read -r fixture_passphrase
[ -n "$fixture_passphrase" ]
puttygen --version

for name in generated exported pkcs8-exported; do
  [ "$(sed -n '1p' "/probe/$name.ppk")" = 'PuTTY-User-Key-File-3: ssh-ed25519' ]
  [ "$(sed -n '2p' "/probe/$name.ppk")" = 'Encryption: aes256-cbc' ]

  # A public export alone does not decrypt the PPK or validate its MAC.
  # Force an independently decrypted private export which remains encrypted.
  printf '%s\n' "$fixture_passphrase" | puttygen "/probe/$name.ppk" --old-passphrase /dev/stdin -O private-openssh-new -o "/tmp/$name.openssh"
  python3 - "$name" <<'PY'
import base64, struct, sys
name = sys.argv[1]
with open('/tmp/' + name + '.openssh', encoding='ascii') as source:
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
print('PASS: independent PuTTYgen decrypted/MAC-verified ' + name + ' and retained OpenSSH encryption.')
PY
  printf '%s\n' "$fixture_passphrase" | puttygen "/tmp/$name.openssh" --old-passphrase /dev/stdin -O public-openssh -o "/out/$name.pub"
  case "$name" in pkcs8-exported) expected_file=/probe/expected-pkcs8.pub;; *) expected_file=/probe/expected-generated.pub;; esac
  expected=$(awk '{print $1" "$2}' "$expected_file")
  actual=$(awk '{print $1" "$2}' "/out/$name.pub")
  [ "$expected" = "$actual" ]
  printf 'PASS: private conversion preserved %s Ed25519 public identity.\n' "$name"

  if printf 'deliberately-wrong-public-fixture-passphrase\n' | puttygen "/probe/$name.ppk" --old-passphrase /dev/stdin -O private-openssh-new -o "/tmp/$name.wrong.openssh"; then
    printf 'FAIL: independent PuTTYgen accepted an incorrect passphrase.\n' >&2
    exit 1
  fi
  [ ! -e "/tmp/$name.wrong.openssh" ]

  sed 's/^Comment: .*/Comment: tampered-public-fixture-comment/' "/probe/$name.ppk" > "/tmp/$name.tampered.ppk"
  if printf '%s\n' "$fixture_passphrase" | puttygen "/tmp/$name.tampered.ppk" --old-passphrase /dev/stdin -O private-openssh-new -o "/tmp/$name.tampered.openssh"; then
    printf 'FAIL: independent PuTTYgen accepted a modified MAC-covered comment.\n' >&2
    exit 1
  fi
  [ ! -e "/tmp/$name.tampered.openssh" ]
  printf 'PASS: independent PuTTYgen rejects incorrect passphrase and comment tampering for %s.\n' "$name"
done
