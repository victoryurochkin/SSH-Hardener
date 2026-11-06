set -eu
for fixture_user in testadmin passwordsudo; do
  install -d -m 0700 -o "$fixture_user" -g "$fixture_user" "/home/$fixture_user/.ssh"
  install -m 0600 -o "$fixture_user" -g "$fixture_user" /fixture.pub "/home/$fixture_user/.ssh/authorized_keys"
done
exec /usr/sbin/sshd -D -e
