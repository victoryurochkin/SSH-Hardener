#!/bin/sh
set -eu
umask 022
mkdir -p /run/sshd /etc/ssh/fixturekeys
ssh-keygen -A >/dev/null 2>&1
usermod -p '*' root
for user in transport_plain transport_nopass transport_pass; do
    useradd -M -d /tmp -s /bin/sh "$user"
    usermod -p '*' "$user"
done
# Public disposable fixture password goes through stdin, never process arguments.
printf 'transport_pass:Public-Fixture-Sudo-2026!\n' | chpasswd
for user in root transport_plain transport_nopass transport_pass; do
    install -o root -g root -m 0644 /probe/fixture.pub "/etc/ssh/fixturekeys/$user"
done
printf 'transport_nopass ALL=(root) NOPASSWD: ALL\ntransport_pass ALL=(root) PASSWD: ALL\nDefaults:transport_pass timestamp_timeout=0\n' > /etc/sudoers.d/90-framed-fixture
chmod 0440 /etc/sudoers.d/90-framed-fixture
visudo -cf /etc/sudoers.d/90-framed-fixture >/dev/null
cat > /etc/ssh/framed_sshd_config <<'CONFIG'
Port 2222
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/framed-sshd.pid
AuthorizedKeysFile /etc/ssh/fixturekeys/%u
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
UsePAM yes
PermitRootLogin prohibit-password
AllowUsers root transport_plain transport_nopass transport_pass
Subsystem sftp internal-sftp
LogLevel VERBOSE
CONFIG
/usr/sbin/sshd -t -f /etc/ssh/framed_sshd_config
exec /usr/sbin/sshd -D -e -f /etc/ssh/framed_sshd_config
