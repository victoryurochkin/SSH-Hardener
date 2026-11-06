#!/bin/sh
set -eu
umask 022
mkdir -p /run/sshd /etc/ssh/fixturekeys
ssh-keygen -A >/dev/null 2>&1
for user in sftp_rw sftp_ro; do
    useradd -M -d /uploads -s /usr/sbin/nologin "$user"
    usermod -p '*' "$user"
    install -o root -g root -m 0644 /probe/fixture.pub "/etc/ssh/fixturekeys/$user"
    base="/srv/ssh-hardener/sftp/$user"
    mkdir -p "$base/uploads/real-folder"
    chown root:root "$base"
    chmod 0755 "$base"
    chown -R "$user:$user" "$base/uploads"
    chmod 0700 "$base/uploads"
    printf 'public seed contents\n' > "$base/uploads/seed.txt"
    chown "$user:$user" "$base/uploads/seed.txt"
    ln -s seed.txt "$base/uploads/file-link"
    ln -s real-folder "$base/uploads/folder-link"
    ln -s missing-target "$base/uploads/dangling-link"
done
cat > /etc/ssh/fixture_sshd_config <<'CONFIG'
Port 2222
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/sshd-fixture.pid
AuthorizedKeysFile /etc/ssh/fixturekeys/%u
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
UsePAM yes
PermitRootLogin no
AllowUsers sftp_rw sftp_ro
Subsystem sftp internal-sftp
LogLevel VERBOSE
Match User sftp_rw
    ChrootDirectory /srv/ssh-hardener/sftp/sftp_rw
    ForceCommand internal-sftp -d /uploads
    DisableForwarding yes
Match User sftp_ro
    ChrootDirectory /srv/ssh-hardener/sftp/sftp_ro
    ForceCommand internal-sftp -R -d /uploads
    DisableForwarding yes
CONFIG
/usr/sbin/sshd -t -f /etc/ssh/fixture_sshd_config
exec /usr/sbin/sshd -D -e -f /etc/ssh/fixture_sshd_config
