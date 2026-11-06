#!/bin/sh
# Disposable container only. Every credential below is public synthetic fixture data.
set -eu
umask 077
mkdir -p /run/sshd /etc/ssh/fixture-authorized-keys /etc/ssh-hardener/totp
chmod 0755 /etc/ssh/fixture-authorized-keys
chmod 0700 /etc/ssh-hardener /etc/ssh-hardener/totp
for user in otp-shell otp-sftp; do
  useradd -m -s /bin/bash "$user"
  printf '%s:%s\n' "$user" 'Public-Test-Only-Account-Password-2026!' | chpasswd
  install -m 0644 /fixture.pub "/etc/ssh/fixture-authorized-keys/$user"
  cat > "/etc/ssh-hardener/totp/$user" <<'SEED'
JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
" TOTP_AUTH
" DISALLOW_REUSE
" WINDOW_SIZE 3
" RATE_LIMIT 100 30
12345678
23456789
34567890
45678901
56789012
67890123
78901234
89012345
SEED
  chmod 0600 "/etc/ssh-hardener/totp/$user"
done
mkdir -p /srv/sshhardener-totp/otp-sftp/uploads
chmod 0755 /srv /srv/sshhardener-totp /srv/sshhardener-totp/otp-sftp
chown otp-sftp:otp-sftp /srv/sshhardener-totp/otp-sftp/uploads
chmod 0700 /srv/sshhardener-totp/otp-sftp/uploads

# Same Google Authenticator module options used by the production managed policy.
# This fixture isolates its auth stack; it does not test production PAM file editing.
cat > /etc/pam.d/sshd <<'PAM'
auth required pam_google_authenticator.so user=root secret=/etc/ssh-hardener/totp/${USER}
account required pam_permit.so
session required pam_permit.so
PAM
chmod 0644 /etc/pam.d/sshd
ssh-keygen -A >/dev/null 2>&1
cat > /etc/ssh/sshd_config <<'CONFIG'
Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
UsePAM yes
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive:pam
AuthorizedKeysFile /etc/ssh/fixture-authorized-keys/%u
PermitRootLogin no
AllowUsers otp-shell otp-sftp
StrictModes yes
MaxAuthTries 3
LoginGraceTime 30
LogLevel VERBOSE
Subsystem sftp internal-sftp
Match User otp-sftp
    ChrootDirectory /srv/sshhardener-totp/otp-sftp
    ForceCommand internal-sftp -d /uploads
    DisableForwarding yes
    PermitTTY no
CONFIG
/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
