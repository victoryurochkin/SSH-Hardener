set -eu
for fixture_user in testadmin passwordsudo; do
  useradd -m -s /bin/bash "$fixture_user"
  printf '%s:TestOnly-SSHHardener-2026!\n' "$fixture_user" | chpasswd
done
printf 'testadmin ALL=(ALL:ALL) NOPASSWD: ALL\npasswordsudo ALL=(ALL:ALL) ALL\n' > /etc/sudoers.d/90-integration-fixture
chmod 0440 /etc/sudoers.d/90-integration-fixture
visudo -cf /etc/sudoers.d/90-integration-fixture
mkdir -p /run/sshd
ssh-keygen -A
cat > /etc/ssh/sshd_config <<'EOF'
Port 22
ListenAddress 0.0.0.0
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM yes
AuthorizedKeysFile .ssh/authorized_keys
PidFile /run/sshd.pid
Subsystem sftp internal-sftp
EOF
