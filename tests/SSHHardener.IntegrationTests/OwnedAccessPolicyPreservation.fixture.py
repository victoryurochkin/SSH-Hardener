"""Actual production helper in a disposable rootfs; no network, user VM or user credentials."""
import base64
import hashlib
import os
from pathlib import Path
import subprocess

BASE = Path('/var/lib/ssh-hardener')
SEED = b'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
CODES = [b'12345678', b'23456789', b'34567890', b'45678901', b'56789012', b'67890123', b'78901234', b'89012345']


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def command(argv, data=None, success=True):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if success:
        check(result.returncode == 0, 'Fixture operation failed: ' + result.stderr.decode(errors='replace'))
    return result


def invoke(mode, user, transaction, *, access='shell', totp=False, create=False, enabled=True, sudo_mode='none', extra='', phase='', data=None, success=True):
    tx = BASE / 'transactions' / transaction
    tx.mkdir(mode=0o700, parents=True, exist_ok=True)
    return command(['python3', '/probe/access-policy.py', mode, user, str(tx), str(BASE), sudo_mode, access, 'no',
                    'yes' if totp else 'no', 'root', '', 'yes' if create else 'no', 'yes' if enabled else 'no', extra, phase], data, success)


def sensitive(totp=False):
    return b'SSHARDENER_ACCESS_V1\n' + b'\n'.join(base64.b64encode(value) for value in
        (b'', SEED if totp else b'', b'\n'.join(CODES) if totp else b'')) + b'\n'


def snapshot():
    files = [Path('/etc/ssh/sshd_config'), Path('/etc/pam.d/sshd')]
    for directory in (BASE / 'access-policy', Path('/etc/ssh-hardener/totp')):
        if directory.exists():
            files.extend(path for path in directory.iterdir() if path.is_file())
    return {str(path): (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mode) for path in files}


def prepare(user, transaction, *, access='shell', totp=False):
    command(['useradd', '-M', '-s', '/bin/sh', user])
    options = dict(access=access, totp=totp, create=True)
    invoke('preflight', user, transaction, **options)
    original = BASE / 'transactions' / transaction / 'sshd_config.original'
    original.write_bytes(Path('/etc/ssh/sshd_config').read_bytes()); original.chmod(0o600)
    invoke('arm', user, transaction, **options)
    invoke('provision', user, transaction, data=sensitive(totp), **options)
    invoke('configure', user, transaction, **options)
    return options


def candidate(user, transaction, phase, **options):
    original = BASE / 'transactions' / transaction / 'sshd_config.original'
    stripped = invoke('base-config', user, transaction, extra=str(original), **options).stdout
    path = BASE / 'transactions' / transaction / ('candidate-' + phase)
    path.write_bytes(stripped); path.chmod(0o600)
    invoke('append-match', user, transaction, extra=str(path), phase=phase, **options)
    command(['/usr/sbin/sshd', '-t', '-f', str(path)])
    effective = command(['/usr/sbin/sshd', '-T', '-f', str(path), '-C', 'user=' + user + ',host=localhost,addr=127.0.0.1']).stdout.decode()
    values = dict(line.split(' ', 1) for line in effective.splitlines() if ' ' in line)
    return path, values


BASE.mkdir(mode=0o700)
(BASE / 'transactions').mkdir(mode=0o700)
Path('/run/sshd').mkdir(exist_ok=True)
command(['ssh-keygen', '-A'])
Path('/etc/ssh/sshd_config').write_text('Port 2222\nUsePAM yes\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\nSubsystem sftp internal-sftp\n')

user = 'owned_mfa'
initial = prepare(user, 'first-mfa', totp=True)
first, policy = candidate(user, 'first-mfa', 'final', **initial)
check(policy['authenticationmethods'] == 'publickey,keyboard-interactive:pam', 'Initial MFA policy missing')
Path('/etc/ssh/sshd_config').write_bytes(first.read_bytes())
secret = Path('/etc/ssh-hardener/totp') / user

# Re-enrollment with the old seed and original recovery codes would reset consumed/replay state.
# It must be blocked before arming or reading any fresh credential payload.
before = snapshot()
blocked = invoke('preflight', user, 'blocked-reenrollment', totp=True, success=False)
check(blocked.returncode != 0 and b'Existing managed TOTP enrollment is preserved' in blocked.stderr, 'Re-enrollment was not explicitly blocked')
check(snapshot() == before, 'Rejected re-enrollment changed policy files')
check(not (BASE / 'transactions/blocked-reenrollment/access/armed').exists(), 'Rejected re-enrollment was armed')
print('PASS: existing TOTP re-enrollment/reset rejected read-only before arm; all policy hashes and modes unchanged')

tx = 'preserve-mfa-to-sftp'
options = dict(access='sftp-only', totp=False, create=False)
invoke('preflight', user, tx, **options)
original = BASE / 'transactions' / tx / 'sshd_config.original'
original.write_bytes(Path('/etc/ssh/sshd_config').read_bytes()); original.chmod(0o600)
invoke('arm', user, tx, **options)
baseline = (BASE / 'transactions' / tx / 'access/fragment.original').read_bytes()
# Model successful Google PAM changes AFTER the arm-time snapshot: one recovery code consumed,
# replay/rate counters updated, file rewritten as mode0400. These state changes must survive rollback.
mutable = secret.read_bytes().replace(CODES[0] + b'\n', b'').replace(b'" DISALLOW_REUSE\n', b'" DISALLOW_REUSE 12345678\n')
mutable = mutable.replace(b'" RATE_LIMIT 3 30\n', b'" RATE_LIMIT 3 30 12345679\n')
secret.write_bytes(mutable); secret.chmod(0o400)
invoke('provision', user, tx, data=sensitive(False), **options)
invoke('configure', user, tx, **options)
check(secret.read_bytes() == mutable and secret.stat().st_mode & 0o777 == 0o400, 'Preserving enrollment changed mutable secret state')
dual, effective = candidate(user, tx, 'dual', **options)
check(baseline in dual.read_bytes(), 'Dual phase did not append the original target fragment')
check(effective['authenticationmethods'] == 'publickey,keyboard-interactive:pam' and effective['kbdinteractiveauthentication'] == 'yes', 'Dual phase bypassed existing MFA')
check(effective['forcecommand'] == 'none', 'New SFTP policy activated before final verification')
print('PASS: existing MFA remains required in dual phase using the verified original fragment; new SFTP restrictions wait until final')
final, effective = candidate(user, tx, 'final', **options)
check(effective['authenticationmethods'] == 'publickey,keyboard-interactive:pam' and effective['forcecommand'] == 'internal-sftp -d /uploads', 'Final preserved-MFA/SFTP policy mismatch')
print('PASS: final policy combines preserved MFA with the newly requested SFTP restriction')
invoke('rollback', user, tx, **options)
check(secret.read_bytes() == mutable and secret.stat().st_mode & 0o777 == 0o400, 'Rollback revived consumed recovery codes or replay state')
check((BASE / 'access-policy' / (user + '.match')).read_bytes() == baseline, 'Rollback did not restore original MFA fragment')
print('PASS: rollback leaves existing enrollment, consumed recovery code, replay/rate counters and0400 mode intact')

sftp_user = 'owned_sftp'
sftp_options = prepare(sftp_user, 'first-sftp', access='sftp-only')
sftp_final, effective = candidate(sftp_user, 'first-sftp', 'final', **sftp_options)
Path('/etc/ssh/sshd_config').write_bytes(sftp_final.read_bytes())
for access, enabled, sudo_mode in (('shell', True, 'none'), ('sftp-only', True, 'none'), ('shell', False, 'legacy')):
    before = snapshot()
    blocked = invoke('preflight', sftp_user, 'blocked-sftp-' + access + str(enabled), access=access, enabled=enabled, sudo_mode=sudo_mode, success=False)
    check(blocked.returncode != 0 and b'Existing managed SFTP accounts require a separate reviewed transition' in blocked.stderr, 'Existing SFTP transition was not explicitly blocked')
    check(snapshot() == before, 'Rejected SFTP transition changed policy files')
print('PASS: existing SFTP repeat/transition including Legacy/no-advanced rejected read-only before arm, without a transient shell or chroot bypass')

new_user = 'fresh_mfa'
new_options = prepare(new_user, 'fresh-mfa', totp=True)
dual, effective = candidate(new_user, 'fresh-mfa', 'dual', **new_options)
check(('Match User ' + new_user).encode() not in dual.read_bytes(), 'New MFA policy activated before key verification')
check(('Match User ' + user).encode() in dual.read_bytes() and ('Match User ' + sftp_user).encode() in dual.read_bytes(), 'Other owned account policies disappeared')
print('PASS: a brand-new target policy waits until final while other owned MFA/SFTP account fragments remain present')
new_secret = Path('/etc/ssh-hardener/totp') / new_user
new_secret.write_bytes(new_secret.read_bytes().replace(CODES[0] + b'\n', b'')); new_secret.chmod(0o400)
invoke('rollback', new_user, 'fresh-mfa', **new_options)
check(not new_secret.exists(), 'Rollback retained its own newly created enrollment')
print('PASS: first-enrollment rollback removes only its own new enrollment after legitimate mutable state changes')
