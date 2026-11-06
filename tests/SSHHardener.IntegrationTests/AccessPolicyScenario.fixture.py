"""Disposable root/container test; all credentials below are public fixture data."""
import base64
import hashlib
import hmac
import io
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

import paramiko

BASE = Path('/var/lib/ssh-hardener')
SEED = b'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
CODES = b'12345678\n23456789\n34567890\n45678901\n56789012\n67890123\n78901234\n89012345'
KEY_PATH = Path('/fixture-key')
STAGE = 'bootstrap'


def command(argv, data=None, expect=0):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
    if expect is not None and result.returncode != expect:
        raise AssertionError(f'{STAGE}: command {argv[0]} exit={result.returncode}; {result.stderr.decode(errors="replace")}')
    return result


def check(value, message):
    if not value:
        raise AssertionError(f'{STAGE}: {message}')


def invoke(operation, name, policy='none', access='shell', otp=False, create=True, readonly=False, rules='', data=None, extra='', phase='', expect=0, transaction=None):
    tx = BASE / 'transactions' / (transaction or name)
    tx.mkdir(parents=True, exist_ok=True, mode=0o700)
    return command(['python3', '/probe/access-policy.py', operation, name, str(tx), str(BASE), policy, access,
                    'yes' if readonly else 'no', 'yes' if otp else 'no', 'root', rules,
                    'yes' if create else 'no', 'yes', extra, phase], data, expect)


def credentials(password=b'', otp=False):
    return b'SSHARDENER_ACCESS_V1\n' + b'\n'.join(base64.b64encode(value) for value in
        (password, SEED if otp else b'', CODES if otp else b'')) + b'\n'


def add_user(name):
    command(['useradd', '-m', '-s', '/bin/bash', name])
    directory = Path('/home') / name / '.ssh'
    directory.mkdir(mode=0o700)
    (directory / 'authorized_keys').write_bytes((KEY_PATH.with_suffix('.pub')).read_bytes())
    command(['chown', '-R', name + ':' + name, str(directory)])
    (directory / 'authorized_keys').chmod(0o600)


def activate(name, **options):
    original = BASE / 'transactions' / options.get('transaction', name) / 'sshd_config.original'
    original.write_bytes(Path('/etc/ssh/sshd_config').read_bytes())
    stripped = invoke('base-config', name, extra=str(original), **options).stdout
    candidate = Path('/etc/ssh/candidate')
    candidate.write_bytes(stripped)
    invoke('append-match', name, extra=str(candidate), phase='final', **options)
    command(['/usr/sbin/sshd', '-t', '-f', str(candidate)])
    Path('/etc/ssh/sshd_config').write_bytes(candidate.read_bytes())


def token():
    secret = base64.b32decode(SEED)
    counter = struct.pack('>Q', int(time.time()) // 30)
    value = hmac.new(secret, counter, hashlib.sha1).digest()
    offset = value[-1] & 15
    return str((struct.unpack('>I', value[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)


def connect(name, code=None, expect_auth=True):
    client = socket.create_connection(('127.0.0.1', 2222), timeout=5)
    transport = paramiko.Transport(client)
    transport.auth_timeout = 10
    transport.banner_timeout = 5
    try:
        transport.start_client(timeout=5)
        remaining = transport.auth_publickey(name, paramiko.RSAKey.from_private_key_file(str(KEY_PATH)))
        if code is not None:
            check('keyboard-interactive' in remaining, 'Server did not require key plus keyboard-interactive')
            transport.auth_interactive(name, lambda title, instructions, prompts: [code for _ in prompts])
        if expect_auth:
            check(transport.is_authenticated(), 'Expected authentication was not completed')
        else:
            check(not transport.is_authenticated(), 'Invalid/missing second factor was accepted')
        return transport
    except paramiko.AuthenticationException:
        transport.close()
        if expect_auth:
            raise
        return None
    except Exception:
        transport.close()
        raise


def shadow(name):
    return next(line.split(':')[1] for line in Path('/etc/shadow').read_text().splitlines() if line.startswith(name + ':'))


try:
    BASE.mkdir(mode=0o700)
    (BASE / 'transactions').mkdir(mode=0o700)
    Path('/run/sshd').mkdir(exist_ok=True)
    command(['ssh-keygen', '-A'])
    command(['ssh-keygen', '-q', '-t', 'rsa', '-b', '3072', '-N', '', '-f', str(KEY_PATH)])
    Path('/root/.ssh').mkdir(exist_ok=True, mode=0o700)
    Path('/root/.ssh/authorized_keys').write_bytes(KEY_PATH.with_suffix('.pub').read_bytes())
    Path('/root/.ssh/authorized_keys').chmod(0o600)
    Path('/etc/ssh/sshd_config').write_text('Port 2222\nListenAddress 127.0.0.1\nUsePAM yes\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\nSubsystem sftp internal-sftp\n')

    STAGE = 'SFTP and target-only PAM enrollment'
    options = dict(policy='none', access='sftp-only', otp=True)
    invoke('preflight', 'otpsftp', **options)
    invoke('arm', 'otpsftp', **options)
    add_user('otpsftp')
    invoke('provision', 'otpsftp', data=credentials(otp=True), **options)
    invoke('configure', 'otpsftp', **options)
    activate('otpsftp', **options)
    invoke('verify', 'otpsftp', **options)
    daemon = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e'], stdout=open('/probe/sshd.log', 'wb'), stderr=subprocess.STDOUT)
    time.sleep(0.3)
    transport = connect('root')
    transport.close()
    transport = connect('otpsftp', expect_auth=False)
    if transport: transport.close()
    valid_code = token()
    transport = connect('otpsftp', valid_code)
    sftp = paramiko.SFTPClient.from_transport(transport)
    check(sftp.normalize('.') == '/uploads', 'SFTP did not start in its chroot uploads directory')
    sftp.putfo(io.BytesIO(b'fixture payload'), 'roundtrip.txt')
    with sftp.open('roundtrip.txt', 'rb') as handle: check(handle.read() == b'fixture payload', 'SFTP data roundtrip failed')
    try:
        sftp.stat('/etc/shadow')
        raise AssertionError('Chroot escape exposed /etc/shadow')
    except IOError:
        pass
    sftp.remove('roundtrip.txt')
    sftp.close(); transport.close()
    failed = connect('otpsftp', valid_code, expect_auth=False)
    if failed: failed.close()
    failed = connect('otpsftp', '000000', expect_auth=False)
    if failed: failed.close()
    print('PASS actual key+TOTP PAM/SFTP login, chroot/write/read/delete, replay and wrong-code denial; original root key-only login preserved', flush=True)

    STAGE = 'recovery-code consumption'
    time.sleep(31)
    transport = connect('otpsftp', '12345678')
    transport.close()
    check(b'12345678' not in Path('/etc/ssh-hardener/totp/otpsftp').read_bytes(), 'Recovery code was not consumed')
    failed = connect('otpsftp', '12345678', expect_auth=False)
    if failed: failed.close()
    invoke('verify', 'otpsftp', **options)
    print('PASS actual one-time recovery-code login, consumed-code rejection and mutable PAM-state verification', flush=True)

    STAGE = 'read-only SFTP and preservation of another managed profile'
    ro_options = dict(policy='none', access='sftp-only', readonly=True)
    invoke('preflight', 'readonlysftp', **ro_options)
    invoke('arm', 'readonlysftp', **ro_options)
    add_user('readonlysftp')
    invoke('provision', 'readonlysftp', data=credentials(), **ro_options)
    invoke('configure', 'readonlysftp', **ro_options)
    activate('readonlysftp', **ro_options)
    daemon.send_signal(1)
    time.sleep(0.3)
    transport = connect('readonlysftp')
    sftp = paramiko.SFTPClient.from_transport(transport)
    check(sftp.normalize('.') == '/uploads', 'Read-only SFTP working directory is wrong')
    try:
        sftp.putfo(io.BytesIO(b'must be denied'), 'forbidden.txt')
        raise AssertionError('Read-only SFTP accepted an upload')
    except IOError:
        pass
    sftp.close(); transport.close()
    check(Path('/etc/ssh/sshd_config').read_text().count('AuthenticationMethods publickey,keyboard-interactive:pam') == 1, 'Configuring another account lost the earlier MFA policy')
    print('PASS actual read-only SFTP upload denial and preservation of the existing independent MFA profile', flush=True)

    STAGE = 'existing SFTP reapply is rejected without resetting its MFA state'
    preserved_secret = Path('/etc/ssh-hardener/totp/otpsftp').read_bytes()
    preserved_pam = Path('/etc/pam.d/sshd').read_bytes()
    preserve_options = dict(policy='none', access='sftp-only', create=False, transaction='preserve-mfa')
    rejected = invoke('preflight', 'otpsftp', expect=None, **preserve_options)
    check(rejected.returncode != 0 and b'Existing managed SFTP accounts require a separate reviewed transition' in rejected.stderr,
          'Existing SFTP reapply was not rejected explicitly')
    check(not (BASE / 'transactions/preserve-mfa/access/armed').exists(), 'Rejected SFTP transition armed a transaction')
    check(Path('/etc/ssh-hardener/totp/otpsftp').read_bytes() == preserved_secret and Path('/etc/pam.d/sshd').read_bytes() == preserved_pam,
          'Rejected SFTP reapply changed the existing secret, consumed codes or PAM stack')
    print('PASS existing SFTP reapply rejected before arm while prior MFA, consumed-code state and PAM stack remain unchanged', flush=True)

    STAGE = 'structured restricted sudo and adversarial service policy'
    unit = Path('/etc/systemd/system/fixture-policy.service')
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text('[Service]\nExecStart=/usr/bin/true\n')
    unit.chmod(0o644)
    # Only unit metadata acquisition is stubbed: real sudoers parsing and policy checks remain real.
    service_query = Path('/usr/local/bin/systemctl')
    service_query.write_text('#!/bin/sh\n[ "$1" = show ] || exit 2\nprintf "%s\\n" "FragmentPath=/etc/systemd/system/fixture-policy.service" "ExecStart={ path=/usr/bin/true ; }"\n')
    service_query.chmod(0o755)
    rules = '/usr/bin/systemctl\tis-active fixture-policy.service\n/usr/bin/systemctl\t--no-pager --full status fixture-policy.service\n/usr/bin/systemctl\trestart fixture-policy.service'
    restricted_options = dict(policy='restricted', rules=rules)
    unit.chmod(0o666)
    check(invoke('preflight', 'restricteduser', expect=None, **restricted_options).returncode != 0, 'Writable unit accepted for privileged restart')
    unit.chmod(0o644)
    attack_rules = '/usr/bin/systemctl\trestart fixture-policy.service; touch /root/should-not-exist'
    check(invoke('preflight', 'restricteduser', policy='restricted', rules=attack_rules, expect=None).returncode != 0, 'Shell injection was accepted in structured sudo rules')
    check(not Path('/root/should-not-exist').exists(), 'Restricted rule parser executed shell input')
    invoke('preflight', 'restricteduser', **restricted_options)
    invoke('arm', 'restricteduser', **restricted_options)
    add_user('restricteduser')
    invoke('provision', 'restricteduser', data=credentials(), **restricted_options)
    invoke('configure', 'restricteduser', **restricted_options)
    with open('/probe/restricted-sudo-check.txt', 'w') as diagnostic:
        diagnostic.write(Path('/etc/sudoers.d/90-sshhardener-access-restricteduser').read_text())
        for entry in rules.splitlines():
            executable, arguments = entry.split('\t')
            probe_result = command(['sudo', '-l', '-U', 'restricteduser', '--', executable] + arguments.split(), expect=None)
            diagnostic.write(arguments + ' exit=' + str(probe_result.returncode) + '\n' + probe_result.stdout.decode() + probe_result.stderr.decode())
    invoke('verify', 'restricteduser', **restricted_options)
    check(command(['runuser', '-u', 'restricteduser', '--', 'sudo', '-k', '-n', '--', '/bin/sh', '-c', 'exit 0'], expect=None).returncode != 0, 'Restricted target obtained a root shell')
    owned_sudo = Path('/etc/sudoers.d/90-sshhardener-access-restricteduser')
    applied_sudo = owned_sudo.read_bytes()
    owned_sudo.write_bytes(applied_sudo + b'# administrator concurrent change\n')
    check(invoke('rollback', 'restricteduser', expect=None, **restricted_options).returncode != 0 and b'concurrent change' in owned_sudo.read_bytes(), 'Concurrent sudo policy was overwritten')
    owned_sudo.write_bytes(applied_sudo)
    invoke('rollback', 'restricteduser', **restricted_options)
    check(not owned_sudo.exists(), 'Owned restricted sudo grant survived rollback')
    add_user('fulladmin')
    foreign_sudo = Path('/etc/sudoers.d/fixture-full-admin')
    foreign_sudo.write_text('fulladmin ALL=(ALL:ALL) NOPASSWD: ALL\n')
    foreign_sudo.chmod(0o440)
    check(invoke('preflight', 'fulladmin', create=False, policy='restricted', rules=rules, expect=None).returncode != 0, 'Existing full administrator was advertised as restricted')
    check(foreign_sudo.exists(), 'Preflight changed foreign sudo grants')
    print('PASS real visudo/exact sudo list allowlist, root-shell denial, writable-unit/injection/full-admin rejection and concurrent sudo conflict preservation; systemctl metadata only is stubbed', flush=True)

    STAGE = 'existing-account password sudo without hash reset'
    add_user('passworduser')
    command(['chpasswd'], b'passworduser:PublicFixturePassword42!\n')
    before_hash = shadow('passworduser')
    password_options = dict(policy='password', create=False)
    invoke('preflight', 'passworduser', **password_options)
    invoke('arm', 'passworduser', **password_options)
    bad = invoke('provision', 'passworduser', data=credentials(b'WrongFixturePassword'), expect=None, **password_options)
    check(bad.returncode != 0 and shadow('passworduser') == before_hash, 'A wrong existing password was accepted or reset')
    invoke('provision', 'passworduser', data=credentials(b'PublicFixturePassword42!'), **password_options)
    invoke('configure', 'passworduser', **password_options)
    check(shadow('passworduser') == before_hash, 'Existing password hash changed')
    invoke('rollback', 'passworduser', **password_options)
    check(shadow('passworduser') == before_hash, 'Rollback changed an existing password hash')
    print('PASS existing password validated through actual libcrypt and password-required sudo, wrong password rejected, hash preserved through rollback', flush=True)

    STAGE = 'owned new password locking and concurrent password preservation'
    new_options = dict(policy='password')
    invoke('preflight', 'newpassword', **new_options)
    invoke('arm', 'newpassword', **new_options)
    add_user('newpassword')
    invoke('provision', 'newpassword', data=credentials(b'AnotherPublicFixturePassword42!'), **new_options)
    invoke('configure', 'newpassword', **new_options)
    check(not shadow('newpassword').startswith('!'), 'New password was not installed')
    invoke('rollback', 'newpassword', **new_options)
    check(shadow('newpassword').startswith('!'), 'Owned new password was not locked on rollback')
    print('PASS new account password installed via stdin and locked only during its own rollback', flush=True)

    STAGE = 'foreign policy conflict preservation'
    original = Path('/etc/ssh/sshd_config').read_bytes()
    Path('/etc/ssh/sshd_config').write_bytes(original + b'\nMatch User outsider\n    PermitTTY no\n')
    check(invoke('preflight', 'blockeduser', expect=None).returncode != 0, 'Foreign Match was accepted')
    Path('/etc/ssh/sshd_config').write_bytes(original)
    secret_path = Path('/etc/ssh-hardener/totp/otpsftp')
    consumed_state = secret_path.read_bytes()
    secret_path.write_bytes(consumed_state.replace(SEED, b'A' * len(SEED), 1))
    result = invoke('rollback', 'otpsftp', expect=None, **options)
    check(result.returncode != 0 and secret_path.read_bytes() != consumed_state, 'Foreign secret rotation was overwritten')
    secret_path.write_bytes(consumed_state)
    # The first conflict may already have restored independent files. Retry must complete safely.
    invoke('rollback', 'otpsftp', **options)
    check(not secret_path.exists(), 'Owned TOTP secret survived rollback')
    check('user=readonlysftp BEGIN' in Path('/etc/ssh/sshd_config').read_text(), 'Fixture lost the independent SSH profile')
    print('PASS foreign Match rejection, foreign TOTP rotation preserved, retry restores only owned enrollment', flush=True)
    daemon.terminate(); daemon.wait(timeout=5)
    print('PASS disposable advanced access scenario; no host network, published ports, user keys or VM used', flush=True)
except Exception:
    print('FAIL at stage: ' + STAGE, flush=True)
    path = Path('/etc/ssh-hardener/totp/otpsftp')
    if path.exists():
        Path('/probe/totp-state-options.txt').write_text('mode=' + oct(path.stat().st_mode & 0o777) + '\n' + '\n'.join(line for line in path.read_text().splitlines() if line.startswith('"')) + '\n')
    raise
