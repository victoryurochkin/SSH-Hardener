namespace SSHHardener.Profiles;

internal static partial class Scripts
{
    // These helpers deliberately receive credentials only through the sensitive step's stdin.
    // Match blocks are appended to the END of the main configuration, never to an Include.
    internal const string AccessPolicyFunctions = """
        access_policy_run() {
          python3 -c "$(cat <<'SSHARDENER_ACCESS_PY'
        """ + "\n" + AccessPolicyPython + "\n" + """

        SSHARDENER_ACCESS_PY
          )" "$1" "$user" "$tx" "$base" "${sudo_mode:-legacy}" "${account_access:-shell}" "${sftp_readonly:-no}" "${use_totp:-no}" "${control_user:-}" "${restricted_commands:-}" "${create_user:-no}" "${access_policy_enabled:-no}" "${2:-}" "${3:-}"
        }
        access_policy_needed() {
          [ "${access_policy_enabled:-no}" = yes ] || [ -d "$base/access-policy" ]
        }
        access_policy_base_config() {
          if access_policy_needed; then access_policy_run base-config "$1"; else cat "$1"; fi
        }
        access_policy_append_match() {
          if access_policy_needed; then access_policy_run append-match "$1" "$2"; fi
        }
        access_policy_target_totp() {
          if access_policy_needed; then access_policy_run target-totp; else printf 'no\n'; fi
        }

        """;

    internal const string AccessPolicyPreflightBody = """
        if [ "${access_policy_enabled:-no}" = yes ] || [ -d "$base/access-policy" ]; then
          command -v python3 >/dev/null 2>&1 || fail 'Advanced access policies require preinstalled Python 3.'
          access_policy_run preflight || fail 'Advanced access policy preflight failed; no policy was changed.'
        fi
        if [ "${use_totp:-no}" = yes ] && ! find /lib /usr/lib -name pam_google_authenticator.so -type f -print -quit 2>/dev/null | grep -q .; then
          [ "$package_manager" = apt ] || fail 'Preinstall pam_google_authenticator on this distribution.'
          [ "$minutes" -ge 10 ] || fail 'TOTP dependency installation requires at least ten recovery minutes.'
          for access_command in apt-get timeout flock sync; do command -v "$access_command" >/dev/null 2>&1 || fail 'A bounded TOTP installation dependency is unavailable.'; done
        fi
        """;

    internal const string AccessPolicyArmBody = """
        if [ "${access_policy_enabled:-no}" = yes ]; then
          access_policy_run arm || fail 'Could not snapshot the advanced access policy baseline.'
        fi
        """;

    internal const string AccessPolicyProvisionBody = """
        guard
        [ "${access_policy_enabled:-no}" = yes ] || exit 0
        if [ "$use_totp" = yes ] && ! find /lib /usr/lib -name pam_google_authenticator.so -type f -print -quit 2>/dev/null | grep -q .; then
          [ "$package_manager" = apt ] || fail 'Preinstall pam_google_authenticator on this distribution.'
          [ "$minutes" -ge 10 ] || fail 'TOTP dependency installation requires at least ten recovery minutes.'
          touch "$tx/fail2ban.install-intent"
          sync -f "$tx/fail2ban.install-intent"
          if (
            exec 9>&-
            exec 8>"$tx/fail2ban.package.lock"
            flock -n 8 || exit 1
            [ ! -e "$tx/fail2ban.package-cancelled" ] || exit 1
            printf 'running\n' > "$tx/fail2ban.package-state"
            if timeout --signal=TERM --kill-after=10s 140s /bin/sh -c '
              export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
              apt-get -o DPkg::Lock::Timeout=30 -o Acquire::Retries=1 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update &&
              apt-get -y --no-remove --no-upgrade --no-install-recommends -o DPkg::Lock::Timeout=30 -o Dpkg::Options::=--force-confold install libpam-google-authenticator
            ' </dev/null >> "$tx/access-packages.log" 2>&1; then printf 'completed\n' > "$tx/fail2ban.package-state"
            else printf 'failed\n' > "$tx/fail2ban.package-state"; exit 1; fi
          ); then :; else fail 'TOTP dependency installation failed. Packages remain installed; inspect the root-only transaction log.'; fi
          [ ! -e "$tx/fail2ban.package-cancelled" ] || fail 'Package installation was cancelled by recovery.'
        fi
        access_policy_run provision || fail 'Sensitive account provisioning failed. Recovery remains armed.'
        """;

    internal const string AccessPolicyConfigureBody = """
        guard
        if [ "${access_policy_enabled:-no}" = yes ]; then
          access_policy_run configure || fail 'Advanced account policy configuration failed.'
        fi
        """;

    internal const string AccessPolicyVerifyBody = """
        if [ "${access_policy_enabled:-no}" = yes ]; then
          access_policy_run verify || fail 'Advanced account policy verification failed.'
        fi
        """;

    internal const string AccessPolicyRollbackBody = """
        if [ -d "$tx/access" ]; then
          access_policy_run rollback || failed=1
        fi
        """;

    internal const string AccessPolicyPython = """
        import base64, ctypes, hashlib, hmac, json, os, pathlib, pwd, re, stat, subprocess, sys, tempfile
        mode, user, tx_text, base_text, sudo_mode, account_access, readonly, totp, control, restricted, create, enabled, extra, phase = sys.argv[1:]
        tx = pathlib.Path(tx_text)
        base = pathlib.Path(base_text)
        work = tx / "access"
        policies = base / "access-policy"
        manifest = policies / (user + ".json")
        fragment = policies / (user + ".match")
        sudoers = pathlib.Path("/etc/sudoers.d") / ("90-sshhardener-access-" + user)
        secret = pathlib.Path("/etc/ssh-hardener/totp") / user
        pam = pathlib.Path("/etc/pam.d/sshd")
        pam_proof = policies / "pam.sha256"
        chroot = pathlib.Path("/srv/ssh-hardener/sftp") / user
        def require(condition, message):
            if not condition: raise RuntimeError(message)
        def digest(data): return hashlib.sha256(data).hexdigest()
        def safe(path, directory=False, missing=False):
            path = pathlib.Path(path)
            for parent in reversed(path.parents):
                info = parent.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not (info.st_mode & 0o022), "Unsafe root-owned policy ancestor")
            try: info = path.lstat()
            except FileNotFoundError:
                require(missing, "Required policy path is missing")
                return None
            require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) and info.st_uid == 0 and not (info.st_mode & 0o022), "Unsafe root-owned policy path")
            return info
        def read(path):
            safe(path)
            with open(path, "rb") as handle: return handle.read()
        def mkdir(path, permissions=0o700):
            path = pathlib.Path(path)
            if path.exists() or path.is_symlink(): safe(path, directory=True); return
            mkdir(path.parent, 0o755)
            path.mkdir(mode=permissions)
            safe(path, directory=True)
        def atomic(path, data, permissions):
            path = pathlib.Path(path)
            safe(path.parent, directory=True)
            safe(path, missing=True)
            fd, temporary = tempfile.mkstemp(prefix=".sshhardener-", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as handle:
                    os.fchmod(handle.fileno(), permissions)
                    handle.write(data); handle.flush(); os.fsync(handle.fileno())
                os.replace(temporary, path)
                directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(directory_fd)
                finally: os.close(directory_fd)
            finally:
                if os.path.exists(temporary): os.unlink(temporary)
        def run(arguments, data=None, allowed=(0,)):
            result = subprocess.run(arguments, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
            require(result.returncode in allowed, "An account policy verification command failed")
            return result
        def snapshot(key, path):
            safe(path.parent, directory=True)
            info = safe(path, missing=True)
            metadata = {"path": str(path), "exists": info is not None, "mode": stat.S_IMODE(info.st_mode) if info else None}
            if info:
                data = read(path)
                atomic(work / (key + ".original"), data, 0o600)
                metadata["original"] = digest(data)
            atomic(work / (key + ".json"), json.dumps(metadata).encode(), 0o600)
        def metadata(key): return json.loads(read(work / (key + ".json")))
        def install(key, path, data, permissions):
            record = metadata(key)
            current = read(path) if safe(path, missing=True) else None
            allowed = [record.get("original"), record.get("applied")]
            require((digest(current) if current is not None else None) in allowed, "Policy changed after the baseline snapshot")
            record["applied"] = digest(data)
            atomic(work / (key + ".applied"), data, 0o600)
            atomic(work / (key + ".json"), json.dumps(record).encode(), 0o600)
            atomic(path, data, permissions)
        def remove_owned(key, path):
            record = metadata(key)
            current = read(path) if safe(path, missing=True) else None
            require((digest(current) if current is not None else None) in (record.get("original"), record.get("applied")), "Policy changed after the baseline snapshot")
            record["applied"] = None
            atomic(work / (key + ".json"), json.dumps(record).encode(), 0o600)
            path.unlink(missing_ok=True)
        def restore(key):
            record = metadata(key)
            if "applied" not in record: return
            path = pathlib.Path(record["path"])
            current = read(path) if safe(path, missing=True) else None
            current_hash = digest(current) if current is not None else None
            if current_hash == record.get("original"): return
            if key == "secret" and current is not None:
                require(valid_secret_mutation(read(work / "secret.applied"), current), "TOTP enrollment changed outside the managed policy")
            else: require(current_hash == record["applied"], "Policy changed concurrently; preserved for console review")
            if record["exists"]: atomic(path, read(work / (key + ".original")), record["mode"])
            else: path.unlink(missing_ok=True)
        def load_manifest(name):
            path = policies / (name + ".json")
            require(stat.S_IMODE(safe(path).st_mode) == 0o600, "Managed access ownership record must have mode 0600")
            data = json.loads(read(path))
            require(data.get("version") == 1 and data.get("user") == name, "Invalid managed access ownership record")
            return data
        def validate_owned():
            if not policies.exists(): return
            safe(policies, directory=True)
            for path in policies.glob("*.match"):
                name = path.stem
                require(re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", name), "Invalid managed account filename")
                data = read(path)
                require(load_manifest(name).get("fragment") == digest(data), "Managed SSH Match proof does not match")
            if pam.exists() and b"# SSHHardener access PAM v1 " in read(pam):
                require(stat.S_IMODE(safe(pam_proof).st_mode) == 0o600, "Managed PAM proof must have mode 0600")
                require(read(pam_proof).decode().strip() == digest(read(pam)), "Managed PAM stack changed concurrently")
        def base_config(path):
            validate_owned()
            data = read(path).decode("utf-8")
            pattern = r"(?m)^# SSHHardener access policy v1 user=([a-z_][a-z0-9_-]{0,31}) BEGIN\n.*?^# SSHHardener access policy v1 user=\1 END\n?"
            def remove(match):
                expected = policies / (match.group(1) + ".match")
                if pathlib.Path(path) == tx / "sshd_config.original" and match.group(1) == user and (work / "fragment.original").exists(): expected = work / "fragment.original"
                require(match.group(0).rstrip("\n") == read(expected).decode().rstrip("\n"), "SSH Match block differs from its managed fragment")
                return ""
            stripped = re.sub(pattern, remove, data, flags=re.DOTALL)
            require(not re.search(r"(?im)^\s*Match\s|^# SSHHardener access policy v1 ", stripped), "Unmanaged or malformed SSH Match requires console review")
            return stripped
        def restricted_rules():
            trusted_system_path(pathlib.Path("/usr/bin/systemctl"))
            require(os.access("/usr/bin/systemctl", os.X_OK), "Restricted systemctl executable is unavailable")
            rules = []
            for line in restricted.splitlines():
                require(line.count("\t") == 1, "Restricted sudo entries require structured executable and literal arguments")
                executable, arguments = line.split("\t")
                require(executable == "/usr/bin/systemctl", "Only the systemctl executable is accepted")
                match = re.fullmatch(r"(is-active|is-enabled|restart|--no-pager --full status) ([A-Za-z0-9][A-Za-z0-9_.@-]{0,126}\.service)", arguments)
                require(match is not None, "Unsupported restricted sudo arguments")
                unit = match.group(2)
                properties = run(["systemctl", "show", unit, "--property=FragmentPath", "--property=DropInPaths", "--property=ExecStart", "--property=ExecStartPre", "--property=ExecStartPost", "--property=ExecReload", "--property=ExecStop", "--property=ExecStopPost"]).stdout.decode()
                fragment_path = re.search(r"(?m)^FragmentPath=(.+)$", properties)
                require(fragment_path is not None, "Restricted service has no verifiable unit file")
                trusted_system_path(pathlib.Path(fragment_path.group(1)))
                for key, value in (line.split("=", 1) for line in properties.splitlines() if "=" in line):
                    if key == "DropInPaths":
                        for path in value.split(): trusted_system_path(pathlib.Path(path))
                    elif key.startswith("Exec"):
                        for path in re.findall(r"path=([^ ;}]+)", value): trusted_system_path(pathlib.Path(path))
                rules.append(executable + " " + arguments)
            require(bool(rules), "Restricted sudo needs at least one exact command")
            return rules
        def trusted_system_path(path):
            # Distribution-owned /bin and /lib links are valid only while every lexical component is root-controlled.
            for part in list(reversed(path.parents)) + [path]:
                info = part.lstat()
                require(info.st_uid == 0 and (stat.S_ISLNK(info.st_mode) or not (info.st_mode & 0o022)), "Restricted service path is writable by another account")
            safe(path.resolve(strict=True))
        def password_hash():
            with open("/etc/shadow", "r", encoding="utf-8") as handle:
                for line in handle:
                    fields = line.rstrip("\n").split(":")
                    if fields[0] == user: return fields[1]
            raise RuntimeError("Local account has no shadow entry")
        def crypt_password(password, setting):
            library = ctypes.CDLL("libcrypt.so.1", use_errno=True)
            library.crypt.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
            library.crypt.restype = ctypes.c_char_p
            hashed = library.crypt(password, setting.encode())
            require(hashed is not None and not hashed.startswith(b"*"), "The account password hash method is unsupported")
            return hashed.decode()
        def valid_secret_mutation(original, current):
            try:
                first = original.decode("ascii").splitlines(); now = current.decode("ascii").splitlines()
                if not first or not now or not hmac.compare_digest(first[0], now[0]): return False
                original_codes = set(line for line in first[1:] if re.fullmatch(r"[0-9]{8}", line))
                found = set()
                for line in now[1:]:
                    if re.fullmatch(r"[0-9]{8}", line):
                        if line not in original_codes or line in found: return False
                        found.add(line); continue
                    if line in (chr(34) + " TOTP_AUTH", chr(34) + " WINDOW_SIZE 3"): continue
                    if re.fullmatch(chr(34) + r" DISALLOW_REUSE(?: [0-9]+)*", line): continue
                    if re.fullmatch(chr(34) + r" RATE_LIMIT 3 30(?: [0-9]+)*", line): continue
                    return False
                return sum(line == chr(34) + " TOTP_AUTH" for line in now) == 1 and sum(line == chr(34) + " WINDOW_SIZE 3" for line in now) == 1 and sum(line.startswith(chr(34) + " DISALLOW_REUSE") for line in now) == 1 and sum(line.startswith(chr(34) + " RATE_LIMIT 3 30") for line in now) == 1
            except (ValueError, UnicodeError): return False
        def managed_secret():
            if not secret.exists(): return
            # Google PAM atomically rewrites consumed/replay state with mode 0400.
            require(stat.S_IMODE(safe(secret).st_mode) in (0o400, 0o600), "TOTP enrollment file must be readable only by root")
            proof = load_manifest(user)
            current = read(secret)
            require(len(current) <= 16384 and proof.get("seed") == digest(current.splitlines()[0]), "TOTP seed is not owned by this application")
            require(valid_secret_mutation(current, current), "Managed TOTP policy options changed")
            recovery = proof.get("recovery")
            require(isinstance(recovery, list) and len(recovery) == 8 and all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) for value in recovery), "Managed recovery-code proof is invalid")
            require(all(digest(line) in recovery for line in current.splitlines()[1:] if re.fullmatch(b"[0-9]{8}", line)), "Recovery codes changed outside the managed enrollment")
        def target_totp():
            if totp == "yes": return True
            if not manifest.exists(): return False
            proof = load_manifest(user)
            if proof.get("seed") is None: return False
            managed_secret()
            return True
        def check_no_existing_sudo():
            if create == "yes": return
            if sudo_mode in ("none", "restricted", "password") or account_access == "sftp-only":
                require(not has_sudo_policy(), "Existing sudo privileges require manual review before applying a reduced or password-required policy")
        def has_sudo_policy():
            # root is allowed to list another user even when that user has NO rules: exit status alone is insufficient.
            result = run(["sudo", "-ll", "-U", user], allowed=(0, 1))
            output = result.stdout.decode("utf-8", errors="replace")
            denied = re.search(r"(?m)^User " + re.escape(user) + r" is not allowed to run sudo on [^\r\n]+\.$", output)
            return denied is None or "Sudoers entry:" in output or "Commands:" in output
        def preflight():
            require(os.geteuid() == 0, "Root is required")
            require(re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user), "Invalid target username")
            require(sudo_mode in ("legacy", "none", "password", "passwordless", "restricted") and account_access in ("shell", "sftp-only") and totp in ("yes", "no") and readonly in ("yes", "no"), "Unsupported account access policy")
            validate_owned(); base_config(pathlib.Path("/etc/ssh/sshd_config"))
            if manifest.exists() and load_manifest(user).get("chroot") is not None:
                sys.stderr.write("Existing managed SFTP accounts require a separate reviewed transition; their restrictions were not changed.\n")
                require(False, "Existing SFTP transition is unsupported")
            if enabled != "yes":
                print("Existing managed account Match blocks verified without changing the legacy policy")
                return
            if totp == "yes" and secret.exists():
                sys.stderr.write("Existing managed TOTP enrollment is preserved. Re-enrollment and recovery-code reset require a separate reviewed transition.\n")
                require(False, "Existing TOTP re-enrollment is unsupported")
            if account_access == "sftp-only" or sudo_mode in ("none", "restricted"):
                require(user != control and user != "root", "Restricted or SFTP target must differ from the control administrator")
            if create != "yes": require(pwd.getpwnam(user).pw_uid != 0 or sudo_mode in ("legacy", "passwordless"), "Target account has root uid")
            if sudo_mode != "legacy":
                run(["visudo", "-c"]); check_no_existing_sudo()
            safe(pathlib.Path("/etc/sudoers.d"), directory=True)
            if sudoers.exists():
                proof = load_manifest(user)
                require(stat.S_IMODE(safe(sudoers).st_mode) == 0o440 and proof.get("sudoers") == digest(read(sudoers)), "A foreign or modified managed sudoers path exists")
            if secret.exists(): managed_secret()
            if sudo_mode == "restricted": restricted_rules()
            if totp == "yes":
                safe(pam)
                require(pam.stat().st_size < 262144, "PAM stack exceeds safe bounds")
                managed_secret()
            if account_access == "sftp-only":
                for path in (pathlib.Path("/srv"), pathlib.Path("/srv/ssh-hardener"), pathlib.Path("/srv/ssh-hardener/sftp")):
                    if path.exists(): safe(path, directory=True)
                if chroot.exists():
                    safe(chroot, directory=True)
                    require(load_manifest(user).get("chroot") == str(chroot), "Existing SFTP chroot is not owned by this application")
            print("Advanced access policy read-only preflight passed")
        def arm():
            safe(tx, directory=True); mkdir(work)
            # Directory creation is root-only; no policy or user data changes before snapshots.
            for directory in (policies, pathlib.Path("/etc/ssh-hardener"), secret.parent): mkdir(directory)
            for key, path in (("sudoers", sudoers), ("fragment", fragment), ("secret", secret), ("pam", pam), ("pam-proof", pam_proof), ("manifest", manifest)):
                snapshot(key, path)
            atomic(work / "armed", b"1\n", 0o600)
        def provision():
            require(read(work / "armed") == b"1\n", "Advanced policy baseline was not armed")
            payload = sys.stdin.buffer.read(65537)
            require(len(payload) <= 65536, "Sensitive account input exceeds safe bounds")
            lines = payload.split(b"\n")
            require(len(lines) == 5 and lines[-1] == b"" and lines[0] == b"SSHARDENER_ACCESS_V1", "Invalid sensitive account protocol")
            decoded = [base64.b64decode(value, validate=True) for value in lines[1:4]]
            password, seed, recovery_codes = decoded
            require(all(base64.b64encode(value) == original for value, original in zip(decoded, lines[1:4])), "Noncanonical sensitive input encoding")
            require(b"\x00" not in password and b"\n" not in password and b"\r" not in password and len(password) <= 4096, "Invalid account password input")
            if sudo_mode == "password":
                require(bool(password), "Password-based sudo requires an account password")
                if create == "yes":
                    setting = "$6$rounds=200000$" + base64.b64encode(os.urandom(12)).decode().replace("+", ".") + "$"
                    hashed = crypt_password(password, setting)
                    atomic(work / "password.original-sha256", digest(password_hash().encode()).encode(), 0o600)
                    atomic(work / "password.expected-sha256", digest(hashed.encode()).encode(), 0o600)
                    atomic(work / "password-intent", b"1\n", 0o600)
                    run(["chpasswd", "-e"], (user + ":" + hashed + "\n").encode())
                else:
                    current_hash = password_hash()
                    require(current_hash.startswith("$") and hmac.compare_digest(crypt_password(password, current_hash), current_hash), "Existing account password was not verified; it was not changed")
            else: require(not password, "A password was supplied to a policy that does not use it")
            if sudo_mode in ("password", "passwordless", "restricted"):
                commands = ", ".join(restricted_rules()) if sudo_mode == "restricted" else "ALL"
                tag = "PASSWD" if sudo_mode == "password" else "NOPASSWD"
                rule = "# SSHHardener managed access sudoers v1\nDefaults:" + user + " env_reset,!setenv\n" + user + " ALL=(root) " + tag + ": NOSETENV: " + commands + "\n"
                atomic(work / "sudoers.candidate", rule.encode(), 0o440)
                run(["visudo", "-cf", str(work / "sudoers.candidate")])
                install("sudoers", sudoers, rule.encode(), 0o440)
                run(["visudo", "-c"])
                if sudo_mode == "password":
                    denied = run(["runuser", "-u", user, "--", "sudo", "-k", "-n", "--", "/bin/sh", "-c", "exit 0"], allowed=(0, 1))
                    require(denied.returncode != 0, "Passwordless sudo overrides the requested password policy")
                    run(["runuser", "-u", user, "--", "sudo", "-k", "-S", "-p", "", "--", "/usr/bin/true"], password + b"\n")
            elif sudo_mode == "none" and sudoers.exists(): remove_owned("sudoers", sudoers)
            if totp == "yes":
                require(re.fullmatch(b"[A-Z2-7]{32}", seed) is not None, "Invalid TOTP seed")
                seed_bytes = base64.b32decode(seed + b"=" * ((-len(seed)) % 8), casefold=False)
                require(len(seed_bytes) >= 20, "TOTP seed requires at least 160 bits")
                codes = recovery_codes.split(b"\n")
                require(len(codes) == 8 and len(set(codes)) == len(codes) and all(re.fullmatch(b"[1-9][0-9]{7}", value) for value in codes), "Invalid one-time recovery codes")
                content = seed + b"\n\" TOTP_AUTH\n\" DISALLOW_REUSE\n\" WINDOW_SIZE 3\n\" RATE_LIMIT 3 30\n" + b"\n".join(codes) + b"\n"
                install("secret", secret, content, 0o600)
            else: require(not seed and not recovery_codes, "TOTP material supplied while TOTP is disabled")
            atomic(work / "provisioned", b"1\n", 0o600)
            print("Sensitive account access provisioning completed; credential material is omitted")
        def configure():
            require(read(work / "provisioned") == b"1\n", "Sensitive provisioning is incomplete")
            if account_access == "sftp-only":
                for path in (pathlib.Path("/srv/ssh-hardener"), chroot.parent, chroot):
                    if not path.exists():
                        mkdir(path, 0o755)
                        with open(work / "created-directories", "ab") as handle: handle.write((str(path) + "\n").encode()); handle.flush(); os.fsync(handle.fileno())
                    safe(path, directory=True)
                    require(stat.S_IMODE(path.stat().st_mode) == 0o755, "SFTP chroot ancestry must have mode 0755")
                uploads = chroot / "uploads"
                target = pwd.getpwnam(user)
                if not uploads.exists():
                    # The enclosing root-owned directory makes this path immune to target renames.
                    uploads.mkdir(mode=0o700)
                    os.chown(uploads, target.pw_uid, target.pw_gid)
                    atomic(work / "uploads-created", b"1\n", 0o600)
                info = uploads.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == target.pw_uid and stat.S_IMODE(info.st_mode) == 0o700, "Unsafe SFTP uploads directory")
            current_pam = read(pam).decode("utf-8")
            begin = "# SSHHardener access PAM v1 user=" + user + " BEGIN"
            end = "# SSHHardener access PAM v1 user=" + user + " END"
            clean_pam = re.sub(r"(?ms)^" + re.escape(begin) + r"\n.*?^" + re.escape(end) + r"\n?", "", current_pam)
            if totp == "yes":
                block = begin + "\nauth [success=1 default=ignore] pam_succeed_if.so quiet user != " + user + "\nauth [success=done default=die] pam_google_authenticator.so user=root secret=/etc/ssh-hardener/totp/${USER}\n" + end + "\n"
                clean_pam = block + clean_pam
            elif target_totp():
                # Absence of a newly enrolled seed is never an instruction to disable existing MFA.
                clean_pam = current_pam
            if clean_pam != current_pam:
                install("pam", pam, clean_pam.encode(), metadata("pam")["mode"])
                install("pam-proof", pam_proof, (digest(clean_pam.encode()) + "\n").encode(), 0o600)
            block = "# SSHHardener access policy v1 user=" + user + " BEGIN\nMatch User " + user + "\n"
            if target_totp(): block += "    AuthenticationMethods publickey,keyboard-interactive:pam\n    KbdInteractiveAuthentication yes\n    PasswordAuthentication no\n"
            if account_access == "sftp-only":
                block += "    ChrootDirectory " + str(chroot) + "\n    ForceCommand internal-sftp " + ("-R " if readonly == "yes" else "") + "-d /uploads\n    DisableForwarding yes\n    AllowTcpForwarding no\n    AllowAgentForwarding no\n    X11Forwarding no\n    PermitTTY no\n    PermitTunnel no\n    PermitUserRC no\n"
            block += "# SSHHardener access policy v1 user=" + user + " END\n"
            install("fragment", fragment, block.encode(), 0o600)
            recovery_proof = None
            if target_totp():
                recovery_proof = [digest(line) for line in read(secret).splitlines()[1:] if re.fullmatch(b"[0-9]{8}", line)] if totp == "yes" else load_manifest(user).get("recovery")
            proof = {"version": 1, "user": user, "fragment": digest(block.encode()), "sudoers": digest(read(sudoers)) if sudoers.exists() else None,
                "seed": digest(read(secret).splitlines()[0]) if target_totp() else None, "recovery": recovery_proof, "chroot": str(chroot) if account_access == "sftp-only" else None}
            install("manifest", manifest, json.dumps(proof, sort_keys=True).encode(), 0o600)
            print("Managed account policy prepared; SSH activation waits for the final phase")
        def verify():
            validate_owned()
            effective_output = run(["/usr/sbin/sshd", "-T", "-C", "user=" + user + ",host=localhost,addr=127.0.0.1"]).stdout.decode()
            effective = dict(line.split(" ", 1) for line in effective_output.splitlines() if " " in line)
            if account_access == "sftp-only":
                expected = {"chrootdirectory": str(chroot), "forcecommand": "internal-sftp " + ("-R " if readonly == "yes" else "") + "-d /uploads",
                    "disableforwarding": "yes", "allowtcpforwarding": "no", "allowagentforwarding": "no", "x11forwarding": "no", "permittty": "no", "permittunnel": "no", "permituserrc": "no"}
                require(all(effective.get(key) == value for key, value in expected.items()), "Effective SFTP restrictions do not match the requested policy")
            if sudo_mode in ("none", "restricted") or account_access == "sftp-only":
                for shell in ("/bin/sh", "/bin/bash", "/usr/bin/env"):
                    result = run(["sudo", "-l", "-U", user, "--", shell], allowed=(0, 1))
                    require(result.returncode != 0, "Unauthorized root shell remains permitted by sudo")
                if sudo_mode == "none": require(not has_sudo_policy(), "Unexpected sudo privilege remains")
            if sudo_mode == "restricted":
                for rule in restricted_rules(): run(["sudo", "-l", "-U", user, "--"] + rule.split())
            if target_totp():
                managed_secret()
                require(effective.get("usepam") == "yes" and effective.get("kbdinteractiveauthentication") == "yes" and effective.get("authenticationmethods") == "publickey,keyboard-interactive:pam" and effective.get("passwordauthentication") == "no", "Effective two-factor authentication policy is not enforced")
                reference = work / "secret.applied" if (work / "secret.applied").exists() else work / "secret.original"
                require(valid_secret_mutation(read(reference), read(secret)), "TOTP secret state does not match the managed enrollment")
            print("Advanced account policy files and effective sudo permissions verified")
        def rollback():
            if not (work / "armed").exists(): return
            failures = []
            for key in ("pam", "secret", "sudoers", "fragment"):
                try: restore(key)
                except Exception: failures.append(key)
            if (work / "password-intent").exists():
                try:
                    current_hash = password_hash()
                    expected = read(work / "password.expected-sha256").decode()
                    if digest(current_hash.encode()) == read(work / "password.original-sha256").decode(): pass
                    elif digest(current_hash.encode()) == expected: run(["usermod", "-L", user])
                    else: require(current_hash.startswith("!") and digest(current_hash[1:].encode()) == expected, "The new account password changed; preserved")
                except Exception: failures.append("password")
            if (work / "uploads-created").exists():
                try: (chroot / "uploads").rmdir()
                except OSError: pass
            if (work / "created-directories").exists():
                for line in reversed(read(work / "created-directories").decode().splitlines()):
                    try: pathlib.Path(line).rmdir()
                    except OSError: pass
            if not failures:
                for key in ("pam-proof", "manifest"):
                    try: restore(key)
                    except Exception: failures.append(key)
            require(not failures, "Access recovery conflicts were preserved for console review: " + ", ".join(failures))
        try:
            require(os.geteuid() == 0, "Root is required")
            if mode == "base-config": sys.stdout.write(base_config(pathlib.Path(extra)))
            elif mode == "target-totp": print("yes" if target_totp() else "no")
            elif mode == "append-match":
                validate_owned()
                with open(extra, "ab") as output:
                    if policies.exists():
                        for path in sorted(policies.glob("*.match")):
                            if path.stem == user and enabled == "yes" and phase != "final":
                                # Final account changes must wait for verification, but an existing
                                # authentication policy must never disappear during the dual phase.
                                # The original fragment is a root-owned, verified arm-time snapshot.
                                baseline = metadata("fragment")
                                if baseline["exists"]: output.write(b"\n" + read(work / "fragment.original"))
                                continue
                            output.write(b"\n" + read(path))
            elif mode == "preflight": preflight()
            elif mode == "arm": arm()
            elif mode == "provision": provision()
            elif mode == "configure": configure()
            elif mode == "verify": verify()
            elif mode == "rollback": rollback()
            else: raise RuntimeError("Unknown account policy operation")
        except Exception as error:
            # Exception values from subprocesses or parsing may contain credentials. Print fixed text only.
            sys.stderr.write("Advanced access policy operation failed: " + type(error).__name__ + ". No credential material is logged.\n")
            sys.exit(1)
        """;
}
