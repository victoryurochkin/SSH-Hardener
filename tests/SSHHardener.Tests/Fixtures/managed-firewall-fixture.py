"""Run the real generated inspector with in-memory filesystem/command responses only.

Python 3.11+ standard library; no pip dependencies and no host firewall execution.
The C# caller supplies the actual Python heredoc extracted from a public plan step.
"""

import ast
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest import mock


CHAIN = "f2b-sshhardener-sshd"
POLICY_PATH = "/etc/fail2ban/jail.d/sshhardener-sshd.local"
PROOF_PATH = "/var/lib/ssh-hardener/fail2ban-managed.sha256"
SCENARIOS = {
    "baseline", "tampered-hash", "writable-policy", "unsafe-base-chain",
    "foreign-input-accept", "foreign-nft-table", "hidden-nft-rule", "unknown-nft-set",
    "own-lookalike-chain", "drop-policy", "query-failure",
    "legacy-owned-empty-nft", "legacy-foreign-native-nft",
}


def iptables_snapshot(owned):
    lines = ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]"]
    if owned:
        lines += [
            f":{CHAIN} - [0:0]",
            f"-A INPUT -p tcp -m multiport --dports 22,22022 -j {CHAIN}",
            f"-A {CHAIN} -s 198.51.100.77/32 -j REJECT --reject-with icmp-port-unreachable",
            f"-A {CHAIN} -j RETURN",
        ]
    return "\n".join(lines + ["COMMIT", ""])


def native_snapshot():
    objects = [{"metainfo": {"version": "fixture", "json_schema_version": 1}}]
    for family in ("ip", "ip6"):
        objects.append({"table": {"family": family, "name": "filter", "handle": 1}})
        for name in ("INPUT", "FORWARD", "OUTPUT"):
            objects.append({"chain": {
                "family": family, "table": "filter", "name": name,
                "type": "filter", "hook": name.lower(), "prio": 0, "policy": "accept",
            }})
    objects += [
        {"chain": {"family": "ip", "table": "filter", "name": CHAIN}},
        {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "expr": [
            {"match": {"op": "in", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set": [22, 22022]}}},
            {"jump": {"target": CHAIN}},
        ]}},
        {"rule": {"family": "ip", "table": "filter", "chain": CHAIN, "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "198.51.100.77"}},
            {"reject": {"type": "icmp", "expr": "port-unreachable"}},
        ]}},
        {"rule": {"family": "ip", "table": "filter", "chain": CHAIN, "expr": [{"return": None}]}},
    ]
    return {"nftables": objects}


def run_scenario(helper_path, scenario):
    if scenario not in SCENARIOS:
        raise AssertionError("Unknown fixture scenario: " + scenario)
    # Keep only trusted imports/function definitions; never execute the production entrypoint.
    parsed = ast.parse(Path(helper_path).read_text(encoding="utf-8"), filename=helper_path)
    isolated = ast.Module(body=[node for node in parsed.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))], type_ignores=[])
    namespace = {"__builtins__": __builtins__}
    exec(compile(isolated, helper_path, "exec"), namespace)
    if not callable(namespace.get("inspect")):
        raise AssertionError("Actual helper did not expose inspect().")

    policy = b"# SSHHardener managed fail2ban jail v1\n[sshhardener-sshd]\nenabled = true\nport = 22022\nmaxretry = 3\n"
    proof = (hashlib.sha256(policy).hexdigest() + "\n").encode("ascii")
    files = {POLICY_PATH: policy, PROOF_PATH: proof}
    modes = {POLICY_PATH: 0o644, PROOF_PATH: 0o600}
    directories = {"/var/lib/ssh-hardener": 0o700, "/etc/fail2ban": 0o755, "/etc/fail2ban/jail.d": 0o755}
    snapshots = {"iptables-save": iptables_snapshot(True), "ip6tables-save": iptables_snapshot(False)}
    native = native_snapshot()
    legacy = scenario in ("legacy-owned-empty-nft", "legacy-foreign-native-nft")

    if scenario == "tampered-hash":
        files[PROOF_PATH] = b"0" * 64 + b"\n"
    elif scenario == "writable-policy":
        modes[POLICY_PATH] = 0o664
    elif scenario == "unsafe-base-chain":
        next(entry["chain"] for entry in native["nftables"] if entry.get("chain", {}).get("name") == "INPUT")["prio"] = -100
    elif scenario == "foreign-input-accept":
        snapshots["iptables-save"] = snapshots["iptables-save"].replace("COMMIT", "-A INPUT -p tcp --dport 443 -j ACCEPT\nCOMMIT")
    elif scenario == "foreign-nft-table":
        native["nftables"].append({"table": {"family": "inet", "name": "unrelated"}})
    elif scenario == "hidden-nft-rule":
        native["nftables"].append({"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "expr": [{"accept": None}]}})
    elif scenario == "unknown-nft-set":
        native["nftables"].append({"set": {"family": "ip", "table": "filter", "name": "extra-allowlist", "type": "ipv4_addr"}})
    elif scenario == "own-lookalike-chain":
        native["nftables"].append({"chain": {"family": "ip", "table": "filter", "name": CHAIN + "-lookalike"}})
    elif scenario == "drop-policy":
        snapshots["iptables-save"] = snapshots["iptables-save"].replace(":INPUT ACCEPT", ":INPUT DROP")
    elif scenario == "legacy-owned-empty-nft":
        native = {"nftables": []}
    elif scenario == "legacy-foreign-native-nft":
        native = {"nftables": [{"table": {"family": "inet", "name": "foreign-native"}}]}

    def fake_lstat(path):
        if path in directories:
            return SimpleNamespace(st_mode=stat.S_IFDIR | directories[path], st_uid=0, st_size=0)
        if path in files:
            return SimpleNamespace(st_mode=stat.S_IFREG | modes[path], st_uid=0, st_size=len(files[path]))
        raise AssertionError("Fixture denies filesystem inspection outside its known paths: " + str(path))

    def fake_open(path, mode="r", *args, **kwargs):
        if path not in files or mode != "rb":
            raise AssertionError("Fixture denies unexpected file open: " + str(path))
        return io.BytesIO(files[path])

    def fake_run(command, **kwargs):
        command = tuple(command)
        if command in (("iptables", "--version"), ("ip6tables", "--version")):
            output = "iptables v1.8.11 (legacy)\n" if legacy else "iptables v1.8.11 (nf_tables)\n"
        elif len(command) == 1 and command[0] in snapshots:
            output = snapshots[command[0]]
        elif command == ("nft", "-j", "list", "ruleset"):
            if scenario == "query-failure":
                raise subprocess.CalledProcessError(1, command, stderr="fixture query failure")
            output = json.dumps(native)
        else:
            raise AssertionError("Fixture denies unexpected subprocess execution: " + repr(command))
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    with mock.patch.object(namespace["os"], "lstat", fake_lstat), mock.patch("builtins.open", fake_open), mock.patch.object(namespace["subprocess"], "run", fake_run):
        try:
            namespace["inspect"]()
        except ValueError as exception:
            if str(exception) != "unrecognized firewall state":
                raise
            return {"accepted": False, "rejection": type(exception).__name__}
        except subprocess.CalledProcessError as exception:
            if scenario != "query-failure":
                raise
            return {"accepted": False, "rejection": type(exception).__name__}
    return {"accepted": True, "rejection": None}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: managed-firewall-fixture.py <actual-helper.py> <scenario>")
    print(json.dumps(run_scenario(sys.argv[1], sys.argv[2])))
