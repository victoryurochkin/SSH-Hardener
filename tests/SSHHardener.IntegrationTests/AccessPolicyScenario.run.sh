#!/bin/sh
set -eu
probe=${1:?Pass the absolute exported fixture directory}
case "$probe" in /*) :;; *) exit 2;; esac
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -f "$probe/access-policy.py" ] || { printf 'Export the production helper first.\n' >&2; exit 2; }
docker build -q -f "$here/AccessPolicyScenario.Dockerfile" -t sshhardener-access-policy:local "$here" > "$probe/image-id.txt"
# SSH binds only to this disposable container loopback. No published ports, host network or VM credentials.
docker run --rm --network none -v "$probe:/probe" -v "$here/AccessPolicyScenario.fixture.py:/fixture.py:ro" sshhardener-access-policy:local -c 'python3 -m py_compile /probe/access-policy.py && python3 /fixture.py' > "$probe/result.txt" 2>&1 || { cat "$probe/result.txt" >&2; exit 1; }
cat "$probe/result.txt"
