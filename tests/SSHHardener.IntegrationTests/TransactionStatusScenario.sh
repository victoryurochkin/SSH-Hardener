#!/bin/sh
# Explicitly disposable root-filesystem fixture. Never run against a real server.
set -eu
[ "${SSH_HARDENER_DISPOSABLE_FIXTURE:-}" = yes ] && [ -f /.dockerenv ] && [ "$(id -u)" = 0 ] || {
  printf 'This fixture requires an explicitly marked disposable Docker container.\n' >&2; exit 1;
}
probe=${1:?Supply the exported production TransactionStatusService probe}
id=${2:-20261106120000-abcdef123456}
base=/var/lib/ssh-hardener
tx="$base/transactions/$id"
[ ! -e "$base" ] && [ ! -L "$base" ] && [ ! -e /run/ssh-hardener.lock ] && [ ! -L /run/ssh-hardener.lock ] || {
  printf 'The fixture requires a clean container, without existing hardener state.\n' >&2; exit 1;
}
umask 077
mkdir -m 0700 "$base" "$base/transactions" "$tx"
printf 'committed\n' > "$tx/state"
printf '%s\n' "$id" > "$base/last-committed"
: > /run/ssh-hardener.lock
chmod 0600 "$tx/state" "$base/last-committed" /run/ssh-hardener.lock
count=0
expect_state() {
  name=$1; state=$2; last=$3
  actual=$(/bin/sh "$probe" 2>/tmp/status-probe-error) || {
    printf 'FAIL %s: probe exited nonzero\n' "$name" >&2; cat /tmp/status-probe-error >&2; exit 1;
  }
  expected=$(printf 'SSHARDENER_TX_STATE=%s\nSSHARDENER_LAST_COMMITTED=%s\n' "$state" "$last")
  [ "$actual" = "$expected" ] || { printf 'FAIL %s: unexpected protocol output\n%s\n' "$name" "$actual" >&2; exit 1; }
  count=$((count + 1)); printf 'PASS %s\n' "$name"
}
expect_rejected() {
  name=$1; shift
  if [ "$#" = 0 ]; then set -- /bin/sh "$probe"; fi
  if actual=$("$@" 2>/tmp/status-probe-error); then
    printf 'FAIL %s: unsafe state was accepted\n%s\n' "$name" "$actual" >&2; exit 1
  fi
  case "$actual" in *SSHARDENER_TX_STATE=not-found*) printf 'FAIL %s: failure was mislabeled as absence\n' "$name" >&2; exit 1;; esac
  count=$((count + 1)); printf 'PASS %s\n' "$name"
}
expect_state committed-latest-with-empty-runtime-lock committed yes
printf '20261106110000-111111111111\n' > "$base/last-committed"
expect_state committed-not-latest committed no
for state in pending rolling-back recovery-deferred recovery-failed rolled-back; do
  printf '%s\n' "$state" > "$tx/state"
  expect_state "$state" "$state" no
done
mv "$base/last-committed" "$base/last-committed.saved"
printf 'pending\n' > "$tx/state"
expect_state pending-without-previous-commit pending no
mv "$base/last-committed.saved" "$base/last-committed"

mv "$tx" "$base/transactions/moved-aside"
expect_state absent-transaction not-found no
mv "$base/transactions/moved-aside" "$tx"
mv "$base" /tmp/status-base.saved
expect_state absent-base not-found no
mv /tmp/status-base.saved "$base"
mv "$tx/state" "$tx/state.saved"
expect_rejected existing-transaction-without-state
mv "$tx/state.saved" "$tx/state"
printf 'committed\npending\n' > "$tx/state"
expect_rejected malformed-state
printf '%065d\n' 0 > "$tx/state"
expect_rejected oversized-state
printf 'committed\n' > "$tx/state"
mv "$tx/state" "$tx/state.saved"
ln -s "$tx/state.saved" "$tx/state"
expect_rejected symlink-state
rm "$tx/state"
mv "$tx/state.saved" "$tx/state"
chmod 0644 "$tx/state"
expect_rejected readable-by-others-state
chmod 0600 "$tx/state"
chown 65534 "$tx/state"
expect_rejected nonroot-owned-state
chown 0 "$tx/state"
chmod 0777 "$base"
expect_rejected unsafe-base-mode
chmod 0700 "$base"
chown 65534 "$base"
expect_rejected nonroot-owned-base
chown 0 "$base"
mv "$tx" /tmp/status-tx.saved
ln -s /tmp/status-tx.saved "$tx"
expect_rejected symlink-transaction-directory
rm "$tx"
mv /tmp/status-tx.saved "$tx"
mv "$base" /tmp/status-base.saved
ln -s /tmp/status-base.saved "$base"
expect_rejected symlink-base-directory
rm "$base"
mv /tmp/status-base.saved "$base"
expect_rejected unprivileged-session runuser -u nobody -- /bin/sh "$probe"

hold_lock() {
  rm -f /tmp/status-lock.ready
  flock -x /run/ssh-hardener.lock /bin/sh -c 'touch /tmp/status-lock.ready; sleep 4' &
  holder=$!
  retries=0
  while [ ! -f /tmp/status-lock.ready ]; do
    [ "$retries" -lt 20 ] || exit 1
    sleep 0.1; retries=$((retries + 1))
  done
}
hold_lock
expect_rejected busy-existing-transaction
wait "$holder"
mv "$base" /tmp/status-base.saved
hold_lock
expect_rejected busy-lock-before-absence-check
wait "$holder"
mv /tmp/status-base.saved "$base"
expect_state lock-release-restores-committed-read committed no
printf 'PASS total=%s; production probe only read state; all mutations were fixture setup in the disposable root filesystem.\n' "$count"
