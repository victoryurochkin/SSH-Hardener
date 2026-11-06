using System.Text.RegularExpressions;
using SSHHardener.Core;

namespace SSHHardener.Profiles;

/// <summary>Reads a transaction only after the session has proven the saved server identity.</summary>
public sealed partial class TransactionStatusService
{
    [GeneratedRegex(@"\ASSHARDENER_TX_STATE=(unknown|not-found|pending|rolling-back|recovery-deferred|recovery-failed|rolled-back|committed)\r?\nSSHARDENER_LAST_COMMITTED=(yes|no)\r?\n?\z", RegexOptions.CultureInvariant)]
    private static partial Regex ResponsePattern();

    public async Task<TransactionStatus> CheckAsync(IRemoteSession session, OperationRecord operation, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(operation);
        ct.ThrowIfCancellationRequested();
        operation.Validate();
        if (!string.Equals(session.Options.Host, operation.Host, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(session.Identity.Host, operation.Host, StringComparison.OrdinalIgnoreCase) ||
            session.Options.Port != session.Identity.Port ||
            (session.Options.Port != operation.OriginalPort && session.Options.Port != operation.NewPort))
            throw new InvalidOperationException("The connected endpoint does not match the saved operation.");
        if (session.Identity.Algorithm != operation.HostKeyAlgorithm || session.Identity.KeyBase64 != operation.HostKeyBase64 ||
            session.Identity.Fingerprint != operation.HostKeyFingerprint)
            throw new InvalidOperationException("The connected server key does not match the saved operation.");

        CommandResult result;
        try
        {
            var script = ProbeScript.Replace("@@ID@@", Shell.Quote(operation.TransactionId), StringComparison.Ordinal);
            result = await session.ExecuteAsync(script, true, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { return new TransactionStatus(OperationState.Unknown, false); }
        if (result.ExitCode != 0 || result.Output.Length > 512 || result.Error.Length > 4096)
            return new TransactionStatus(OperationState.Unknown, false);
        var response = ResponsePattern().Match(result.Output);
        if (!response.Success) return new TransactionStatus(OperationState.Unknown, false);
        var state = response.Groups[1].Value switch
        {
            "not-found" => OperationState.NotFound,
            "pending" => OperationState.Pending,
            "rolling-back" => OperationState.RollingBack,
            "recovery-deferred" => OperationState.RecoveryDeferred,
            "recovery-failed" => OperationState.RecoveryFailed,
            "rolled-back" => OperationState.RolledBack,
            "committed" => OperationState.Committed,
            _ => OperationState.Unknown
        };
        return new TransactionStatus(state, state is not (OperationState.Unknown or OperationState.NotFound) && response.Groups[2].Value == "yes");
    }

    private const string ProbeScript = """
        command -v timeout >/dev/null 2>&1 || exit 74
        timeout --signal=TERM --kill-after=1s 5s /bin/sh -s <<'SSHARDENER_STATUS_PROBE'
        set -eu
        export LC_ALL=C
        id=@@ID@@
        base=/var/lib/ssh-hardener
        tx="$base/transactions/$id"
        [ "$(id -u)" = 0 ] || exit 77
        for tool in stat find head grep flock; do command -v "$tool" >/dev/null 2>&1 || exit 74; done
        safe_parent() {
          [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %u -- "$1")" = 0 ] || exit 77
          mode=$(stat -c %a -- "$1") || exit 77
          case "$mode" in *[2367][0-7]|*[0-7][2367]) exit 77;; esac
        }
        safe_directory() {
          [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %u -- "$1")" = 0 ] && [ "$(stat -c %a -- "$1")" = 700 ] || exit 77
        }
        safe_file() {
          [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %u -- "$1")" = 0 ] && [ "$(stat -c %a -- "$1")" = 600 ] || exit 77
          size=$(stat -c %s -- "$1") || exit 77
          [ "$size" -le 64 ] || exit 65
          [ "$size" -gt 0 ] || [ "${2:-}" = allow-empty ] || exit 65
        }
        entry_exists() {
          # Unlike test -e, a successful directory enumeration distinguishes a
          # genuinely absent name from a permission/stat failure and dangling link.
          found=$(find "$1" -mindepth 1 -maxdepth 1 -name "$2" -printf x -quit 2>/dev/null) || exit 77
          [ "$found" = x ]
        }
        not_found() { printf 'SSHARDENER_TX_STATE=not-found\nSSHARDENER_LAST_COMMITTED=no\n'; exit 0; }
        safe_parent /var
        safe_parent /var/lib
        safe_parent /run
        if [ -e /run/ssh-hardener.lock ] || [ -L /run/ssh-hardener.lock ]; then
          safe_file /run/ssh-hardener.lock allow-empty
          exec 9</run/ssh-hardener.lock
          flock -s -w 2 9 || exit 75
        fi
        if ! entry_exists /var/lib ssh-hardener; then not_found; fi
        safe_directory "$base"
        if ! entry_exists "$base" transactions; then not_found; fi
        safe_directory "$base/transactions"
        if ! entry_exists "$base/transactions" "$id"; then not_found; fi
        safe_directory "$tx"
        # An existing transaction without a valid state is incomplete, not absent.
        safe_file "$tx/state"
        state=$(head -c 65 -- "$tx/state") || exit 77
        case "$state" in pending|rolling-back|recovery-deferred|recovery-failed|rolled-back|committed) :;; *) exit 65;; esac
        is_last=no
        if entry_exists "$base" last-committed; then
          safe_file "$base/last-committed"
          last=$(head -c 65 -- "$base/last-committed") || exit 77
          printf '%s\n' "$last" | grep -Eq '^[0-9]{14}-[a-f0-9]{12}$' || exit 65
          [ "$last" != "$id" ] || is_last=yes
        fi
        printf 'SSHARDENER_TX_STATE=%s\nSSHARDENER_LAST_COMMITTED=%s\n' "$state" "$is_last"
        SSHARDENER_STATUS_PROBE
        """;
}
