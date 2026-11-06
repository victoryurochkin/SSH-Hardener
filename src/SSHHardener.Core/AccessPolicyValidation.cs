using System.Text.RegularExpressions;

namespace SSHHardener.Core;

public static partial class AccessPolicyValidation
{
    [GeneratedRegex(@"\A[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,126}\.service\z", RegexOptions.CultureInvariant)]
    private static partial Regex UnitPattern();

    public static void Validate(HardeningOptions options)
    {
        if (!Enum.IsDefined(options.AccountAccess) || !Enum.IsDefined(options.SudoMode))
            throw new ArgumentException("Unknown account access or sudo policy.");
        if (options.VerificationSudoPassword is { } verification &&
            (verification.Length > 256 || verification.Any(x => x is '\r' or '\n' or '\0')))
            throw new ArgumentException("Invalid sudo verification credential.");
        if (options.SudoMode != SudoPolicyMode.Legacy)
        {
            if (options.GrantSudo || options.NoPasswordSudo)
                throw new ArgumentException("Choose an explicit sudo policy instead of mixing it with legacy permission flags.");
            if (options.SudoMode == SudoPolicyMode.Password)
            {
                var password = options.NewUserSudoPassword;
                if (string.IsNullOrEmpty(password) || password.Length > 256 || password.Contains('\0') || password.Contains('\r') || password.Contains('\n'))
                    throw new ArgumentException("Supply the account password for verified password-based sudo.");
                if (options.CreateUser && password.Length < 12)
                    throw new ArgumentException("A new account password must contain at least 12 characters.");
            }
            else if (!string.IsNullOrEmpty(options.NewUserSudoPassword))
                throw new ArgumentException("An account password is accepted only for password-based sudo.");
            if (options.Username == "root" && options.SudoMode is SudoPolicyMode.None or SudoPolicyMode.Restricted)
                throw new ArgumentException("Root cannot be configured as a restricted or unprivileged account.");
        }
        if (options.RestrictedSudoCommands is null) throw new ArgumentException("Invalid restricted sudo command list.");
        if (options.SudoMode == SudoPolicyMode.Restricted)
        {
            if (options.RestrictedSudoCommands.Length is < 1 or > 32)
                throw new ArgumentException("Select 1–32 exact service commands for restricted sudo.");
            var distinct = new HashSet<RestrictedSudoCommand>();
            foreach (var command in options.RestrictedSudoCommands)
            {
                ValidateRestrictedCommand(command);
                if (!distinct.Add(command)) throw new ArgumentException("Duplicate restricted sudo command.");
            }
        }
        else if (options.RestrictedSudoCommands.Length != 0)
            throw new ArgumentException("Restricted commands require the restricted sudo policy.");
        if (options.AccountAccess == AccountAccess.SftpOnly)
        {
            if (options.Username == "root" || options.SudoMode != SudoPolicyMode.None)
                throw new ArgumentException("An SFTP-only account must be non-root and have no sudo permission.");
        }
        else if (options.SftpReadOnly) throw new ArgumentException("Read-only SFTP requires an SFTP-only account.");
        if (options.EnableTotp)
        {
            if (options.Username == "root") throw new ArgumentException("Use a dedicated non-root administrator for two-factor SSH authentication.");
            if (!options.DisablePasswordAuthentication)
                throw new ArgumentException("Two-factor SSH access requires a public key plus a TOTP code and disables password-only login.");
            TotpService.ValidateSecret(options.TotpSecret ?? "");
            TotpService.ValidateRecoveryCodes(options.TotpRecoveryCodes);
            if (options.TotpEnrollmentConfirmedAt is not { } confirmedAt ||
                confirmedAt > DateTimeOffset.UtcNow.AddMinutes(1) || confirmedAt < DateTimeOffset.UtcNow.AddMinutes(-30) ||
                !TotpService.VerifyCode(options.TotpSecret!, options.TotpEnrollmentCode ?? "", confirmedAt))
                throw new ArgumentException("Confirm a current code from your authenticator before enabling two-factor authentication.");
        }
    }

    public static void ValidateRestrictedCommand(RestrictedSudoCommand command)
    {
        if (command is null || command.Executable != "/usr/bin/systemctl" || command.Arguments is null)
            throw new ArgumentException("Restricted sudo accepts exact /usr/bin/systemctl service operations only.");
        var parts = command.Arguments.Split(' ', StringSplitOptions.None);
        var valid = parts.Length == 2 && parts[0] is "is-active" or "is-enabled" or "restart" && UnitPattern().IsMatch(parts[1]);
        valid |= parts.Length == 4 && parts[0] == "--no-pager" && parts[1] == "--full" && parts[2] == "status" && UnitPattern().IsMatch(parts[3]);
        if (!valid) throw new ArgumentException("Use an exact service name and an allowed service operation; shell text and wildcards are not accepted.");
    }
}
