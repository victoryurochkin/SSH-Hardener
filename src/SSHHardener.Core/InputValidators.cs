using System.Buffers.Binary;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace SSHHardener.Core;

public static partial class InputValidators
{
    [GeneratedRegex(@"\A[a-z_][a-z0-9_-]{0,31}\z", RegexOptions.CultureInvariant)]
    private static partial Regex UsernamePattern();

    public static void Validate(HardeningOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.NewPort is < 1 or > 65535) throw new ArgumentException("SSH port must be 1–65535.");
        if (!UsernamePattern().IsMatch(options.Username)) throw new ArgumentException("Invalid Linux username.");
        if (options.CreateUser && new[] { "root", "daemon", "bin", "sys", "sync", "nobody", "sshd", "admin" }.Contains(options.Username))
            throw new ArgumentException("The username is reserved. Choose a dedicated administrator username.");
        if (options.PermitRootLogin is not ("no" or "prohibit-password" or "yes")) throw new ArgumentException("Invalid root login policy.");
        if (options.Username == "root" && options.PermitRootLogin == "no") throw new ArgumentException("The recovery identity cannot be root when root login is disabled.");
        if (string.IsNullOrWhiteSpace(options.PrivateKeyPath)) throw new ArgumentException("A corresponding private key is required to verify the new login.");
        if (options.GrantSudo && !options.NoPasswordSudo)
            throw new ArgumentException("This release supports verified NOPASSWD sudo only. Password-based sudo provisioning is not supported.");
        if (options.NoPasswordSudo && !options.GrantSudo) throw new ArgumentException("NOPASSWD requires GrantSudo.");
        if (!string.IsNullOrEmpty(options.NewUserSudoPassword)) throw new ArgumentException("New user passwords are not supported by this release.");
        if (options.RollbackMinutes is < 5 or > 60) throw new ArgumentException("Rollback deadline must be 5–60 minutes.");
        if (options.MaxRetry is < 1 or > 100) throw new ArgumentException("MaxRetry must be 1–100.");
        if (options.MaxAuthTries is < 1 or > 20) throw new ArgumentException("MaxAuthTries must be 1–20 attempts per SSH connection.");
        if (options.FindTimeSeconds is < 60 or > 86400) throw new ArgumentException("Fail2ban findtime must be 60–86400 seconds.");
        if (options.BanSeconds != -1 && options.BanSeconds is < 60 or > 31536000)
            throw new ArgumentException("Ban duration must be -1 or 60–31536000 seconds.");
        foreach (var address in options.IgnoreAddresses) ValidateAddress(address);
        ValidatePublicKey(options.PublicKey);
    }

    public static void ValidateAddress(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException("Empty IP address.");
        var parts = value.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address) || parts[0].Contains('%'))
            throw new ArgumentException("Whitelist entries must be IPv4/IPv6 addresses or CIDR prefixes.");
        if (parts.Length == 2 && (!int.TryParse(parts[1], out var prefix) || prefix < 0 || prefix > address.GetAddressBytes().Length * 8))
            throw new ArgumentException("Invalid CIDR prefix.");
    }

    public static void ValidatePublicKey(string value)
    {
        if (value is null || value.Length > 32768 || value.Contains('\n') || value.Contains('\r') || value.Contains('\0'))
            throw new ArgumentException("Supply one OpenSSH public key without authorized_keys options.");
        var parts = value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) throw new ArgumentException("Invalid OpenSSH public key.");
        byte[] wire;
        try { wire = Convert.FromBase64String(parts[1]); }
        catch (FormatException ex) { throw new ArgumentException("Invalid public key base64.", ex); }
        var offset = 0;
        byte[] Field()
        {
            if (offset + 4 > wire.Length) throw new ArgumentException("Truncated public key.");
            var size = BinaryPrimitives.ReadUInt32BigEndian(wire.AsSpan(offset, 4)); offset += 4;
            if (size > 16384 || offset + size > wire.Length) throw new ArgumentException("Invalid public key field.");
            var field = wire.AsSpan(offset, checked((int)size)).ToArray(); offset += (int)size;
            return field;
        }
        var algorithm = Encoding.ASCII.GetString(Field());
        if (algorithm != parts[0]) throw new ArgumentException("Public key type does not match its data.");
        switch (algorithm)
        {
            case "ssh-ed25519":
                if (Field().Length != 32) throw new ArgumentException("An Ed25519 public key must be 32 bytes.");
                break;
            case "ssh-rsa":
                var exponent = Field();
                if (exponent.Length is 0 or > 8 || (exponent[0] & 128) != 0 || (exponent[^1] & 1) == 0)
                    throw new ArgumentException("Invalid RSA exponent.");
                ulong exponentValue = 0;
                foreach (var b in exponent) exponentValue = (exponentValue << 8) | b;
                if (exponentValue < 3) throw new ArgumentException("Invalid RSA exponent.");
                var modulus = Field();
                if (modulus.Length == 0 || (modulus[0] & 128) != 0 || (modulus[^1] & 1) == 0 ||
                    (modulus.Length > 1 && modulus[0] == 0 && (modulus[1] & 128) == 0))
                    throw new ArgumentException("Invalid RSA modulus.");
                var first = Array.FindIndex(modulus, x => x != 0);
                if (first < 0) throw new ArgumentException("Invalid RSA modulus.");
                var bits = (modulus.Length - first - 1) * 8 + (int)Math.Floor(Math.Log2(modulus[first])) + 1;
                if (bits < 3072) throw new ArgumentException("RSA keys must have at least 3072 bits.");
                break;
            case "ecdsa-sha2-nistp256":
            case "ecdsa-sha2-nistp384":
            case "ecdsa-sha2-nistp521":
                var curve = Encoding.ASCII.GetString(Field());
                if (algorithm != "ecdsa-sha2-" + curve) throw new ArgumentException("Invalid ECDSA curve.");
                var point = Field();
                var expected = curve == "nistp256" ? 65 : curve == "nistp384" ? 97 : 133;
                if (point.Length != expected || point[0] != 4) throw new ArgumentException("Invalid ECDSA public point.");
                break;
            default:
                throw new ArgumentException("This release supports Ed25519, RSA ≥3072 and NIST ECDSA keys. DSA and hardware keys are not supported.");
        }
        if (offset != wire.Length) throw new ArgumentException("Unexpected trailing public key data.");
    }
}

public static class Shell
{
    public static string Quote(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Contains('\0')) throw new ArgumentException("NUL is not valid shell text.", nameof(value));
        return "'" + value.Replace("'", "'\"'\"'", StringComparison.Ordinal) + "'";
    }
}
