using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace SSHHardener.Core;

/// <summary>In-memory RFC 6238 SHA-1 TOTP, using 160-bit RFC 4648 Base32 secrets, 30 seconds and six digits.</summary>
public static class TotpService
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private const int SecretBytes = 20;

    public static string GenerateSecret()
    {
        Span<byte> bytes = stackalloc byte[SecretBytes];
        RandomNumberGenerator.Fill(bytes);
        try
        {
            Span<char> result = stackalloc char[32];
            var accumulator = 0;
            var bits = 0;
            var index = 0;
            foreach (var value in bytes)
            {
                accumulator = (accumulator << 8) | value;
                bits += 8;
                while (bits >= 5) { bits -= 5; result[index++] = Alphabet[(accumulator >> bits) & 31]; }
            }
            return new string(result);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    /// <summary>Eight distinct Google Authenticator compatible eight-digit scratch codes.</summary>
    public static IReadOnlyList<string> GenerateRecoveryCodes()
    {
        var codes = new HashSet<string>(StringComparer.Ordinal);
        while (codes.Count < 8)
            codes.Add(RandomNumberGenerator.GetInt32(10_000_000, 100_000_000).ToString("D8", CultureInfo.InvariantCulture));
        return Array.AsReadOnly(codes.ToArray());
    }

    public static void ValidateSecret(string secret)
    {
        if (secret is null || secret.Length != 32 || secret.Any(c => Alphabet.IndexOf(c) < 0))
            throw new ArgumentException("A TOTP secret must be exactly 32 uppercase Base32 characters.", nameof(secret));
    }

    public static void ValidateRecoveryCodes(IEnumerable<string> codes)
    {
        ArgumentNullException.ThrowIfNull(codes);
        var unique = new HashSet<string>(StringComparer.Ordinal);
        var count = 0;
        foreach (var code in codes)
        {
            if (++count > 8 || code is null || code.Length != 8 || code[0] is < '1' or > '9' ||
                code.Any(c => c is < '0' or > '9') || !unique.Add(code))
                throw new ArgumentException("Recovery codes must be eight unique eight-digit ASCII numbers.", nameof(codes));
        }
        if (count != 8) throw new ArgumentException("Exactly eight recovery codes are required.", nameof(codes));
    }

    public static string GenerateCode(string secret, DateTimeOffset now)
    {
        ValidateSecret(secret);
        var counter = Counter(now);
        Span<byte> decoded = stackalloc byte[SecretBytes];
        Span<byte> digits = stackalloc byte[6];
        Decode(secret, decoded);
        try { WriteCode(decoded, counter, digits); return System.Text.Encoding.ASCII.GetString(digits); }
        finally { CryptographicOperations.ZeroMemory(decoded); CryptographicOperations.ZeroMemory(digits); }
    }

    /// <summary>Checks every allowed time step without early exit. Replay prevention is the caller's responsibility.</summary>
    public static bool VerifyCode(string secret, string code, DateTimeOffset now, int window = 1)
    {
        ValidateSecret(secret);
        if (window is < 0 or > 10) throw new ArgumentOutOfRangeException(nameof(window), "The time-step window must be between zero and ten.");
        var counter = Counter(now);
        if (code is null || code.Length != 6 || code.Any(c => c is < '0' or > '9')) return false;
        Span<byte> decoded = stackalloc byte[SecretBytes];
        Span<byte> expected = stackalloc byte[6];
        Span<byte> supplied = stackalloc byte[6];
        for (var i = 0; i < supplied.Length; i++) supplied[i] = (byte)code[i];
        Decode(secret, decoded);
        var matched = false;
        try
        {
            for (var offset = -window; offset <= window; offset++)
            {
                // Counter zero has no preceding RFC 6238 time step.
                if (counter + offset < 0) continue;
                WriteCode(decoded, counter + offset, expected);
                matched |= CryptographicOperations.FixedTimeEquals(expected, supplied);
            }
            return matched;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(supplied);
        }
    }

    private static long Counter(DateTimeOffset now)
    {
        var seconds = now.ToUnixTimeSeconds();
        if (seconds < 0) throw new ArgumentOutOfRangeException(nameof(now), "TOTP time must not precede the Unix epoch.");
        return seconds / 30;
    }

    private static void Decode(string secret, Span<byte> output)
    {
        var accumulator = 0;
        var bits = 0;
        var index = 0;
        foreach (var c in secret)
        {
            accumulator = (accumulator << 5) | Alphabet.IndexOf(c);
            bits += 5;
            if (bits >= 8) { bits -= 8; output[index++] = (byte)(accumulator >> bits); }
        }
    }

    private static void WriteCode(ReadOnlySpan<byte> secret, long counter, Span<byte> output)
    {
        Span<byte> movingFactor = stackalloc byte[8];
        Span<byte> digest = stackalloc byte[20];
        BinaryPrimitives.WriteInt64BigEndian(movingFactor, counter);
        HMACSHA1.HashData(secret, movingFactor, digest);
        var offset = digest[^1] & 15;
        var binary = BinaryPrimitives.ReadUInt32BigEndian(digest.Slice(offset, 4)) & 0x7fff_ffff;
        var value = binary % 1_000_000;
        for (var i = 5; i >= 0; i--) { output[i] = (byte)('0' + value % 10); value /= 10; }
        CryptographicOperations.ZeroMemory(digest);
        CryptographicOperations.ZeroMemory(movingFactor);
    }
}
