using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace SSHHardener.Ssh;

/// <summary>
/// Serializes the documented PuTTY PPK v3 RSA container. Cryptographic primitives
/// are provided by Bouncy Castle and the framework; no custom cipher or KDF.
/// https://the.earth.li/~sgtatham/putty/0.85/htmldoc/AppendixC.html
/// </summary>
internal static class PuttyKeyWriter
{
    private const string Algorithm = "ssh-rsa";
    private const string Encryption = "aes256-cbc";
    private const string Comment = "@victoryur-SSHHardener";
    private const int MemoryKiB = 65_536;
    private const int Passes = 3;
    private const int Parallelism = 1;

    internal static byte[] EncodeRsa(RSAParameters parameters, string passphrase, CancellationToken ct)
    {
        if (parameters.Modulus is null || parameters.Exponent is null || parameters.D is null ||
            parameters.P is null || parameters.Q is null || parameters.InverseQ is null)
            throw new CryptographicException("A complete two-prime RSA private key is required.");
        using var publicData = new MemoryStream();
        using var privateData = new MemoryStream();
        using var macData = new MemoryStream();
        byte[]? passwordBytes = null, derived = null, privatePlaintext = null;
        byte[]? cipherKey = null, cipherIv = null, macKey = null;
        Argon2Parameters.Builder? builder = null;
        Argon2Parameters? argonParameters = null;
        try
        {
            ct.ThrowIfCancellationRequested();
            WriteString(publicData, Encoding.ASCII.GetBytes(Algorithm));
            WriteMpint(publicData, parameters.Exponent);
            WriteMpint(publicData, parameters.Modulus);
            // PPK's private RSA section excludes the public e/n values.
            WriteMpint(privateData, parameters.D);
            WriteMpint(privateData, parameters.P);
            WriteMpint(privateData, parameters.Q);
            WriteMpint(privateData, parameters.InverseQ);
            var meaningfulLength = checked((int)privateData.Length);
            privatePlaintext = new byte[checked((meaningfulLength + 15) / 16 * 16)];
            privateData.GetBuffer().AsSpan(0, meaningfulLength).CopyTo(privatePlaintext);
            // PPK uses random padding, not PKCS#7; an aligned blob has no extra block.
            RandomNumberGenerator.Fill(privatePlaintext.AsSpan(meaningfulLength));

            var salt = RandomNumberGenerator.GetBytes(16);
            passwordBytes = Encoding.UTF8.GetBytes(passphrase);
            builder = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                .WithVersion(Argon2Parameters.Version13)
                .WithMemoryAsKB(MemoryKiB).WithIterations(Passes).WithParallelism(Parallelism).WithSalt(salt);
            argonParameters = builder.Build();
            var generator = new Argon2BytesGenerator();
            generator.Init(argonParameters);
            derived = new byte[80];
            generator.GenerateBytes(passwordBytes, derived);
            ct.ThrowIfCancellationRequested();
            cipherKey = derived.AsSpan(0, 32).ToArray();
            cipherIv = derived.AsSpan(32, 16).ToArray();
            macKey = derived.AsSpan(48, 32).ToArray();

            var publicBlob = publicData.ToArray();
            WriteString(macData, Encoding.ASCII.GetBytes(Algorithm));
            WriteString(macData, Encoding.ASCII.GetBytes(Encryption));
            WriteString(macData, Encoding.UTF8.GetBytes(Comment));
            WriteString(macData, publicBlob);
            WriteString(macData, privatePlaintext);
            var mac = HMACSHA256.HashData(macKey, macData.GetBuffer().AsSpan(0, checked((int)macData.Length)));
            byte[] ciphertext;
            using (var aes = Aes.Create())
            {
                aes.Key = cipherKey;
                ciphertext = aes.EncryptCbc(privatePlaintext, cipherIv, PaddingMode.None);
            }
            var text = new StringBuilder();
            text.Append("PuTTY-User-Key-File-3: ").Append(Algorithm).Append('\n')
                .Append("Encryption: ").Append(Encryption).Append('\n')
                .Append("Comment: ").Append(Comment).Append('\n');
            AppendBase64(text, "Public-Lines", publicBlob);
            text.Append("Key-Derivation: Argon2id\n")
                .Append("Argon2-Memory: ").Append(MemoryKiB).Append('\n')
                .Append("Argon2-Passes: ").Append(Passes).Append('\n')
                .Append("Argon2-Parallelism: ").Append(Parallelism).Append('\n')
                .Append("Argon2-Salt: ").Append(Convert.ToHexStringLower(salt)).Append('\n');
            AppendBase64(text, "Private-Lines", ciphertext);
            text.Append("Private-MAC: ").Append(Convert.ToHexStringLower(mac)).Append('\n');
            return Encoding.ASCII.GetBytes(text.ToString());
        }
        finally
        {
            Zero(passwordBytes); Zero(derived); Zero(privatePlaintext);
            Zero(cipherKey); Zero(cipherIv); Zero(macKey);
            CryptographicOperations.ZeroMemory(privateData.GetBuffer());
            CryptographicOperations.ZeroMemory(macData.GetBuffer());
            argonParameters?.Clear(); builder?.Clear();
        }
    }

    private static void AppendBase64(StringBuilder output, string header, byte[] bytes)
    {
        var data = Convert.ToBase64String(bytes);
        output.Append(header).Append(": ").Append((data.Length + 63) / 64).Append('\n');
        for (var offset = 0; offset < data.Length; offset += 64)
            output.Append(data, offset, Math.Min(64, data.Length - offset)).Append('\n');
    }

    private static void WriteMpint(Stream stream, byte[] unsigned)
    {
        var first = 0;
        while (first < unsigned.Length && unsigned[first] == 0) first++;
        var bytes = unsigned.AsSpan(first);
        var signPadding = bytes.Length > 0 && (bytes[0] & 0x80) != 0;
        Span<byte> size = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(size, bytes.Length + (signPadding ? 1 : 0));
        stream.Write(size);
        if (signPadding) stream.WriteByte(0);
        stream.Write(bytes);
    }

    private static void WriteString(Stream stream, byte[] bytes)
    {
        Span<byte> size = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(size, bytes.Length);
        stream.Write(size); stream.Write(bytes);
    }

    private static void Zero(byte[]? bytes)
    {
        if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
    }
}
