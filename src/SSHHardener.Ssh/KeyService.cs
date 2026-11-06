using System.Buffers.Binary;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Renci.SshNet;
using Renci.SshNet.Security;
using System.Numerics;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace SSHHardener.Ssh;

public sealed class KeyService
{
    /// <summary>Generates RSA 4096 and writes an encrypted private key plus its OpenSSH public key.</summary>
    public async Task<string> GenerateRsaAsync(string path, string passphrase, CancellationToken ct = default,
        PrivateKeyFormat format = PrivateKeyFormat.EncryptedPkcs8Pem)
    {
        ValidatePassphrase(passphrase);
        if (!Enum.IsDefined(format)) throw new ArgumentOutOfRangeException(nameof(format));
        var fullPath = ValidateDestination(path);
        return await Task.Run(async () =>
        {
            using var rsa = RSA.Create(4096);
            ct.ThrowIfCancellationRequested();
            var parameters = rsa.ExportParameters(format == PrivateKeyFormat.EncryptedPuttyV3);
            byte[]? encoded = null;
            try
            {
                encoded = format == PrivateKeyFormat.EncryptedPuttyV3
                    ? PuttyKeyWriter.EncodeRsa(parameters, passphrase, ct)
                    : Encoding.ASCII.GetBytes(rsa.ExportEncryptedPkcs8PrivateKeyPem(passphrase,
                        new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000)) + "\n");
                var expectedPublic = rsa.ExportParameters(false);
                return await WritePairAsync(fullPath, encoded, passphrase, EncodePublicKey(expectedPublic),
                    parsed => ValidateRsaSignature(parsed, expectedPublic), ct).ConfigureAwait(false);
            }
            finally { ClearParameters(parameters); Zero(encoded); }
        }, ct).ConfigureAwait(false);
    }

    /// <summary>Generates Ed25519 and writes an encrypted private key plus its OpenSSH public key.</summary>
    public async Task<string> GenerateEd25519Async(string path, string passphrase, CancellationToken ct = default,
        PrivateKeyFormat format = PrivateKeyFormat.EncryptedPuttyV3)
    {
        ValidatePassphrase(passphrase);
        if (!Enum.IsDefined(format)) throw new ArgumentOutOfRangeException(nameof(format));
        var fullPath = ValidateDestination(path);
        return await Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();
            var seed = RandomNumberGenerator.GetBytes(32);
            byte[]? encoded = null;
            try
            {
                var privateKey = new Ed25519PrivateKeyParameters(seed);
                var publicKey = privateKey.GeneratePublicKey().GetEncoded();
                encoded = format == PrivateKeyFormat.EncryptedPuttyV3
                    ? PuttyKeyWriter.EncodeEd25519(seed, publicKey, passphrase, ct)
                    : EncodeEd25519Pkcs8(privateKey, passphrase);
                ct.ThrowIfCancellationRequested();
                return await WritePairAsync(fullPath, encoded, passphrase, EncodeEd25519PublicKey(publicKey),
                    parsed => ValidateEd25519Signature(parsed, publicKey), ct).ConfigureAwait(false);
            }
            finally { Zero(seed); Zero(encoded); }
        }, ct).ConfigureAwait(false);
    }

    /// <summary>Re-encodes the same RSA identity as encrypted PuTTY PPK v3; never changes the source or the server.</summary>
    public async Task<string> ExportRsaToPuttyAsync(string sourcePath, string destinationPath,
        string sourcePassphrase, string exportPassphrase, CancellationToken ct = default)
        => await ExportToPuttyCoreAsync(sourcePath, destinationPath, sourcePassphrase, exportPassphrase, rsaOnly: true, ct).ConfigureAwait(false);

    /// <summary>Re-encodes the same RSA or Ed25519 identity as encrypted PPK v3 without changing the source.</summary>
    public async Task<string> ExportToPuttyAsync(string sourcePath, string destinationPath,
        string sourcePassphrase, string exportPassphrase, CancellationToken ct = default)
        => await ExportToPuttyCoreAsync(sourcePath, destinationPath, sourcePassphrase, exportPassphrase, rsaOnly: false, ct).ConfigureAwait(false);

    private static async Task<string> ExportToPuttyCoreAsync(string sourcePath, string destinationPath,
        string sourcePassphrase, string exportPassphrase, bool rsaOnly, CancellationToken ct)
    {
        ValidatePassphrase(exportPassphrase);
        var source = Path.GetFullPath(sourcePath);
        var destination = ValidateDestination(destinationPath);
        if (string.Equals(source, destination, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(source, destination + ".pub", StringComparison.OrdinalIgnoreCase))
            throw new IOException("Choose a destination distinct from the original key.");
        if (new FileInfo(source).Length > 1_048_576) throw new IOException("Private key input exceeds 1 MiB.");
        return await Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();
            using var imported = OpenPrivateKey(source, sourcePassphrase);
            if (!rsaOnly && imported.Key is ED25519Key sourceEd)
            {
                var seed = sourceEd.PrivateKey.ToArray();
                byte[]? edEncoded = null;
                try
                {
                    if (seed.Length != 32) throw new CryptographicException("Invalid Ed25519 private seed.");
                    var publicKey = new Ed25519PrivateKeyParameters(seed).GeneratePublicKey().GetEncoded();
                    if (!CryptographicOperations.FixedTimeEquals(publicKey, sourceEd.PublicKey))
                        throw new CryptographicException("The imported Ed25519 private key does not match its public identity.");
                    edEncoded = PuttyKeyWriter.EncodeEd25519(seed, publicKey, exportPassphrase, ct);
                    return await WritePairAsync(destination, edEncoded, exportPassphrase, EncodeEd25519PublicKey(publicKey),
                        parsed => ValidateEd25519Signature(parsed, publicKey), ct).ConfigureAwait(false);
                }
                finally { Zero(seed); Zero(edEncoded); }
            }
            if (imported.Key is not RsaKey sourceRsa)
                throw new NotSupportedException(rsaOnly ? "This export supports RSA keys only." : "PuTTY export supports RSA and Ed25519 keys only.");
            var parameters = ParametersFromSshKey(sourceRsa);
            byte[]? encoded = null;
            try
            {
                using var rsa = RSA.Create();
                rsa.ImportParameters(parameters);
                ct.ThrowIfCancellationRequested();
                encoded = PuttyKeyWriter.EncodeRsa(parameters, exportPassphrase, ct);
                var expectedPublic = rsa.ExportParameters(false);
                return await WritePairAsync(destination, encoded, exportPassphrase, EncodePublicKey(expectedPublic),
                    parsed => ValidateRsaSignature(parsed, expectedPublic), ct).ConfigureAwait(false);
            }
            finally { ClearParameters(parameters); Zero(encoded); }
        }, ct).ConfigureAwait(false);
    }

    public string ReadPublicKey(string path, string? passphrase = null)
    {
        using var key = OpenPrivateKey(path, passphrase);
        var algorithm = key.HostKeyAlgorithms.FirstOrDefault() ?? throw new CryptographicException("Key has no supported algorithm.");
        var blob = algorithm.Data;
        var length = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(0, 4));
        if (length > 128 || blob.Length < 4 + length) throw new CryptographicException("Invalid SSH key.");
        var name = Encoding.ASCII.GetString(blob, 4, (int)length);
        return name + " " + Convert.ToBase64String(blob) + " @victoryur-SSHHardener";
    }
    public static string Fingerprint(string publicKey)
    {
        var blob = Convert.FromBase64String(publicKey.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1]);
        return "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');
    }

    /// <summary>Loads supported SSH.NET formats, correctly decoding RFC 8410 Ed25519 PKCS#8 using Bouncy Castle.</summary>
    public static PrivateKeyFile OpenPrivateKey(string path, string? passphrase = null)
    {
        using var input = new FileStream(Path.GetFullPath(path), FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length > 1_048_576) throw new IOException("Private key input exceeds 1 MiB.");
        var bytes = new byte[checked((int)input.Length)];
        try
        {
            input.ReadExactly(bytes);
            if (input.ReadByte() != -1) throw new IOException("Private key input changed while being read.");
            return OpenPrivateKey(bytes, passphrase);
        }
        finally { Zero(bytes); }
    }

    private static PrivateKeyFile OpenPrivateKey(byte[] bytes, string? passphrase)
    {
        // PEM may contain a BOM, leading whitespace or explanatory preamble.
        // Never let those bypass the RFC 8410 adapter and silently change an Ed25519 identity.
        if (bytes.AsSpan().IndexOf("-----BEGIN ENCRYPTED PRIVATE KEY-----"u8) >= 0 ||
            bytes.AsSpan().IndexOf("-----BEGIN PRIVATE KEY-----"u8) >= 0)
        {
            using var reader = new StringReader(Encoding.ASCII.GetString(bytes));
            var pem = new Org.BouncyCastle.Utilities.IO.Pem.PemReader(reader).ReadPemObject()
                ?? throw new CryptographicException("Invalid PKCS#8 PEM key.");
            char[]? password = null;
            try
            {
                PrivateKeyInfo keyInfo;
                if (pem.Type == "ENCRYPTED PRIVATE KEY")
                {
                    if (passphrase is null) throw new CryptographicException("The private key requires a passphrase.");
                    password = passphrase.ToCharArray();
                    keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(password,
                        EncryptedPrivateKeyInfo.GetInstance(pem.Content));
                }
                else keyInfo = PrivateKeyInfo.GetInstance(pem.Content);
                // SSH.NET 2026 interprets RFC 8410's nested OCTET STRING as seed bytes.
                // Use its public Key constructor with the correctly decoded seed instead.
                if (keyInfo.PrivateKeyAlgorithm.Algorithm.Equals(Org.BouncyCastle.Asn1.EdEC.EdECObjectIdentifiers.id_Ed25519))
                {
                    var ed = (Ed25519PrivateKeyParameters)PrivateKeyFactory.CreateKey(keyInfo);
                    var seed = ed.GetEncoded();
                    try { return new PrivateKeyFile(new ED25519Key(seed)); }
                    finally { Zero(seed); }
                }
            }
            finally
            {
                if (password is not null) Array.Clear(password);
                Zero(pem.Content);
            }
        }
        using var stream = new MemoryStream(bytes, writable: false);
        return new PrivateKeyFile(stream, passphrase);
    }

    private static async Task<string> WritePairAsync(string fullPath, byte[] encoded, string passphrase,
        string publicKey, Action<PrivateKeyFile> validateSignature, CancellationToken ct)
    {
        var expectedBlob = Convert.FromBase64String(publicKey.Split(' ')[1]);
        FileStream? privateStream = null, publicStream = null;
        var privateCreated = false;
        var publicCreated = false;
        var completed = false;
        byte[]? readBack = null;
        try
        {
            ct.ThrowIfCancellationRequested();
            var sid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("Cannot identify Windows user.");
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
            // The ACL and exclusive handle exist before the first private-file byte is written.
            privateStream = new FileInfo(fullPath).Create(FileMode.CreateNew, FileSystemRights.Read | FileSystemRights.Write,
                FileShare.None, 4096, FileOptions.None, security);
            privateCreated = true;
            await privateStream.WriteAsync(encoded, ct).ConfigureAwait(false);
            await privateStream.FlushAsync(ct).ConfigureAwait(false);
            privateStream.Position = 0;
            readBack = new byte[encoded.Length];
            await privateStream.ReadExactlyAsync(readBack, ct).ConfigureAwait(false);
            ValidateSerializedKey(readBack, passphrase, expectedBlob, validateSignature);
            ct.ThrowIfCancellationRequested();
            publicStream = new FileStream(fullPath + ".pub", FileMode.CreateNew, FileAccess.Write, FileShare.None);
            publicCreated = true;
            await publicStream.WriteAsync(Encoding.ASCII.GetBytes(publicKey + "\n"), ct).ConfigureAwait(false);
            await publicStream.FlushAsync(ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            privateStream.Flush(flushToDisk: true);
            publicStream.Flush(flushToDisk: true);
            publicStream.Dispose(); publicStream = null;
            privateStream.Dispose(); privateStream = null;
            completed = true;
            return publicKey;
        }
        finally
        {
            try { publicStream?.Dispose(); }
            finally
            {
                try { privateStream?.Dispose(); }
                finally
                {
                    Zero(readBack);
                    if (!completed)
                    {
                        // Only paths successfully created by this invocation are removed.
                        try { if (publicCreated) File.Delete(fullPath + ".pub"); }
                        finally { if (privateCreated) File.Delete(fullPath); }
                    }
                }
            }
        }
    }

    private static void ValidateSerializedKey(byte[] bytes, string passphrase, byte[] expectedBlob, Action<PrivateKeyFile> validateSignature)
    {
        using var parsed = OpenPrivateKey(bytes, passphrase);
        var actualBlob = parsed.HostKeyAlgorithms.FirstOrDefault()?.Data ?? throw new CryptographicException("The exported key has no public identity.");
        if (!CryptographicOperations.FixedTimeEquals(actualBlob, expectedBlob))
            throw new CryptographicException("The exported key changed its public identity.");
        validateSignature(parsed);
    }

    private static void ValidateRsaSignature(PrivateKeyFile parsed, RSAParameters expectedPublic)
    {
        if (parsed.Key is not RsaKey rsaKey) throw new CryptographicException("The exported key is not RSA.");
        var parameters = ParametersFromSshKey(rsaKey);
        try
        {
            using var signer = RSA.Create();
            signer.ImportParameters(parameters);
            using var verifier = RSA.Create();
            verifier.ImportParameters(expectedPublic);
            var challenge = RandomNumberGenerator.GetBytes(32);
            var signature = signer.SignData(challenge, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (!verifier.VerifyData(challenge, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                throw new CryptographicException("The exported private key failed its signature check.");
        }
        finally { ClearParameters(parameters); }
    }

    private static void ValidateEd25519Signature(PrivateKeyFile parsed, byte[] expectedPublic)
    {
        if (parsed.Key is not ED25519Key edKey) throw new CryptographicException("The exported key is not Ed25519.");
        var seed = edKey.PrivateKey.ToArray();
        try
        {
            var signer = new Ed25519Signer();
            signer.Init(true, new Ed25519PrivateKeyParameters(seed));
            var challenge = RandomNumberGenerator.GetBytes(32);
            signer.BlockUpdate(challenge, 0, challenge.Length);
            var signature = signer.GenerateSignature();
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(expectedPublic));
            verifier.BlockUpdate(challenge, 0, challenge.Length);
            if (!verifier.VerifySignature(signature))
                throw new CryptographicException("The exported private key failed its Ed25519 signature check.");
        }
        finally { Zero(seed); }
    }

    private static byte[] EncodeEd25519Pkcs8(Ed25519PrivateKeyParameters key, string passphrase)
    {
        var password = passphrase.ToCharArray();
        byte[]? der = null;
        var salt = RandomNumberGenerator.GetBytes(16);
        try
        {
            der = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(NistObjectIdentifiers.IdAes256Cbc,
                PkcsObjectIdentifiers.IdHmacWithSha256, password, salt, 600_000, new SecureRandom(), key).GetEncoded();
            var pem = PemEncoding.WriteUtf8("ENCRYPTED PRIVATE KEY"u8, der);
            var result = new byte[pem.Length + 1];
            pem.CopyTo(result, 0); result[^1] = (byte)'\n';
            return result;
        }
        finally { Array.Clear(password); Zero(der); Zero(salt); }
    }

    private static string EncodeEd25519PublicKey(byte[] publicKey)
    {
        using var stream = new MemoryStream();
        WriteString(stream, Encoding.ASCII.GetBytes("ssh-ed25519"));
        WriteString(stream, publicKey);
        return "ssh-ed25519 " + Convert.ToBase64String(stream.ToArray()) + " @victoryur-SSHHardener";
    }

    private static RSAParameters ParametersFromSshKey(RsaKey key)
    {
        if (key.KeyLength is < 3072 or > 16384) throw new CryptographicException("RSA keys must have between 3072 and 16384 bits.");
        var parameters = new RSAParameters();
        try
        {
            parameters.Modulus = PositiveBytes(key.Modulus);
            parameters.Exponent = PositiveBytes(key.Exponent);
            var size = parameters.Modulus.Length;
            var primeSize = (size + 1) / 2;
            parameters.D = PositiveBytes(key.D, size);
            parameters.P = PositiveBytes(key.P, primeSize);
            parameters.Q = PositiveBytes(key.Q, primeSize);
            parameters.DP = PositiveBytes(key.DP, primeSize);
            parameters.DQ = PositiveBytes(key.DQ, primeSize);
            parameters.InverseQ = PositiveBytes(key.InverseQ, primeSize);
            return parameters;
        }
        catch { ClearParameters(parameters); throw; }
    }

    private static byte[] PositiveBytes(BigInteger value, int? width = null)
    {
        if (value.Sign <= 0) throw new CryptographicException("An RSA private component is missing or invalid.");
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (width is null) return bytes;
        try
        {
            if (bytes.Length > width.Value) throw new CryptographicException("An RSA component exceeds its expected width.");
            var padded = new byte[width.Value];
            bytes.CopyTo(padded.AsSpan(padded.Length - bytes.Length));
            return padded;
        }
        finally { Zero(bytes); }
    }

    private static string ValidateDestination(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (Path.GetFileName(fullPath).IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new ArgumentException("Invalid private key destination.", nameof(path));
        if (File.Exists(fullPath) || File.Exists(fullPath + ".pub") || Directory.Exists(fullPath) || Directory.Exists(fullPath + ".pub"))
            throw new IOException("The private or public key destination already exists; choose a new name.");
        return fullPath;
    }

    private static void ValidatePassphrase(string passphrase)
    {
        if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length < 12)
            throw new ArgumentException("Use a private-key passphrase of at least 12 characters.");
    }

    private static void ClearParameters(RSAParameters p)
    {
        Zero(p.D); Zero(p.P); Zero(p.Q); Zero(p.DP); Zero(p.DQ); Zero(p.InverseQ);
    }

    private static void Zero(byte[]? bytes)
    {
        if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
    }
    private static string EncodePublicKey(RSAParameters p)
    {
        using var stream = new MemoryStream();
        WriteString(stream, Encoding.ASCII.GetBytes("ssh-rsa"));
        WriteMpint(stream, p.Exponent!); WriteMpint(stream, p.Modulus!);
        return "ssh-rsa " + Convert.ToBase64String(stream.ToArray()) + " @victoryur-SSHHardener";
    }
    private static void WriteMpint(Stream stream, byte[] bytes)
    {
        if ((bytes[0] & 0x80) != 0) WriteString(stream, new byte[] { 0 }.Concat(bytes).ToArray());
        else WriteString(stream, bytes);
    }
    private static void WriteString(Stream stream, byte[] data)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, data.Length); stream.Write(length); stream.Write(data);
    }
}
