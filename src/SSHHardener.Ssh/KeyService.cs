using System.Buffers.Binary;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Renci.SshNet;

namespace SSHHardener.Ssh;

public sealed class KeyService
{
    /// <summary>RSA 4096 in encrypted PKCS#8 PEM; intentionally uses established framework crypto.</summary>
    public async Task<string> GenerateRsaAsync(string path, string passphrase, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length < 12)
            throw new ArgumentException("Use a private-key passphrase of at least 12 characters.");
        var fullPath = Path.GetFullPath(path);
        if (File.Exists(fullPath) || File.Exists(fullPath + ".pub")) throw new IOException("Key file already exists; choose a new name.");
        return await Task.Run(async () =>
        {
            using var rsa = RSA.Create(4096);
            ct.ThrowIfCancellationRequested();
            var pem = rsa.ExportEncryptedPkcs8PrivateKeyPem(passphrase,
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000));
            var publicKey = EncodePublicKey(rsa.ExportParameters(false));
            // CreateNew plus an exclusive current-user ACL BEFORE writing any private material.
            var sid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("Cannot identify Windows user.");
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
            var created = false;
            try
            {
                using (var stream = new FileInfo(fullPath).Create(FileMode.CreateNew, FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, security))
                {
                    created = true;
                    var bytes = Encoding.ASCII.GetBytes(pem + "\n");
                    try { await stream.WriteAsync(bytes, ct).ConfigureAwait(false); }
                    finally { CryptographicOperations.ZeroMemory(bytes); }
                }
                // Validate the actual exported representation using the same parser as connections.
                var parsed = ReadPublicKey(fullPath, passphrase);
                if (parsed.Split(' ')[1] != publicKey.Split(' ')[1]) throw new CryptographicException("Key export did not round-trip.");
                using (var publicStream = new FileStream(fullPath + ".pub", FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    var publicBytes = Encoding.ASCII.GetBytes(publicKey + "\n");
                    await publicStream.WriteAsync(publicBytes, ct).ConfigureAwait(false);
                }
                return publicKey;
            }
            catch { if (created) File.Delete(fullPath); throw; }
        }, ct).ConfigureAwait(false);
    }

    public string ReadPublicKey(string path, string? passphrase = null)
    {
        using var key = new PrivateKeyFile(path, passphrase);
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
