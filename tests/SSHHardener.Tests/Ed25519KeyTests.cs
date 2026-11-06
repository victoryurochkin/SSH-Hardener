using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Renci.SshNet;
using Renci.SshNet.Security;
using SSHHardener.Ssh;

namespace SSHHardener.Tests;

public sealed class Ed25519KeyTests(Ed25519KeyFixture fixture) : IClassFixture<Ed25519KeyFixture>
{
    [Theory]
    [InlineData("generated.ppk")]
    [InlineData("generated.pem")]
    [InlineData("exported.ppk")]
    public void EncryptedKeysRoundTripWithExpectedIdentityAndPrivateSignature(string filename)
    {
        var path = fixture.PathFor(filename);
        var publicKey = new KeyService().ReadPublicKey(path, Ed25519KeyFixture.Passphrase);
        Assert.StartsWith("ssh-ed25519 ", publicKey);
        Assert.Equal(publicKey, File.ReadAllText(path + ".pub").Trim());
        using var imported = KeyService.OpenPrivateKey(path, Ed25519KeyFixture.Passphrase);
        var ed = Assert.IsType<ED25519Key>(imported.Key);
        Assert.Equal(32, ed.PrivateKey.Length);
        Assert.Equal(32, ed.PublicKey.Length);
        var challenge = RandomNumberGenerator.GetBytes(32);
        var algorithm = imported.HostKeyAlgorithms.First();
        var signature = algorithm.Sign(challenge);
        Assert.True(algorithm.VerifySignature(challenge, signature));
        Assert.ThrowsAny<Exception>(() => KeyService.OpenPrivateKey(path, "incorrect-fixture-passphrase"));
        AssertPrivateAcl(path);
    }

    [Fact]
    public void GeneratedPpkUsesEncryptedAuthenticatedArgon2idV3Container()
    {
        var text = File.ReadAllText(fixture.PathFor("generated.ppk"));
        Assert.StartsWith("PuTTY-User-Key-File-3: ssh-ed25519", text);
        Assert.Contains("Encryption: aes256-cbc", text);
        Assert.Contains("Key-Derivation: Argon2id", text);
        Assert.Contains("Argon2-Memory: 65536", text);
        Assert.Contains("Argon2-Passes: 3", text);
        Assert.Contains("Argon2-Parallelism: 1", text);
        using var directSshNet = new PrivateKeyFile(fixture.PathFor("generated.ppk"), Ed25519KeyFixture.Passphrase);
        Assert.IsType<ED25519Key>(directSshNet.Key);
    }

    [Fact]
    public void StandardRfc8410NestedOctetSeedHasKnownRfc8032Identity()
    {
        // RFC 8032 test 1; public fixture key, never used against a real server.
        var seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var der = Convert.FromHexString("302e020100300506032b657004220420").Concat(seed).ToArray();
        var path = fixture.UniquePath("rfc8410.pem");
        try
        {
            File.WriteAllText(path, "\uFEFF\n" + PemEncoding.WriteString("PRIVATE KEY", der), new UTF8Encoding(false));
            using var key = KeyService.OpenPrivateKey(path);
            var ed = Assert.IsType<ED25519Key>(key.Key);
            Assert.Equal(seed, ed.PrivateKey);
            Assert.Equal("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", Convert.ToHexStringLower(ed.PublicKey));
        }
        finally { CryptographicOperations.ZeroMemory(seed); CryptographicOperations.ZeroMemory(der); }
    }

    [Fact]
    public async Task SameKeyExportPreservesSourceAndFingerprint()
    {
        var source = fixture.PathFor("generated.pem");
        var exported = fixture.PathFor("exported.ppk");
        var service = new KeyService();
        Assert.Equal(fixture.SourceHash, SHA256.HashData(await File.ReadAllBytesAsync(source)));
        Assert.Equal(KeyService.Fingerprint(service.ReadPublicKey(source, Ed25519KeyFixture.Passphrase)),
            KeyService.Fingerprint(service.ReadPublicKey(exported, Ed25519KeyFixture.Passphrase)));
        var reexport = fixture.UniquePath("reexport.ppk");
        var expected = service.ReadPublicKey(fixture.PathFor("generated.ppk"), Ed25519KeyFixture.Passphrase);
        var actual = await service.ExportToPuttyAsync(fixture.PathFor("generated.ppk"), reexport,
            Ed25519KeyFixture.Passphrase, Ed25519KeyFixture.Passphrase);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("comment")]
    [InlineData("ciphertext")]
    [InlineData("mac")]
    public void PpkTamperingFailsAuthentication(string mutation)
    {
        var lines = File.ReadAllLines(fixture.PathFor("generated.ppk"));
        var path = fixture.UniquePath("tampered.ppk");
        var index = mutation switch
        {
            "comment" => Array.FindIndex(lines, line => line.StartsWith("Comment:")),
            "ciphertext" => Array.FindIndex(lines, line => line.StartsWith("Private-Lines:")) + 1,
            _ => Array.FindIndex(lines, line => line.StartsWith("Private-MAC:"))
        };
        if (mutation == "comment") lines[index] += " changed";
        else
        {
            var characters = lines[index].ToCharArray();
            var offset = mutation == "ciphertext" ? 0 : characters.Length - 1;
            characters[offset] = characters[offset] == 'A' ? 'B' : 'A';
            lines[index] = new string(characters);
        }
        File.WriteAllLines(path, lines);
        Assert.ThrowsAny<Exception>(() => KeyService.OpenPrivateKey(path, Ed25519KeyFixture.Passphrase));
    }

    [Fact]
    public async Task CollisionsCancellationAndBadPassphraseLeaveExistingFilesUnchanged()
    {
        var service = new KeyService();
        var source = fixture.PathFor("generated.pem");
        var destination = fixture.UniquePath("existing.ppk");
        await File.WriteAllTextAsync(destination + ".pub", "preexisting sidecar");
        await Assert.ThrowsAsync<IOException>(() => service.GenerateEd25519Async(destination, Ed25519KeyFixture.Passphrase));
        Assert.False(File.Exists(destination));
        Assert.Equal("preexisting sidecar", await File.ReadAllTextAsync(destination + ".pub"));
        await Assert.ThrowsAsync<IOException>(() => service.ExportToPuttyAsync(source, source,
            Ed25519KeyFixture.Passphrase, Ed25519KeyFixture.Passphrase));
        var failed = fixture.UniquePath("failed.ppk");
        await Assert.ThrowsAnyAsync<Exception>(() => service.ExportToPuttyAsync(source, failed, "wrong-fixture-password", Ed25519KeyFixture.Passphrase));
        Assert.False(File.Exists(failed)); Assert.False(File.Exists(failed + ".pub"));
        var cancelled = fixture.UniquePath("cancelled.ppk");
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.GenerateEd25519Async(cancelled,
            Ed25519KeyFixture.Passphrase, new CancellationToken(true)));
        Assert.False(File.Exists(cancelled)); Assert.False(File.Exists(cancelled + ".pub"));
        var invalid = fixture.UniquePath("short.ppk");
        await Assert.ThrowsAsync<ArgumentException>(() => service.GenerateEd25519Async(invalid, "short"));
        Assert.False(File.Exists(invalid));
    }

    private static void AssertPrivateAcl(string path)
    {
        var sid = WindowsIdentity.GetCurrent().User;
        var acl = new FileInfo(path).GetAccessControl();
        Assert.True(acl.AreAccessRulesProtected);
        Assert.All(acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(), rule =>
        {
            Assert.Equal(sid, rule.IdentityReference);
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.False(rule.IsInherited);
        });
    }
}

public sealed class Ed25519KeyFixture : IAsyncLifetime
{
    public const string Passphrase = "public-ed25519-fixture-not-user-secret";
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "sshhardener-ed25519-" + Guid.NewGuid().ToString("N"));
    public byte[] SourceHash { get; private set; } = [];
    public string PathFor(string name) => Path.Combine(_directory, name);
    public string UniquePath(string suffix) => PathFor(Guid.NewGuid().ToString("N") + "-" + suffix);

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        var service = new KeyService();
        await service.GenerateEd25519Async(PathFor("generated.ppk"), Passphrase);
        await service.GenerateEd25519Async(PathFor("generated.pem"), Passphrase, format: PrivateKeyFormat.EncryptedPkcs8Pem);
        SourceHash = SHA256.HashData(await File.ReadAllBytesAsync(PathFor("generated.pem")));
        await service.ExportToPuttyAsync(PathFor("generated.pem"), PathFor("exported.ppk"), Passphrase, Passphrase);
    }

    public Task DisposeAsync()
    {
        foreach (var path in Directory.GetFiles(_directory)) File.Delete(path);
        Directory.Delete(_directory);
        return Task.CompletedTask;
    }
}
