using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using SSHHardener.Core;
using SSHHardener.Ssh;

namespace SSHHardener.Tests;

public sealed class PuttyKeyTests(PuttyKeyFixture fixture) : IClassFixture<PuttyKeyFixture>
{
    [Fact]
    public void GeneratedPuttyV3IsEncryptedAndRoundTripsThroughActualSshNet()
    {
        var text = File.ReadAllText(fixture.PuttyPath);
        Assert.StartsWith("PuTTY-User-Key-File-3: ssh-rsa", text);
        Assert.Contains("Encryption: aes256-cbc", text);
        Assert.Contains("Key-Derivation: Argon2id", text);
        Assert.Contains("Argon2-Memory: 65536", text);
        Assert.Contains("Argon2-Passes: 3", text);
        Assert.Contains("Argon2-Parallelism: 1", text);
        var derived = new KeyService().ReadPublicKey(fixture.PuttyPath, PuttyKeyFixture.Passphrase);
        InputValidators.ValidatePublicKey(derived);
        Assert.Equal(KeyIdentity(fixture.PublicKey), KeyIdentity(derived));
    }

    [Fact]
    public void WrongPassphraseIsRejectedByActualSshNet() =>
        Assert.ThrowsAny<Exception>(() => new KeyService().ReadPublicKey(fixture.PuttyPath, "an-incorrect-fixture-passphrase"));

    [Theory]
    [InlineData("ciphertext")]
    [InlineData("comment")]
    [InlineData("mac")]
    public void CiphertextAndMacCoveredMetadataTamperingCannotBeImported(string mutation)
    {
        var path = fixture.UniquePath("tampered-" + mutation + ".ppk");
        var lines = File.ReadAllLines(fixture.PuttyPath);
        if (mutation == "comment")
        {
            var index = Array.FindIndex(lines, x => x.StartsWith("Comment:", StringComparison.Ordinal));
            Assert.True(index >= 0);
            lines[index] += " altered";
        }
        else if (mutation == "ciphertext")
        {
            var index = Array.FindIndex(lines, x => x.StartsWith("Private-Lines:", StringComparison.Ordinal)) + 1;
            Assert.True(index > 0 && index < lines.Length);
            var chars = lines[index].ToCharArray();
            chars[0] = chars[0] == 'A' ? 'B' : 'A';
            lines[index] = new string(chars);
        }
        else
        {
            var index = Array.FindIndex(lines, x => x.StartsWith("Private-MAC:", StringComparison.Ordinal));
            Assert.True(index >= 0);
            var chars = lines[index].ToCharArray();
            chars[^1] = chars[^1] == '0' ? '1' : '0';
            lines[index] = new string(chars);
        }
        File.WriteAllLines(path, lines);
        Assert.ThrowsAny<Exception>(() => new KeyService().ReadPublicKey(path, PuttyKeyFixture.Passphrase));
    }

    [Fact]
    public async Task ExportKeepsTheSameRsaIdentityWithoutModifyingSource()
    {
        var destination = fixture.UniquePath("exported.ppk");
        var before = SHA256.HashData(await File.ReadAllBytesAsync(fixture.SourcePath));
        var service = new KeyService();
        const string newPassphrase = "different-export-fixture-passphrase";
        await service.ExportRsaToPuttyAsync(fixture.SourcePath, destination, PuttyKeyFixture.Passphrase, newPassphrase, CancellationToken.None);
        Assert.Equal(before, SHA256.HashData(await File.ReadAllBytesAsync(fixture.SourcePath)));
        var sourceKey = service.ReadPublicKey(fixture.SourcePath, PuttyKeyFixture.Passphrase);
        var exportedKey = service.ReadPublicKey(destination, newPassphrase);
        Assert.Equal(KeyIdentity(sourceKey), KeyIdentity(exportedKey));
        Assert.Equal(KeyService.Fingerprint(sourceKey), KeyService.Fingerprint(exportedKey));
        Assert.Equal(KeyIdentity(exportedKey), KeyIdentity((await File.ReadAllTextAsync(destination + ".pub")).Trim()));
        Assert.ThrowsAny<Exception>(() => service.ReadPublicKey(destination, PuttyKeyFixture.Passphrase));
        AssertPrivateAcl(destination);
    }

    [Fact]
    public async Task FailedSourceDecryptionLeavesNoPartialExportPair()
    {
        var destination = fixture.UniquePath("wrong-source-pass.ppk");
        await Assert.ThrowsAnyAsync<Exception>(() => new KeyService().ExportRsaToPuttyAsync(fixture.SourcePath,
            destination, "incorrect-source-fixture-passphrase", PuttyKeyFixture.Passphrase, CancellationToken.None));
        Assert.False(File.Exists(destination));
        Assert.False(File.Exists(destination + ".pub"));
    }

    [Fact]
    public async Task ExistingPublicSidecarIsPreservedAndNoPrivateFileIsCreated()
    {
        var destination = fixture.UniquePath("collision.ppk");
        await File.WriteAllTextAsync(destination + ".pub", "unrelated public fixture text");
        await Assert.ThrowsAnyAsync<IOException>(() => new KeyService().ExportRsaToPuttyAsync(fixture.SourcePath,
            destination, PuttyKeyFixture.Passphrase, PuttyKeyFixture.Passphrase, CancellationToken.None));
        Assert.False(File.Exists(destination));
        Assert.Equal("unrelated public fixture text", await File.ReadAllTextAsync(destination + ".pub"));
    }

    [Fact]
    public async Task ExistingPrivateDestinationCannotBeOverwritten()
    {
        var before = SHA256.HashData(await File.ReadAllBytesAsync(fixture.PuttyPath));
        await Assert.ThrowsAnyAsync<IOException>(() => new KeyService().ExportRsaToPuttyAsync(fixture.SourcePath,
            fixture.PuttyPath, PuttyKeyFixture.Passphrase, PuttyKeyFixture.Passphrase, CancellationToken.None));
        Assert.Equal(before, SHA256.HashData(await File.ReadAllBytesAsync(fixture.PuttyPath)));
    }

    [Fact]
    public void GeneratedPrivateFileGrantsAccessOnlyToCurrentWindowsUser() => AssertPrivateAcl(fixture.PuttyPath);

    private static void AssertPrivateAcl(string path)
    {
        var owner = WindowsIdentity.GetCurrent().User;
        Assert.NotNull(owner);
        var acl = new FileInfo(path).GetAccessControl();
        Assert.True(acl.AreAccessRulesProtected);
        var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        Assert.NotEmpty(rules);
        Assert.All(rules, rule =>
        {
            Assert.Equal(owner, rule.IdentityReference);
            Assert.False(rule.IsInherited);
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
        });
    }

    private static string KeyIdentity(string key) => string.Join(' ', key.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Take(2));
}

public sealed class PuttyKeyFixture : IAsyncLifetime
{
    internal const string Passphrase = "public-fixture-passphrase-not-a-user-secret";
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "ssh-hardener-putty-tests-" + Guid.NewGuid().ToString("N"));
    public string PuttyPath => Path.Combine(_directory, "generated.ppk");
    public string SourcePath => Path.Combine(_directory, "source.pem");
    public string PublicKey { get; private set; } = "";
    public string UniquePath(string suffix) => Path.Combine(_directory, Guid.NewGuid().ToString("N") + "-" + suffix);

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        var service = new KeyService();
        PublicKey = await service.GenerateRsaAsync(PuttyPath, Passphrase, CancellationToken.None, PrivateKeyFormat.EncryptedPuttyV3);
        await service.GenerateRsaAsync(SourcePath, Passphrase, CancellationToken.None);
    }

    public Task DisposeAsync()
    {
        foreach (var path in Directory.GetFiles(_directory)) File.Delete(path);
        Directory.Delete(_directory);
        return Task.CompletedTask;
    }
}
