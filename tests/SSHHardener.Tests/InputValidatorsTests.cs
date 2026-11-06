using System.Buffers.Binary;
using System.Text;
using SSHHardener.Core;

namespace SSHHardener.Tests;

public sealed class InputValidatorsTests
{
    internal static string Ed25519Key => PublicKey("ssh-ed25519", Encoding.ASCII.GetBytes("ssh-ed25519"), Enumerable.Range(1, 32).Select(x => (byte)x).ToArray());
    internal static HardeningOptions ValidOptions => new() { PublicKey = Ed25519Key, PrivateKeyPath = "selected-key.pem", Username = "sshadmin" };

    [Theory]
    [InlineData("sshadmin\n")]
    [InlineData("sshadmin;id")]
    [InlineData("$(id)")]
    [InlineData("-root")]
    [InlineData("root")]
    public void UnsafeOrReservedUsernamesAreRejected(string user) =>
        Assert.Throws<ArgumentException>(() => InputValidators.Validate(ValidOptions with { Username = user }));

    [Theory]
    [InlineData(0)]
    [InlineData(-22)]
    [InlineData(65536)]
    public void OutOfRangePortsAreRejected(int port) =>
        Assert.Throws<ArgumentException>(() => InputValidators.Validate(ValidOptions with { NewPort = port }));

    [Theory]
    [InlineData("192.0.2.1")]
    [InlineData("192.0.2.0/24")]
    [InlineData("2001:db8::/32")]
    [InlineData("::1")]
    public void IpAndCidrWhitelistEntriesAreAccepted(string address) => InputValidators.ValidateAddress(address);

    [Theory]
    [InlineData("example.com")]
    [InlineData("192.0.2.0/33")]
    [InlineData("::/129")]
    [InlineData("192.0.2.1;id")]
    [InlineData("fe80::1%eth0")]
    [InlineData("192.0.2.1/24/1")]
    public void InvalidWhitelistEntriesAreRejected(string address) =>
        Assert.Throws<ArgumentException>(() => InputValidators.ValidateAddress(address));

    [Fact]
    public void PublicKeyMustMatchItsWireType()
    {
        var key = Ed25519Key.Replace("ssh-ed25519 ", "ssh-rsa ", StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => InputValidators.ValidatePublicKey(key));
    }

    [Fact]
    public void AppendedWireDataIsRejected()
    {
        var parts = Ed25519Key.Split(' ');
        var data = Convert.FromBase64String(parts[1]).Concat(new byte[] { 1 }).ToArray();
        Assert.Throws<ArgumentException>(() => InputValidators.ValidatePublicKey("ssh-ed25519 " + Convert.ToBase64String(data)));
    }

    [Theory]
    [InlineData("\ncommand=\"id\"")]
    [InlineData("\rssh-rsa AAAA")]
    [InlineData("\0")]
    public void MultilineKeysAreRejected(string suffix) =>
        Assert.Throws<ArgumentException>(() => InputValidators.ValidatePublicKey(Ed25519Key + suffix));

    [Fact]
    public void AuthorizedKeysOptionsCannotBeInjectedBeforeKey() =>
        Assert.Throws<ArgumentException>(() => InputValidators.ValidatePublicKey("command=\"id\" " + Ed25519Key));

    [Fact]
    public void WeakRsaIsRejected()
    {
        var modulus = new byte[257]; modulus[1] = 0x80;
        var key = PublicKey("ssh-rsa", Encoding.ASCII.GetBytes("ssh-rsa"), [1, 0, 1], modulus);
        Assert.Throws<ArgumentException>(() => InputValidators.ValidatePublicKey(key));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void InvalidRsaExponentIsRejected(byte exponent)
    {
        var modulus = new byte[385]; modulus[1] = 0x80;
        var key = PublicKey("ssh-rsa", Encoding.ASCII.GetBytes("ssh-rsa"), [exponent], modulus);
        Assert.Throws<ArgumentException>(() => InputValidators.ValidatePublicKey(key));
    }

    [Fact]
    public void PrivateKeyProofIsRequired() =>
        Assert.Throws<ArgumentException>(() => InputValidators.Validate(ValidOptions with { PrivateKeyPath = "" }));

    [Fact]
    public void PasswordSudoProvisioningIsNotSilentlyDowngraded() =>
        Assert.Throws<ArgumentException>(() => InputValidators.Validate(ValidOptions with { GrantSudo = true, NoPasswordSudo = false }));

    [Fact]
    public void NopasswdNeedsExplicitSudoRole() =>
        Assert.Throws<ArgumentException>(() => InputValidators.Validate(ValidOptions with { NoPasswordSudo = true, GrantSudo = false }));

    [Fact]
    public void ShellQuotePreservesSingleArgumentBoundaries() =>
        Assert.Equal("'a'\"'\"'; $(id)\n'", Shell.Quote("a'; $(id)\n"));

    [Fact]
    public void ShellNulCannotBeTruncatedByRemoteShell() =>
        Assert.Throws<ArgumentException>(() => Shell.Quote("safe\0;id"));

    private static string PublicKey(string kind, params byte[][] fields)
    {
        using var wire = new MemoryStream();
        Span<byte> size = stackalloc byte[4];
        foreach (var field in fields)
        {
            BinaryPrimitives.WriteUInt32BigEndian(size, (uint)field.Length);
            wire.Write(size); wire.Write(field);
        }
        return kind + " " + Convert.ToBase64String(wire.ToArray()) + " test-only";
    }
}
