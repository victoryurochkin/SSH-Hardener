using SSHHardener.Core;

namespace SSHHardener.Tests;

public sealed class TotpTests
{
    private const string Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    // RFC 6238 Appendix B SHA-1 vectors, reduced modulo 10^6 for this API's six digits.
    [Theory]
    [InlineData(59L, "287082")]
    [InlineData(1111111109L, "081804")]
    [InlineData(1111111111L, "050471")]
    [InlineData(1234567890L, "005924")]
    [InlineData(2000000000L, "279037")]
    [InlineData(20000000000L, "353130")]
    public void MatchesRfc6238Sha1Vectors(long seconds, string expected)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(seconds);
        Assert.Equal(expected, TotpService.GenerateCode(Secret, now));
        Assert.True(TotpService.VerifyCode(Secret, expected, now, 0));
    }

    [Fact]
    public void WindowAllowsOnlyConfiguredAdjacentSteps()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_234_567_890);
        foreach (var delta in new[] { -30, 0, 30 })
        {
            var code = TotpService.GenerateCode(Secret, now.AddSeconds(delta));
            Assert.True(TotpService.VerifyCode(Secret, code, now));
            Assert.Equal(delta == 0, TotpService.VerifyCode(Secret, code, now, 0));
        }
        Assert.False(TotpService.VerifyCode(Secret, TotpService.GenerateCode(Secret, now.AddSeconds(60)), now));
        Assert.Equal(TotpService.GenerateCode(Secret, now), TotpService.GenerateCode(Secret, now.AddSeconds(29)));
        Assert.NotEqual(TotpService.GenerateCode(Secret, now), TotpService.GenerateCode(Secret, now.AddSeconds(30)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("123456\n")]
    [InlineData("１２３４５６")]
    [InlineData("123 56")]
    public void MalformedCodesAreRejected(string code) =>
        Assert.False(TotpService.VerifyCode(Secret, code, DateTimeOffset.UtcNow));

    [Theory]
    [InlineData("")]
    [InlineData("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ=")]
    [InlineData("gezdgnbvgy3tqojqgezdgnbvgy3tqojq")]
    [InlineData("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJ0")]
    [InlineData("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJ\n")]
    public void SecretIsStrictCanonical160BitBase32(string secret) =>
        Assert.Throws<ArgumentException>(() => TotpService.ValidateSecret(secret));

    [Fact]
    public void GeneratedSecretsAndRecoveryCodesHaveRequiredEntropyAndShape()
    {
        var secrets = Enumerable.Range(0, 32).Select(_ => TotpService.GenerateSecret()).ToArray();
        Assert.Equal(secrets.Length, secrets.Distinct().Count());
        Assert.All(secrets, TotpService.ValidateSecret);
        var codes = TotpService.GenerateRecoveryCodes();
        TotpService.ValidateRecoveryCodes(codes);
        Assert.Equal(8, codes.Count);
        Assert.Equal(8, codes.Distinct().Count());
        Assert.All(codes, c => Assert.Matches("\\A[1-9][0-9]{7}\\z", c));
    }

    [Fact]
    public void InvalidRecoverySetsAndBoundsAreRejected()
    {
        var codes = TotpService.GenerateRecoveryCodes().ToArray();
        Assert.Throws<ArgumentException>(() => TotpService.ValidateRecoveryCodes(codes.Take(7)));
        Assert.Throws<ArgumentException>(() => TotpService.ValidateRecoveryCodes(codes.Concat(["12345678"])));
        codes[1] = codes[0];
        Assert.Throws<ArgumentException>(() => TotpService.ValidateRecoveryCodes(codes));
        codes = TotpService.GenerateRecoveryCodes().ToArray(); codes[0] = "01234567";
        Assert.Throws<ArgumentException>(() => TotpService.ValidateRecoveryCodes(codes));
        Assert.Throws<ArgumentOutOfRangeException>(() => TotpService.VerifyCode(Secret, "123456", DateTimeOffset.UtcNow, -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => TotpService.VerifyCode(Secret, "123456", DateTimeOffset.UtcNow, 11));
        Assert.Throws<ArgumentOutOfRangeException>(() => TotpService.GenerateCode(Secret, DateTimeOffset.UnixEpoch.AddTicks(-1)));
    }

    [Fact]
    public void EpochDoesNotAcceptNegativeTimeSteps() =>
        Assert.True(TotpService.VerifyCode(Secret, TotpService.GenerateCode(Secret, DateTimeOffset.UnixEpoch), DateTimeOffset.UnixEpoch));
}
