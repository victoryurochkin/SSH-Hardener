using Renci.SshNet;
using SSHHardener.Ssh;

namespace SSHHardener.Tests;

public sealed class AlgorithmPolicyTests
{
    [Fact]
    public void LegacyAlgorithmsAreNotOfferedAndModernRsaRemainsAvailable()
    {
        var connection = new ConnectionInfo("server.example", "admin", new PasswordAuthenticationMethod("admin", "fixture"));
        SshAlgorithmPolicy.Apply(connection);
        Assert.DoesNotContain(connection.KeyExchangeAlgorithms.Keys, x => x.Contains("sha1", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(connection.Encryptions.Keys, x => x.EndsWith("-cbc", StringComparison.Ordinal));
        Assert.DoesNotContain(connection.HmacAlgorithms.Keys, x => x.Contains("sha1", StringComparison.OrdinalIgnoreCase) || x.Contains("md5", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain("ssh-rsa", connection.HostKeyAlgorithms.Keys);
        Assert.DoesNotContain("ssh-dss", connection.HostKeyAlgorithms.Keys);
        Assert.Contains("rsa-sha2-512", connection.HostKeyAlgorithms.Keys);
        Assert.NotEmpty(connection.Encryptions);
        Assert.NotEmpty(connection.KeyExchangeAlgorithms);
    }
}
