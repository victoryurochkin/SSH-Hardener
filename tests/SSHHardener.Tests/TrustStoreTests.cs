using SSHHardener.Core;
using SSHHardener.Ssh;

namespace SSHHardener.Tests;

public sealed class TrustStoreTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "sshhardener-tests-" + Guid.NewGuid().ToString("N"));
    private static HostIdentity Identity => new("server.example", 22, "ssh-ed25519", "SHA256:test", "dGVzdC1ob3N0LWtleQ==");

    [Fact]
    public async Task FirstContactRejectionDoesNotPersistTrust()
    {
        var store = new KnownHostsStore(_folder);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.VerifyAsync(Identity, _ => Task.FromResult(false), CancellationToken.None));
        Assert.False(File.Exists(Path.Combine(_folder, "known-hosts.json")));
    }

    [Fact]
    public async Task ChangedKeyIsRejectedWithoutOfferingToOverwrite()
    {
        var store = new KnownHostsStore(_folder);
        await store.VerifyAsync(Identity, _ => Task.FromResult(true), CancellationToken.None);
        var prompted = false;
        await Assert.ThrowsAsync<HostKeyChangedException>(() => store.VerifyAsync(Identity with { KeyBase64 = "YXR0YWNrZXI=" }, _ =>
        {
            prompted = true;
            return Task.FromResult(true);
        }, CancellationToken.None));
        Assert.False(prompted);
    }

    [Fact]
    public async Task PinnedConnectionPolicyStillRunsForKnownEndpoint()
    {
        var store = new KnownHostsStore(_folder);
        await store.VerifyAsync(Identity, _ => Task.FromResult(true), CancellationToken.None);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.VerifyAsync(Identity, _ => Task.FromResult(false), CancellationToken.None));
    }

    public void Dispose()
    {
        if (!Directory.Exists(_folder)) return;
        foreach (var file in Directory.GetFiles(_folder)) File.Delete(file);
        Directory.Delete(_folder);
    }
}
