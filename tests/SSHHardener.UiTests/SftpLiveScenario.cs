using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SSHHardener.App;
using SSHHardener.Core;
using SSHHardener.Ssh;

namespace SSHHardener.UiTests;

/// <summary>Opt-in loopback-only integration against the disposable Docker fixture; never uses user credentials.</summary>
internal static class SftpLiveScenario
{
    private const string Passphrase = "public-disposable-sftp-fixture-passphrase";
    internal static async Task PrepareAsync(string directory)
    {
        Directory.CreateDirectory(directory);
        await new KeyService().GenerateEd25519Async(Path.Combine(directory, "fixture.ppk"), Passphrase);
    }

    internal static async Task RunAsync(string configurationPath, List<string> outcomes)
    {
        var config = JsonSerializer.Deserialize<FixtureConfig>(await File.ReadAllTextAsync(configurationPath))
            ?? throw new InvalidOperationException("Missing fixture config.");
        Require(config.Kind == "SSHHardener-disposable-sftp-test" && config.Port is > 0 and <= 65535, "fixture identity");
        var directory = Path.GetDirectoryName(Path.GetFullPath(configurationPath))!;
        var publicKey = (await File.ReadAllTextAsync(Path.Combine(directory, "host.pub"))).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var blob = Convert.FromBase64String(publicKey[1]);
        var pin = new HostIdentity("127.0.0.1", config.Port, publicKey[0], "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('='), publicKey[1]);
        var factory = new SftpSessionFactory(new KnownHostsStore(Path.Combine(directory, "trust")));
        var connection = new ConnectionOptions("127.0.0.1", config.Port, "sftp_rw", PrivateKeyPath: Path.Combine(directory, "fixture.ppk"), Passphrase: Passphrase);
        Task<bool> Trust(HostIdentity candidate) => Task.FromResult(candidate.Algorithm == pin.Algorithm && candidate.KeyBase64 == pin.KeyBase64);
        await using (var session = await factory.ConnectSftpAsync(connection, Trust, CancellationToken.None))
        {
            var initial = await session.ListAsync("/uploads", CancellationToken.None);
            Require(initial.Any(entry => entry.Name == "seed.txt" && !entry.IsSymbolicLink), "real seed listing");
            Require(initial.Any(entry => entry.Name == "file-link" && entry.IsSymbolicLink), "READDIR preserves leaf symlink metadata");
            foreach (var path in new[] { "/uploads/file-link", "/uploads/folder-link/write.txt", "/uploads/dangling-link" })
                await MustFailAsync(() => session.UploadAsync(new MemoryStream("blocked"u8.ToArray()), path, true, CancellationToken.None), "symlink write rejected");
            await MustFailAsync(() => session.UploadAsync(new MemoryStream("overwrite"u8.ToArray()), "/uploads/seed.txt", false, CancellationToken.None), "existing target preserved");
            using var content = new MemoryStream(); await session.DownloadAsync("/uploads/seed.txt", content, CancellationToken.None);
            Require(Encoding.UTF8.GetString(content.ToArray()) == "public seed contents\n", "no-overwrite kept original bytes");
            await using var source = new CancelledSource();
            using var cancel = new CancellationTokenSource();
            var transfer = session.UploadAsync(source, "/uploads/cancelled-partial.txt", false, cancel.Token);
            await source.Waiting.Task.WaitAsync(TimeSpan.FromSeconds(10)); cancel.Cancel();
            try { await transfer; throw new InvalidOperationException("Cancellation was ignored."); } catch (OperationCanceledException) { }
            Require(!(await session.ListAsync("/uploads", CancellationToken.None)).Any(entry => entry.Name == "cancelled-partial.txt"), "real cancelled upload removes its own partial file");
        }
        var verifier = new TargetAccessVerifier(new NoShellFactory(), factory);
        await verifier.VerifyAsync(connection, pin, new TargetAccessExpectation(AccountAccess.SftpOnly, SudoPolicyMode.None, [], false, true), CancellationToken.None);
        await verifier.VerifyAsync(connection with { Username = "sftp_ro" }, pin,
            new TargetAccessExpectation(AccountAccess.SftpOnly, SudoPolicyMode.None, [], true, true), CancellationToken.None);
        await MustFailAsync(() => factory.ConnectSftpAsync(connection, _ => Task.FromResult(false), CancellationToken.None), "pin rejection before authentication");

        await using var vm = new SftpBrowserViewModel(factory, connection, new SSHHardener.App.Localization())
        {
            ReadSecrets = () => new SftpConnectionSecrets("", Passphrase), TrustHost = Trust
        };
        await vm.ConnectAsync(); Require(vm.CanBrowse, "real browser connects");
        vm.SelectedEntry = vm.Entries.Single(entry => entry.Name == "uploads"); await vm.OpenSelectedAsync();
        Require(vm.DirectoryPath == "/uploads" && vm.CanMutate, "real browser enters chroot upload directory");
        var upload = Path.Combine(directory, "browser-transfer.txt"); await File.WriteAllTextAsync(upload, "public browser transfer contents");
        await vm.UploadAsync(upload); Require(vm.Entries.Any(entry => entry.Name == "browser-transfer.txt"), "real browser upload");
        vm.SelectedEntry = vm.Entries.Single(entry => entry.Name == "browser-transfer.txt");
        var download = Path.Combine(directory, "browser-downloaded-" + Guid.NewGuid().ToString("N") + ".txt"); await vm.DownloadSelectedAsync(download);
        Require(await File.ReadAllTextAsync(download) == "public browser transfer contents", "real browser download");
        await vm.RenameSelectedAsync("browser-renamed.txt"); Require(vm.Entries.Any(entry => entry.Name == "browser-renamed.txt"), "real browser rename");
        vm.SelectedEntry = vm.Entries.Single(entry => entry.Name == "browser-renamed.txt"); await vm.DeleteSelectedAsync();
        Require(!vm.Entries.Any(entry => entry.Name.StartsWith("browser-", StringComparison.Ordinal)), "real browser delete");
        await vm.CreateDirectoryAsync("browser-folder"); vm.SelectedEntry = vm.Entries.Single(entry => entry.Name == "browser-folder"); await vm.DeleteSelectedAsync();
        Require(!vm.Entries.Any(entry => entry.Name == "browser-folder"), "real empty folder create/delete");
        outcomes.Add("PASS: loopback Docker production SFTP + browser VM actual upload/download/rename/mkdir/delete, RW/RO verification, symlink components, no-overwrite, cancellation partial cleanup and host-pin rejection.");
    }

    private static void Require(bool result, string reason) { if (!result) throw new InvalidOperationException(reason); }
    private static async Task MustFailAsync(Func<Task> operation, string reason)
    {
        var failed = false; try { await operation(); } catch (OperationCanceledException) { throw; } catch { failed = true; }
        Require(failed, reason);
    }
    private sealed record FixtureConfig(string Kind, int Port);
    private sealed class NoShellFactory : IRemoteSessionFactory
    {
        public Task<IRemoteSession> ConnectAsync(ConnectionOptions options, Func<HostIdentity, Task<bool>> trustHost, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("An SFTP-only final verifier must never open a shell.");
    }
    private sealed class CancelledSource : Stream
    {
        private bool _first = true;
        public TaskCompletionSource Waiting { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_first) { _first = false; buffer.Span[..16].Fill(42); return 16; }
            Waiting.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return 0;
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
