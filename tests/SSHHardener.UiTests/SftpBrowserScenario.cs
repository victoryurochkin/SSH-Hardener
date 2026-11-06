using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using SSHHardener.App;
using SSHHardener.Core;

namespace SSHHardener.UiTests;

internal static class SftpBrowserScenario
{
    internal static async Task RunAsync(Dispatcher dispatcher, string directory, List<string> outcomes)
    {
        var snapshots = Path.GetFullPath(Path.Combine("artifacts", "sftp-browser"));
        Directory.CreateDirectory(snapshots);
        foreach (var english in new[] { false, true })
        {
            var l = new SSHHardener.App.Localization(); if (english) l.Toggle();
            var palette = SetPalette(english);
            var factory = new FixtureFactory();
            Func<CancellationToken, Task<string>> originalOtp = _ => Task.FromResult("123456");
            var initial = new ConnectionOptions("fixture.invalid", 22, "sftp-fixture", Password: "initial-must-not-be-reused",
                Passphrase: "initial-phrase-must-not-be-reused") { OneTimeCodeProvider = originalOtp };
            await using var vm = new SftpBrowserViewModel(factory, initial, l);
            var window = new SftpWindow(vm)
            {
                Left = -30000, Top = -30000, Width = 920, Height = 820,
                WindowStartupLocation = WindowStartupLocation.Manual, ShowActivated = false, ShowInTaskbar = false
            };
            try
            {
                window.Show();
                var clears = 0;
                vm.ReadSecrets = () => new SftpConnectionSecrets("entered-public-fixture-password", "entered-public-fixture-phrase");
                vm.ClearSecrets = () => clears++;
                await vm.ConnectAsync();
                Require(vm.CanBrowse && vm.Entries.Count == 1, "SFTP connected and root listing bound");
                Require(factory.LastConnection?.Password == "entered-public-fixture-password", "source password is read only on explicit connect");
                Require(factory.LastConnection?.Passphrase == "entered-public-fixture-phrase", "source key phrase uses explicit secret delegate");
                Require(factory.LastConnection?.OneTimeCodeProvider == originalOtp, "same-endpoint source MFA callback preserved");
                Require(clears == 1, "secret fields cleared after connect attempt");
                vm.SelectedEntry = vm.Entries.Single();
                await vm.OpenSelectedAsync();
                Require(vm.DirectoryPath == "/uploads" && vm.Entries.Count == 5, "folder navigation and populated listing");
                var file = vm.Entries.Single(entry => entry.Name == "readme.txt");
                vm.SelectedEntry = file;
                Require(vm.CanDownload, "file selected and download enabled");
                var before = factory.Session.Mutations;
                vm.Host = "other-fixture.invalid";
                Require(!vm.CanBrowse && !vm.CanMutate, "editing endpoint disables old-session actions");
                await vm.CreateDirectoryAsync("must-not-be-created");
                Require(factory.Session.Mutations == before, "old session is never mutated after endpoint edit");
                vm.Host = initial.Host;
                vm.DirectoryPath = "/unlisted";
                await vm.DeleteSelectedAsync();
                Require(factory.Session.Mutations == before, "edited but unlisted path cannot target stale selection");
                vm.DirectoryPath = "/uploads";
                var local = Path.Combine(directory, "sftp-download-" + english + ".txt");
                await File.WriteAllTextAsync(local, "preexisting-local-contents");
                await vm.DownloadSelectedAsync(local);
                Require(await File.ReadAllTextAsync(local) == "preexisting-local-contents", "download never overwrites by default");
                await vm.DownloadSelectedAsync(local, overwrite: true);
                Require(await File.ReadAllTextAsync(local) == "public fixture readme", "explicit download overwrite uses verified completed transfer");
                Require(!Directory.GetFiles(directory).Any(path => path.EndsWith(".partial", StringComparison.Ordinal)), "download staging files cleaned");
                factory.Session.CancelDownloads = true;
                var cancelled = Path.Combine(directory, "sftp-cancelled-" + english + ".txt");
                var download = vm.DownloadSelectedAsync(cancelled);
                await dispatcher.InvokeAsync(() => { }, DispatcherPriority.Background);
                vm.Cancel(); await download;
                Require(!vm.Busy && !File.Exists(cancelled), "cancelled transfer returns idle without partial output");
                Require(!Directory.GetFiles(directory).Any(path => path.EndsWith(".partial", StringComparison.Ordinal)), "cancelled download staging cleaned");
                factory.Session.CancelDownloads = false;
                vm.SelectedEntry = null;
                await vm.RefreshAsync();
                await dispatcher.InvokeAsync(() => { }, DispatcherPriority.ContextIdle);
                window.UpdateLayout();
                Require(FindVisual<DataGrid>(window)?.Items.Count == 5, "real DataGrid rows are bound");
                var content = (FrameworkElement)window.Content;
                var image = new RenderTargetBitmap((int)Math.Ceiling(content.ActualWidth + content.Margin.Left + content.Margin.Right),
                    (int)Math.Ceiling(content.ActualHeight + content.Margin.Top + content.Margin.Bottom), 96, 96, PixelFormats.Pbgra32);
                image.Render(window);
                var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image));
                using (var output = File.Create(Path.Combine(snapshots, english ? "sftp-en-dark-920.png" : "sftp-ru-light-920.png"))) encoder.Save(output);
                outcomes.Add("PASS: SFTP browser " + (english ? "EN dark" : "RU light") + ", real WPF bindings, explicit credentials/MFA, endpoint/path guards, default overwrite refusal, transfer/cancel cleanup.");
            }
            finally
            {
                await vm.DisposeAsync(); window.Close();
                await dispatcher.InvokeAsync(() => { }, DispatcherPriority.ContextIdle);
                foreach (var entry in palette) Application.Current.Resources[entry.Key] = entry.Value;
            }
        }
        if (Environment.GetEnvironmentVariable("SSHARDENER_SFTP_TEST_PREPARE") is { Length: > 0 } prepare)
            await SftpLiveScenario.PrepareAsync(prepare);
        if (Environment.GetEnvironmentVariable("SSHARDENER_SFTP_TEST_CONFIG") is { Length: > 0 } config)
            await SftpLiveScenario.RunAsync(config, outcomes);
    }

    private static Dictionary<string, object> SetPalette(bool dark)
    {
        var colors = dark ? new Dictionary<string, string>
        {
            ["BackgroundBrush"] = "#101C25", ["CardBrush"] = "#192A35", ["ForegroundBrush"] = "#E4EDF3", ["InputBrush"] = "#152530",
            ["BorderBrush"] = "#38505E", ["HoverBrush"] = "#233B46", ["NavigationBrush"] = "#244A44", ["NavigationTextBrush"] = "#A7E5CE"
        } : new Dictionary<string, string>();
        var saved = new Dictionary<string, object>();
        foreach (var entry in colors)
        {
            saved[entry.Key] = Application.Current.Resources[entry.Key];
            Application.Current.Resources[entry.Key] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(entry.Value));
        }
        return saved;
    }

    private static T? FindVisual<T>(DependencyObject element) where T : DependencyObject
    {
        if (element is T found) return found;
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(element); index++)
            if (FindVisual<T>(VisualTreeHelper.GetChild(element, index)) is { } child) return child;
        return null;
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }

    private sealed class FixtureFactory : ISftpSessionFactory
    {
        public FixtureSession Session { get; } = new();
        public ConnectionOptions? LastConnection { get; private set; }
        public async Task<ISftpSession> ConnectSftpAsync(ConnectionOptions connection, Func<HostIdentity, Task<bool>> trustHost, CancellationToken cancellationToken)
        {
            LastConnection = connection;
            if (!await trustHost(Session.Identity with { IsKnown = true })) throw new InvalidOperationException("fixture trust denied");
            return Session;
        }
    }
    private sealed class FixtureSession : ISftpSession
    {
        public HostIdentity Identity { get; } = new("fixture.invalid", 22, "ssh-ed25519", "SHA256:public-fixture", Convert.ToBase64String(SHA256.HashData("public-fixture"u8)));
        public bool CancelDownloads { get; set; }
        public int Mutations { get; private set; }
        public Task<IReadOnlyList<RemoteFileEntry>> ListAsync(string path, CancellationToken cancellationToken)
        {
            var time = DateTimeOffset.Parse("2026-11-06T10:30:00+00:00");
            return Task.FromResult<IReadOnlyList<RemoteFileEntry>>(path == "/" ? [new("uploads", "/uploads", true, false, 0, time)] :
            [new("archive", "/uploads/archive", true, false, 0, time), new("readme.txt", "/uploads/readme.txt", false, false, 21, time),
                new("project-notes.pdf", "/uploads/project-notes.pdf", false, false, 145280, time),
                new("nightly-backup.tar.gz", "/uploads/nightly-backup.tar.gz", false, false, 48392704, time),
                new("shared-link", "/uploads/shared-link", false, true, 12, time)]);
        }
        public async Task DownloadAsync(string remotePath, Stream destination, CancellationToken cancellationToken)
        {
            if (CancelDownloads) await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            await destination.WriteAsync(Encoding.UTF8.GetBytes("public fixture readme"), cancellationToken);
        }
        public Task UploadAsync(Stream source, string remotePath, bool overwrite, CancellationToken cancellationToken) { Mutations++; return Task.CompletedTask; }
        public Task CreateDirectoryAsync(string path, CancellationToken cancellationToken) { Mutations++; return Task.CompletedTask; }
        public Task RenameAsync(string source, string destination, CancellationToken cancellationToken) { Mutations++; return Task.CompletedTask; }
        public Task DeleteAsync(string path, bool directory, CancellationToken cancellationToken) { Mutations++; return Task.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
