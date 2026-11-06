using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using SSHHardener.App;
using SSHHardener.Core;
using SSHHardener.Profiles;
using SSHHardener.Ssh;
using Localization = SSHHardener.App.Localization;

namespace SSHHardener.UiTests;

internal static class BulkUiScenario
{
    public static async Task RunAsync(string directory, string evidenceDirectory)
    {
        const string passphrase = "synthetic-only-bulk-ui-fixture";
        var key = Path.Combine(directory, "bulk.ppk");
        var publicKey = await new KeyService().GenerateEd25519Async(key, passphrase);
        var profiles = new ProfileStore(directory);
        await profiles.SaveAsync([new ServerProfile("First fixture", "first.example", 22, "operator"), new ServerProfile("Second fixture", "second.example", 22, "operator")]);
        var backend = new Fixture();
        var model = new BulkViewModel(new BulkHardeningCoordinator(backend, backend, backend, backend, backend.Persist), profiles,
            new HardeningOptions { PublicKey = publicKey, PrivateKeyPath = key, KeyPassphrase = passphrase, EnableTotp = true }, new Localization());
        var window = new BulkWindow(model)
        {
            WindowStartupLocation = WindowStartupLocation.Manual, Left = -30000, Top = -30000,
            ShowInTaskbar = false, ShowActivated = false
        };
        try
        {
            var credentialRequests = 0;
            var enrollmentRequests = 0;
            var otpRequests = 0;
            model.RequestCredentials = (_, _, token) => { token.ThrowIfCancellationRequested(); credentialRequests++; return Task.FromResult<BulkCredentials?>(new("fixture-password", null, null, "fixture-target-sudo")); };
            model.RequestTrust = (_, _, _) => Task.FromResult(true);
            model.RequestEnrollment = (_, _) =>
            {
                enrollmentRequests++;
                var secret = TotpService.GenerateSecret();
                var now = DateTimeOffset.UtcNow;
                return Task.FromResult<TotpEnrollment?>(new(secret, TotpService.GenerateCode(secret, now), now, TotpService.GenerateRecoveryCodes().ToArray()));
            };
            model.RequestOtp = (_, _) => { otpRequests++; return Task.FromResult<string?>("123456"); };
            model.ConfirmApply = _ => Task.FromResult(true);
            window.Show();
            await model.ImportProfilesCommand.ExecuteAsync(null);
            Require(model.Hosts.Count == 2, "Saved profile import did not populate the real host grid.");
            await model.PreviewCommand.ExecuteAsync(null);
            Require(model.CanApply, "All individual previews did not enable Apply.");
            Require(enrollmentRequests == 2, "Bulk MFA did not enroll each host independently.");
            model.Concurrency = 2;
            await model.ApplyCommand.ExecuteAsync(null);
            await Application.Current.Dispatcher.InvokeAsync(() => { window.UpdateLayout(); }, DispatcherPriority.ApplicationIdle);
            Require(model.Hosts.All(host => host.Percent == 100 && host.State == model.L["BulkStateCommitted"]), "The real grid lost a confirmed per-host outcome.");
            Require(credentialRequests == 4, "Credentials were reused rather than requested again for each Apply host.");
            Require(enrollmentRequests == 2, "Apply lost and silently replaced an approved MFA enrollment.");
            Require(otpRequests == 2, "Per-host target OTP providers were not bound.");
            Require(backend.Secrets.Count == 2 && backend.Secrets.Distinct().Count() == 2, "Two hosts received the same TOTP secret.");
            Require(!model.CanApply, "A completed preview could be applied a second time.");
            Directory.CreateDirectory(evidenceDirectory);
            var bitmap = new RenderTargetBitmap((int)window.ActualWidth, (int)window.ActualHeight, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(window);
            var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using (var output = File.Create(Path.Combine(evidenceDirectory, "bulk-ui-ru.png"))) encoder.Save(output);
            await VerifyDialogCancellation(window, model.L);
            Console.WriteLine("PASS: real WPF bulk host grid, profiles, independent MFA enrollment, reentered credentials, per-host progress/outcomes and cancelled secret dialogs; no network.");
        }
        finally { window.Close(); }
    }

    private static async Task VerifyDialogCancellation(Window owner, Localization l)
    {
        foreach (var kind in new[] { "otp", "enrollment", "credentials" })
        {
            using var cancellation = new CancellationTokenSource();
            var cancel = Task.Run(async () => { await Task.Delay(100); cancellation.Cancel(); });
            object? result = kind switch
            {
                "otp" => FeatureDialogs.ShowOtp(owner, l, "synthetic fixture", cancellation.Token),
                "enrollment" => FeatureDialogs.EnrollTotp(owner, l, "synthetic fixture", cancellation.Token),
                _ => FeatureDialogs.ShowCredentials(owner, l, new BulkTarget("fixture", "Fixture", "fixture.example", 22, "operator"), new HardeningOptions(), cancellation.Token)
            };
            Require(result is null, "Cancellation failed to close the " + kind + " secret dialog.");
            await cancel;
        }
    }

    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private sealed class Fixture : IRemoteSessionFactory, IAuditService, IPlanBuilder, IHardeningEngine
    {
        private int _ids;
        public List<string> Secrets { get; } = [];
        public Task Persist(OperationRecord record, CancellationToken token) { record.Validate(); token.ThrowIfCancellationRequested(); return Task.CompletedTask; }
        public async Task<IRemoteSession> ConnectAsync(ConnectionOptions connection, Func<HostIdentity, Task<bool>> trust, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var name = Encoding.ASCII.GetBytes("ssh-ed25519");
            var blob = new byte[4 + name.Length + 4 + 32];
            BinaryPrimitives.WriteInt32BigEndian(blob, name.Length); name.CopyTo(blob, 4);
            BinaryPrimitives.WriteInt32BigEndian(blob.AsSpan(4 + name.Length), 32); blob[^1] = 1;
            var identity = new HostIdentity(connection.Host, connection.Port, "ssh-ed25519", "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('='), Convert.ToBase64String(blob));
            if (!await trust(identity)) throw new InvalidOperationException("Fixture host was rejected.");
            return new Session(connection, identity);
        }
        public Task<ServerAudit> AuditAsync(IRemoteSession session, CancellationToken ct) => Task.FromResult(new ServerAudit
        { HasRoot = true, InitSystem = "systemd", OsId = "debian", OsVersion = "12", RawReport = "Synthetic Debian 12 audit. No network connection or server mutation." });
        public HardeningPlan Build(ServerAudit audit, ConnectionOptions connection, HardeningOptions options) =>
            new("20261106120000-" + Interlocked.Increment(ref _ids).ToString("x12"), audit, connection, options,
                [new PlannedStep("preflight", "Synthetic preview only", "# This fixture never executes a remote command.", "# Independent fixture recovery.")], []);
        public async Task<HardeningResult> ApplyAsync(IRemoteSession original, HardeningPlan plan, IProgress<OperationProgress>? progress, CancellationToken ct)
        {
            progress?.Report(new OperationProgress("fixture", "Synthetic verification", 50));
            lock (Secrets) Secrets.Add(plan.Options.TotpSecret!);
            Require(plan.Options.VerificationSudoPassword == "fixture-target-sudo", "Legacy target sudo verification credential was not mapped.");
            Require(plan.Options.VerificationOneTimeCodeProvider is not null, "Target OTP provider is missing.");
            _ = await plan.Options.VerificationOneTimeCodeProvider!(ct);
            return new HardeningResult(plan.TransactionId, true, false, "Synthetic commit confirmation.", DateTimeOffset.UtcNow);
        }
        public Task RollbackAsync(IRemoteSession session, string transactionId, CancellationToken ct) => throw new InvalidOperationException("The UI fixture must never invoke global rollback.");
    }
    private sealed class Session(ConnectionOptions options, HostIdentity identity) : IRemoteSession
    {
        public ConnectionOptions Options => options;
        public HostIdentity Identity => identity;
        public Task<CommandResult> ExecuteAsync(string script, bool privileged, CancellationToken cancellationToken) => throw new InvalidOperationException("No remote commands are permitted in this UI fixture.");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
