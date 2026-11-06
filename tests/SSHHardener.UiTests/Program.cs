using System.IO;
using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Xml.Linq;
using SSHHardener.App;
using SSHHardener.Core;
using SSHHardener.Reports;
using SSHHardener.Ssh;

namespace SSHHardener.UiTests;

internal static class Program
{
    private static readonly MethodInfo AppendLogMethod = typeof(MainViewModel).GetMethod("AddLog", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("MainViewModel.AddLog is unavailable.");
    private static readonly List<Exception> DispatcherFailures = [];
    private static string _stage = "startup";
    private static string? _historyPreviewDirectory;

    [STAThread]
    private static int Main(string[] args)
    {
        var diagnosticArgument = args.FirstOrDefault(x => !x.StartsWith("--", StringComparison.Ordinal));
        var diagnostics = diagnosticArgument is null ? Path.Combine(AppContext.BaseDirectory, "ui-regression.txt") : Path.GetFullPath(diagnosticArgument);
        if (args.Contains("--history-previews", StringComparer.Ordinal)) _historyPreviewDirectory = Path.GetDirectoryName(diagnostics);
        var legacyScroll = args.Contains("--legacy-scroll", StringComparer.Ordinal);
        var directory = Path.Combine(Path.GetTempPath(), "ssh-hardener-ui-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        Application? application = null;
        MainWindow? window = null;
        MainViewModel? model = null;
        var outcomes = new List<string>();
        try
        {
            // Use a plain Application: production App.OnStartup and its MessageBox exception handler
            // must never run in this regression process, including during nested dispatcher frames.
            application = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
            application.DispatcherUnhandledException += (_, exception) =>
            {
                DispatcherFailures.Add(exception.Exception);
                exception.Handled = true;
            };
            application.Resources.MergedDictionaries.Add(LoadActualResources());
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(application.Dispatcher));

            var engine = new ProgressFixtureEngine();
            model = new MainViewModel(new NoNetworkFactory(), new FixtureAudit(), new FixturePlanner(), engine,
                new KeyService(), new ProfileStore(directory), new ReportExporter(), new OperationHistoryStore(directory));
            ListBox? legacyLogView = null;
            if (legacyScroll)
            {
                // Reinstall the previous synchronous handler before ItemsSource subscribes.
                // This reproduces its stale ItemCollection ordering without editing production files.
                model.Log.CollectionChanged += (_, _) =>
                {
                    if (model.Log.Count != 0) legacyLogView!.ScrollIntoView(model.Log[^1]);
                };
            }
            window = new MainWindow(model)
            {
                WindowStartupLocation = WindowStartupLocation.Manual,
                Left = -30000, Top = -30000, Width = 1180, Height = 820,
                ShowInTaskbar = false, ShowActivated = false
            };
            legacyLogView = (ListBox)window.FindName("ActionLog");
            window.Show();
            var task = ExerciseAsync(application.Dispatcher, window, model, engine, outcomes, directory);
            var frame = new DispatcherFrame();
            _ = task.ContinueWith(_ => application.Dispatcher.BeginInvoke(() => frame.Continue = false), TaskScheduler.Default);
            Dispatcher.PushFrame(frame);
            task.GetAwaiter().GetResult();
            ThrowDispatcherFailures();
            Save(diagnostics, "PASS: real WPF log binding, immediate tab switch, progress callbacks, 1000-entry trim and final autoscroll. No network or production startup handlers.\n" + string.Join('\n', outcomes));
            Console.WriteLine("PASS: WPF apply-log regression.");
            return 0;
        }
        catch (Exception error)
        {
            var details = "FAIL at " + _stage + "\n" + error + "\n" + string.Join("\n", DispatcherFailures.Select(x => x.ToString()));
            Save(diagnostics, details);
            Console.Error.WriteLine(details);
            return 1;
        }
        finally
        {
            window?.Close();
            model?.DisposeAsync().AsTask().GetAwaiter().GetResult();
            application?.Shutdown();
            foreach (var file in Directory.GetFiles(directory)) File.Delete(file);
            Directory.Delete(directory);
        }
    }

    private static ResourceDictionary LoadActualResources()
    {
        var source = XDocument.Load(Path.Combine(AppContext.BaseDirectory, "AppResources.xaml"));
        XNamespace presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        var resources = source.Root?.Element(presentation + "Application.Resources")
            ?? throw new InvalidOperationException("The actual App.xaml resource section was not found.");
        var root = new XElement(presentation + "ResourceDictionary",
            new XAttribute(XNamespace.Xmlns + "x", "http://schemas.microsoft.com/winfx/2006/xaml"),
            resources.Elements().Select(x => new XElement(x)));
        return (ResourceDictionary)XamlReader.Parse(root.ToString());
    }

    private static async Task ExerciseAsync(Dispatcher dispatcher, MainWindow window, MainViewModel model,
        ProgressFixtureEngine engine, List<string> outcomes, string directory)
    {
        _stage = "initial-real-layout";
        await DrainAsync(dispatcher, window);
        var list = (ListBox)window.FindName("ActionLog");

        _stage = "immediate-apply-tab-and-first-progress";
        model.SelectedTab = 4;
        // This is deliberately before a dispatcher/layout yield, as in the actual ApplyAsync path.
        AppendLog(model, "preflight: server checks started at 5%");
        await DrainAsync(dispatcher, window);
        Require(list.Items.Count == 1, "The first progress item did not reach the real ListBox binding.");
        outcomes.Add("PASS first progress after immediate Apply-tab selection");

        _stage = "synchronous-burst-and-trim";
        for (var index = 0; index < 1105; index++) AppendLog(model, "burst progress " + index);
        await DrainAsync(dispatcher, window);
        Require(model.Log.Count == 1000 && list.Items.Count == 1000, "The 1000-entry log bound was not preserved.");
        outcomes.Add("PASS synchronous burst and RemoveAt trim while ItemsControl is bound");

        _stage = "worker-progress-and-ui-updates";
        var progress = new Progress<OperationProgress>(value =>
        {
            typeof(MainViewModel).GetProperty(nameof(MainViewModel.Progress))!.SetValue(model, value.Percent);
            AppendLog(model, value.Step + ": " + value.Message);
        });
        var plan = new HardeningPlan("20261106120000-abcdef123456", new ServerAudit(),
            new ConnectionOptions("fixture.invalid", 22, "fixture"), new HardeningOptions(), [], []);
        await engine.ApplyAsync(new NoNetworkSession(), plan, progress, CancellationToken.None);
        await DrainAsync(dispatcher, window);
        Require(model.Progress == 100, "Queued UI progress did not reach the final value.");
        Require(model.Log.Count == 1000 && list.Items.Count == 1000, "Progress callbacks broke collection trimming or binding.");
        Require(model.Log[^1].Contains("progress-1204", StringComparison.Ordinal), "The final queued progress was lost.");
        outcomes.Add("PASS worker Progress<T> callbacks and footer/progress bindings");

        _stage = "tab-reselection-and-final-autoscroll";
        model.SelectedTab = 1;
        await DrainAsync(dispatcher, window);
        model.SelectedTab = 4;
        AppendLog(model, "final-visible-marker");
        await DrainAsync(dispatcher, window);
        Require(list.Items.Count == model.Log.Count, "Re-selected Apply tab has a stale item view.");
        Require(list.ItemContainerGenerator.ContainerFromIndex(list.Items.Count - 1) is not null,
            "The final log item was not realized by deferred autoscroll.");
        var scroll = Descendants<ScrollViewer>(list).FirstOrDefault();
        Require(scroll is not null && scroll.ScrollableHeight > 0 && scroll.VerticalOffset >= scroll.ScrollableHeight - 1,
            "The real log ScrollViewer did not follow the final entry.");
        outcomes.Add("PASS final visible item and scrolled-to-bottom after tab re-selection");

        _stage = "clear-reset-and-close-with-pending-scroll";
        model.Log.Clear();
        AppendLog(model, "first-entry-after-clear");
        await DrainAsync(dispatcher, window);
        Require(list.Items.Count == 1 && model.Log.Count == 1, "A collection reset left the log view inconsistent.");
        AppendLog(model, "pending-entry-before-close");
        window.Close();
        await dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        ThrowDispatcherFailures();
        outcomes.Add("PASS collection reset and closing with a pending deferred scroll");

        await VerifyFatalUiFailureLifecycleAsync(dispatcher, model);
        outcomes.Add("PASS fatal UI failure cancels immediately, waits for recovery and permanently blocks new operations");

        if (_historyPreviewDirectory is not null) await SaveHistoryPreviewsAsync(dispatcher, directory, _historyPreviewDirectory);
        await VerifyRestartRecoveryLifecycleAsync(directory);
        outcomes.Add("PASS persisted history restarts without network/secrets, requires pinned fresh status and rechecks before manual recovery");
        await VerifyHistoryBarrierBeforeApplyAsync(directory);
        outcomes.Add("PASS failed history persistence blocks the engine; successful persistence precedes the first engine call");
    }

    private static async Task SaveHistoryPreviewsAsync(Dispatcher dispatcher, string directory, string outputDirectory)
    {
        _stage = "cached-history-fixture-previews-before-live-check";
        foreach (var english in new[] { false, true })
        {
            await using var model = new MainViewModel(new NoNetworkFactory(), new FixtureAudit(), new FixturePlanner(), new RecoveryEngine(),
                new KeyService(), new ProfileStore(directory), new ReportExporter(), new OperationHistoryStore(directory));
            var record = RecoveryRecord();
            foreach (var (state, index) in new[] { (OperationState.Committed, 0), (OperationState.Pending, 1), (OperationState.RolledBack, 2) })
                model.Operations.Add(record with { TransactionId = $"20261106120000-{index + 1:x12}", CreatedAt = record.CreatedAt.AddMinutes(-index),
                    LastConfirmedState = state, LastConfirmedAt = record.CreatedAt.AddMinutes(-index) });
            model.SelectedOperation = model.Operations[0];
            var preview = new MainWindow(model) { Width = 920, Height = 640 };
            try
            {
                preview.ConfigurePreview(dark: english, english: english, tab: 4);
                preview.Measure(new Size(920, 640));
                preview.Arrange(new Rect(0, 0, 920, 640));
                await DrainAsync(dispatcher, preview);
                var visual = (FrameworkElement)preview.Content;
                visual.Measure(new Size(920, 640));
                visual.Arrange(new Rect(0, 0, 920, 640));
                await DrainAsync(dispatcher, preview);
                Require(model.Operations.Count == 3 && !model.CanRollback, "Cached preview history unexpectedly authorized recovery.");
                var bitmap = new RenderTargetBitmap(920, 640, 96, 96, PixelFormats.Pbgra32);
                bitmap.Render(visual);
                var encoder = new PngBitmapEncoder();
                encoder.Frames.Add(BitmapFrame.Create(bitmap));
                Directory.CreateDirectory(outputDirectory);
                using var output = File.Create(Path.Combine(outputDirectory, english ? "history-fixture-920-dark-en.png" : "history-fixture-920-light-ru.png"));
                encoder.Save(output);
            }
            finally { preview.Close(); }
        }
    }

    private static async Task VerifyRestartRecoveryLifecycleAsync(string directory)
    {
        _stage = "restart-history-load-and-pinned-recovery";
        var record = RecoveryRecord() with { LastConfirmedState = OperationState.Committed, LastConfirmedAt = DateTimeOffset.UtcNow };
        await new OperationHistoryStore(directory).UpsertAsync(record, CancellationToken.None);
        var factory = new RecoveryFactory(record);
        var auditor = new RecoveryAudit();
        var engine = new RecoveryEngine();
        MainViewModel NewModel() => new(factory, auditor, new FixturePlanner(), engine,
            new KeyService(), new ProfileStore(directory), new ReportExporter(), new OperationHistoryStore(directory));

        await using (var first = NewModel())
        {
            await first.InitializeAsync();
            Require(first.Operations.Count == 1 && !first.CanRollback, "Loading cached committed metadata authorized recovery.");
        }
        await using var restarted = NewModel();
        await restarted.InitializeAsync();
        Require(factory.ConnectCalls == 0 && factory.QueryCalls == 0 && auditor.Calls == 0 && engine.RollbackCalls == 0,
            "Restart/initialization unexpectedly contacted or changed the server.");
        Require(restarted.Operations.Count == 1 && !restarted.CanRollback, "The operation did not survive a new view-model instance safely.");
        var secrets = new ConnectionSecrets("stale-password", "stale-key-passphrase", "stale-sudo-password");
        var cleared = 0;
        restarted.ReadConnectionSecrets = () => secrets;
        restarted.ClearConnectionSecrets = () => { cleared++; secrets = new ConnectionSecrets("", "", ""); };
        restarted.UseOriginalConnectionCommand.Execute(null);
        Require(restarted.Host == record.Host && restarted.Port == "22" && restarted.Username == record.OriginalUsername &&
            restarted.PrivateKey == record.OriginalPrivateKeyPath && cleared == 1, "Original endpoint restore did not clear secrets or restore metadata.");
        restarted.UseNewConnectionCommand.Execute(null);
        Require(restarted.Port == "22022" && restarted.Username == record.NewUsername && restarted.PrivateKey == record.NewPrivateKeyPath &&
            cleared == 2 && secrets == new ConnectionSecrets("", "", ""), "New endpoint restore carried credentials across sessions.");
        Require(!restarted.CanRollback && factory.ConnectCalls == 0, "Selecting an endpoint automatically connected or enabled recovery.");

        await InvokePrivateAsync(restarted, "ConnectAsync");
        Require(factory.ConnectCalls == 1 && factory.QueryCalls == 1 && restarted.CanRollback,
            "Pinned reconnect and fresh latest-commit status did not enable explicit recovery.");
        Require(factory.LastOptions?.Password is null && factory.LastOptions?.Passphrase is null && factory.LastOptions?.SudoPassword is null,
            "Restored history supplied an old secret to the new connection.");
        var confirmedAt = restarted.SelectedOperation!.LastConfirmedAt;
        factory.QueryExitCode = 1;
        await ExpectFailureAsync(() => InvokePrivateAsync(restarted, "CheckOperationAsync"));
        Require(!restarted.CanRollback && restarted.SelectedOperation!.LastConfirmedAt == confirmedAt,
            "A failed fresh query kept recovery authorized or overwrote last-confirmed metadata.");
        factory.QueryExitCode = 0;
        factory.State = "pending";
        factory.LastCommitted = false;
        await InvokePrivateAsync(restarted, "CheckOperationAsync");
        Require(restarted.CanRollback, "A freshly verified pending transaction did not permit explicit recovery.");

        var originalSelection = restarted.SelectedOperation!;
        var other = record with { TransactionId = "20261106120000-abcdef123457", CreatedAt = record.CreatedAt.AddSeconds(1) };
        restarted.Operations.Add(other);
        restarted.SelectedOperation = other;
        Require(!restarted.CanRollback, "Changing the selected operation reused a previous server check.");
        restarted.SelectedOperation = originalSelection;
        await InvokePrivateAsync(restarted, "CheckOperationAsync");
        Require(restarted.CanRollback, "Rechecking the original selection failed.");
        var queriesBeforeEdit = factory.QueryCalls;
        restarted.Host = "other-fixture.invalid";
        Require(!restarted.CanRollback && factory.QueryCalls == queriesBeforeEdit, "Editing connection fields reused or implicitly refreshed a status.");

        restarted.UseNewConnectionCommand.Execute(null);
        factory.WrongHostKey = true;
        var auditsBeforeMismatch = auditor.Calls;
        await ExpectFailureAsync(() => InvokePrivateAsync(restarted, "ConnectAsync"));
        Require(!restarted.CanRollback && auditor.Calls == auditsBeforeMismatch && factory.QueryCalls == queriesBeforeEdit,
            "A changed host key reached audit/status or reused recovery permission.");
        factory.WrongHostKey = false;
        factory.State = "committed";
        factory.LastCommitted = true;
        await InvokePrivateAsync(restarted, "ConnectAsync");
        Require(restarted.CanRollback, "Fresh pinned reconnect failed after rejecting the changed identity.");
        Require(factory.Sessions.Any(session => session.Disposed), "Replacing a connection did not dispose the previous session.");

        var confirmations = 0;
        restarted.ConfirmAction = _ => { confirmations++; return true; };
        factory.LastCommitted = false;
        var beforeRecheck = factory.QueryCalls;
        await ExpectFailureAsync(() => InvokePrivateAsync(restarted, "RollbackAsync"));
        Require(factory.QueryCalls == beforeRecheck + 1 && engine.RollbackCalls == 0 && confirmations == 0,
            "Manual recovery used stale latest-commit information before confirmation.");
        factory.LastCommitted = true;
        restarted.ConfirmAction = _ => { confirmations++; return false; };
        await InvokePrivateAsync(restarted, "RollbackAsync");
        Require(engine.RollbackCalls == 0 && confirmations == 1, "Declining explicit recovery still changed the server.");
        restarted.ConfirmAction = _ => true;
        await InvokePrivateAsync(restarted, "RollbackAsync");
        Require(engine.RollbackCalls == 1 && engine.ApplyCalls == 0 && !restarted.CanRollback,
            "Explicit recovery did not invalidate its session/status or triggered an apply.");
        var stored = await new OperationHistoryStore(directory).LoadAsync(CancellationToken.None);
        Require(stored.Single(x => x.TransactionId == record.TransactionId).LastConfirmedState == OperationState.RolledBack,
            "A confirmed explicit recovery did not persist its terminal state.");
        var resultField = typeof(MainViewModel).GetField("_result", BindingFlags.Instance | BindingFlags.NonPublic)!;
        Require(resultField.GetValue(restarted) is HardeningResult outcome && outcome.TransactionId == record.TransactionId,
            "The restored operation did not record its own rollback outcome.");
        Require(typeof(MainViewModel).GetField("_executedPlan", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(restarted) is null,
            "The fixture must exercise restored recovery without an in-memory executed plan.");
        if (!restarted.Operations.Any(x => x.TransactionId == other.TransactionId)) restarted.Operations.Add(other);
        restarted.SelectedOperation = other;
        Require(resultField.GetValue(restarted) is null,
            "Selecting another history record retained the previous restored rollback result without an executed plan.");
        ThrowDispatcherFailures();
    }

    private static async Task VerifyHistoryBarrierBeforeApplyAsync(string directory)
    {
        _stage = "history-persistence-before-server-mutation";
        var record = RecoveryRecord();
        var history = new OperationHistoryStore(directory);
        var engine = new RecoveryEngine();
        await using var model = new MainViewModel(new NoNetworkFactory(), new FixtureAudit(), new FixturePlanner(), engine,
            new KeyService(), new ProfileStore(directory), new ReportExporter(), history);
        model.ConfirmAction = _ => true;
        var options = new ConnectionOptions(record.Host, record.OriginalPort, record.OriginalUsername, PrivateKeyPath: record.OriginalPrivateKeyPath);
        var identity = RecoveryIdentity(record, record.OriginalPort);
        var session = new RecoverySession(options, identity, () => new CommandResult(0, "", ""));
        var audit = new ServerAudit { HasRoot = true, InitSystem = "systemd" };
        var plan = new HardeningPlan(record.TransactionId, audit, options,
            new HardeningOptions { Username = record.NewUsername, NewPort = record.NewPort, PrivateKeyPath = record.NewPrivateKeyPath! }, [], []);
        SetPrivateField(model, "_session", session);
        SetPrivateField(model, "_audit", audit);
        SetPrivateField(model, "_plan", plan);
        SetPrivateField(model, "_connectionChanged", false);
        var dataPath = Path.Combine(directory, "operations.dat");
        await File.WriteAllTextAsync(dataPath, "deliberately corrupt fixture history");
        await ExpectFailureAsync(() => InvokePrivateAsync(model, "ApplyAsync"));
        Require(engine.ApplyCalls == 0, "The engine started despite a failed durable history write.");
        File.Delete(dataPath);
        engine.BeforeApply = async () =>
        {
            var persisted = await new OperationHistoryStore(directory).LoadAsync(CancellationToken.None);
            Require(persisted.Any(x => x.TransactionId == record.TransactionId), "The engine ran before its recovery reference was durable.");
        };
        await InvokePrivateAsync(model, "ApplyAsync");
        Require(engine.ApplyCalls == 1 && !model.CanRollback, "Successful apply bypassed persistence or trusted cached local outcome for recovery.");
        ThrowDispatcherFailures();
    }

    private static OperationRecord RecoveryRecord()
    {
        using var wire = new MemoryStream();
        foreach (var field in new[] { Encoding.ASCII.GetBytes("ssh-ed25519"), Enumerable.Range(1, 32).Select(x => (byte)x).ToArray() })
        {
            var length = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(length, (uint)field.Length);
            wire.Write(length); wire.Write(field);
        }
        var key = wire.ToArray();
        return new OperationRecord("20261106120000-abcdef123456", DateTimeOffset.UtcNow, "fixture.invalid", 22, "root", "C:\\fixture\\original.pem",
            22022, "sshadmin", "C:\\fixture\\target.ppk", "ssh-ed25519", Convert.ToBase64String(key),
            "SHA256:" + Convert.ToBase64String(SHA256.HashData(key)).TrimEnd('='));
    }

    private static HostIdentity RecoveryIdentity(OperationRecord operation, int port) => new(operation.Host, port,
        operation.HostKeyAlgorithm, operation.HostKeyFingerprint, operation.HostKeyBase64, IsKnown: true);

    private static Task InvokePrivateAsync(MainViewModel model, string method)
    {
        var action = typeof(MainViewModel).GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("View-model action not found: " + method);
        try { return (Task)action.Invoke(model, [CancellationToken.None])!; }
        catch (TargetInvocationException failure) when (failure.InnerException is not null)
        { ExceptionDispatchInfo.Capture(failure.InnerException).Throw(); throw; }
    }

    private static async Task ExpectFailureAsync(Func<Task> operation)
    {
        try { await operation(); }
        catch (Exception error) when (error is InvalidOperationException or ArgumentException or System.Security.Cryptography.CryptographicException or IOException or InvalidDataException or HostKeyChangedException) { return; }
        throw new InvalidOperationException("The protected operation unexpectedly succeeded.");
    }

    private static void SetPrivateField(MainViewModel model, string name, object value) =>
        (typeof(MainViewModel).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("View-model field not found: " + name)).SetValue(model, value);

    private static async Task VerifyFatalUiFailureLifecycleAsync(Dispatcher dispatcher, MainViewModel model)
    {
        _stage = "fatal-ui-cancellation-and-recovery-lifecycle";
        var cancellationObserved = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var recoveryRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = false;
        CancellationToken observedToken = default;
        async Task OperationWithIndependentRecovery(CancellationToken token)
        {
            entered = true;
            observedToken = token;
            using var cancellation = token.Register(() => cancellationObserved.TrySetResult());
            await cancellationObserved.Task;
            // Cancellation has reached the operation, but independent recovery is still running.
            // The shutdown task must wait for this explicit signal instead of disposing resources early.
            await recoveryRelease.Task;
            token.ThrowIfCancellationRequested();
        }

        var operation = RunOperationAsync(model, OperationWithIndependentRecovery);
        Require(entered && model.Busy, "The controlled operation did not enter its busy lifecycle.");
        var stopping = model.StopForUiFailureAsync();
        Require(observedToken.IsCancellationRequested && cancellationObserved.Task.IsCompleted,
            "Fatal UI failure did not immediately cancel the active operation.");
        Require(!stopping.IsCompleted, "Fatal UI shutdown completed before independent recovery was released.");

        var secondOperationStarted = false;
        await RunOperationAsync(model, _ => { secondOperationStarted = true; return Task.CompletedTask; });
        await dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        Require(!secondOperationStarted && !stopping.IsCompleted,
            "Another operation started or shutdown completed while independent recovery was pending.");

        recoveryRelease.TrySetResult();
        await Task.WhenAll(operation, stopping).WaitAsync(TimeSpan.FromSeconds(5));
        Require(!model.Busy && !model.Idle, "The fatal UI latch did not keep the model disabled after recovery finished.");
        var afterRecoveryStarted = false;
        await RunOperationAsync(model, _ => { afterRecoveryStarted = true; return Task.CompletedTask; });
        Require(!afterRecoveryStarted, "A new operation started after the fatal UI latch was set.");
        ThrowDispatcherFailures();
    }

    private static Task RunOperationAsync(MainViewModel model, Func<CancellationToken, Task> operation)
    {
        var run = typeof(MainViewModel).GetMethod("RunAsync", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("MainViewModel.RunAsync is unavailable.");
        try { return (Task)run.Invoke(model, [operation])!; }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(error.InnerException).Throw();
            throw;
        }
    }

    private static void AppendLog(MainViewModel model, string text)
    {
        try { AppendLogMethod.Invoke(model, [text]); }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        { ExceptionDispatchInfo.Capture(error.InnerException).Throw(); }
    }

    private static async Task DrainAsync(Dispatcher dispatcher, Window window)
    {
        for (var pass = 0; pass < 3; pass++)
        {
            await dispatcher.InvokeAsync(window.UpdateLayout, DispatcherPriority.ApplicationIdle);
            ThrowDispatcherFailures();
        }
    }

    private static void ThrowDispatcherFailures()
    {
        if (DispatcherFailures.Count != 0) throw new AggregateException("Unhandled WPF dispatcher failure(s).", DispatcherFailures);
    }

    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T match) yield return match;
            foreach (var descendant in Descendants<T>(child)) yield return descendant;
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static void Save(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    private sealed class ProgressFixtureEngine : IHardeningEngine
    {
        public Task<HardeningResult> ApplyAsync(IRemoteSession original, HardeningPlan plan, IProgress<OperationProgress>? progress, CancellationToken cancellationToken) => Task.Run(() =>
        {
            for (var index = 0; index < 1205; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress?.Report(new OperationProgress("preflight", "progress-" + index, index == 1204 ? 100 : index % 100));
            }
            return new HardeningResult(plan.TransactionId, true, false, "fixture complete", DateTimeOffset.UtcNow);
        }, cancellationToken);
        public Task RollbackAsync(IRemoteSession session, string transactionId, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class NoNetworkFactory : IRemoteSessionFactory
    {
        public Task<IRemoteSession> ConnectAsync(ConnectionOptions options, Func<HostIdentity, Task<bool>> trustHost, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("UI regression must not establish a network connection.");
    }

    private sealed class RecoveryFactory(OperationRecord operation) : IRemoteSessionFactory
    {
        public int ConnectCalls { get; private set; }
        public int QueryCalls { get; private set; }
        public ConnectionOptions? LastOptions { get; private set; }
        public List<RecoverySession> Sessions { get; } = [];
        public string State { get; set; } = "committed";
        public bool LastCommitted { get; set; } = true;
        public int QueryExitCode { get; set; }
        public bool WrongHostKey { get; set; }

        public async Task<IRemoteSession> ConnectAsync(ConnectionOptions options, Func<HostIdentity, Task<bool>> trustHost, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ConnectCalls++; LastOptions = options;
            var identity = RecoveryIdentity(operation, options.Port) with { Host = options.Host };
            if (WrongHostKey)
            {
                var key = Convert.FromBase64String(identity.KeyBase64); key[^1] ^= 1;
                identity = identity with { KeyBase64 = Convert.ToBase64String(key), Fingerprint = "SHA256:" + Convert.ToBase64String(SHA256.HashData(key)).TrimEnd('=') };
            }
            if (!await trustHost(identity)) throw new InvalidOperationException("The fixture host identity was rejected.");
            var session = new RecoverySession(options, identity, () =>
            {
                QueryCalls++;
                return new CommandResult(QueryExitCode,
                    $"SSHARDENER_TX_STATE={State}\nSSHARDENER_LAST_COMMITTED={(LastCommitted ? "yes" : "no")}\n", "");
            });
            Sessions.Add(session);
            return session;
        }
    }

    private sealed class RecoveryAudit : IAuditService
    {
        public int Calls { get; private set; }
        public Task<ServerAudit> AuditAsync(IRemoteSession session, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return Task.FromResult(new ServerAudit { HasRoot = true, InitSystem = "systemd", Description = "fixture audit" });
        }
    }

    private sealed class RecoveryEngine : IHardeningEngine
    {
        public int ApplyCalls { get; private set; }
        public int RollbackCalls { get; private set; }
        public Func<Task>? BeforeApply { get; set; }
        public async Task<HardeningResult> ApplyAsync(IRemoteSession original, HardeningPlan plan, IProgress<OperationProgress>? progress, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ApplyCalls++;
            if (BeforeApply is not null) await BeforeApply();
            return new HardeningResult(plan.TransactionId, true, false, "fixture committed", DateTimeOffset.UtcNow);
        }
        public Task RollbackAsync(IRemoteSession session, string transactionId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RollbackCalls++;
            return Task.CompletedTask;
        }
    }

    private sealed class RecoverySession(ConnectionOptions options, HostIdentity identity, Func<CommandResult> response) : IRemoteSession
    {
        public ConnectionOptions Options { get; } = options;
        public HostIdentity Identity { get; } = identity;
        public bool Disposed { get; private set; }
        public Task<CommandResult> ExecuteAsync(string script, bool privileged, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(privileged && script.Contains("SSHARDENER_TX_STATE", StringComparison.Ordinal) && !script.Contains("rollback.sh", StringComparison.Ordinal),
                "History status attempted an unexpected server command.");
            return Task.FromResult(response());
        }
        public ValueTask DisposeAsync() { Disposed = true; return ValueTask.CompletedTask; }
    }

    private sealed class FixtureAudit : IAuditService
    {
        public Task<ServerAudit> AuditAsync(IRemoteSession session, CancellationToken cancellationToken) => Task.FromResult(new ServerAudit { HasRoot = true });
    }

    private sealed class FixturePlanner : IPlanBuilder
    {
        public HardeningPlan Build(ServerAudit audit, ConnectionOptions connection, HardeningOptions options) =>
            new("20261106120000-abcdef123456", audit, connection, options, [], []);
    }

    private sealed class NoNetworkSession : IRemoteSession
    {
        public ConnectionOptions Options { get; } = new("fixture.invalid", 22, "fixture");
        public HostIdentity Identity { get; } = new("fixture.invalid", 22, "ssh-ed25519", "SHA256:fixture", "Zml4dHVyZQ==");
        public Task<CommandResult> ExecuteAsync(string script, bool privileged, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("UI regression must not execute a remote command.");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
