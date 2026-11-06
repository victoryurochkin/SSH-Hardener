using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;
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

    [STAThread]
    private static int Main(string[] args)
    {
        var diagnosticArgument = args.FirstOrDefault(x => !x.StartsWith("--", StringComparison.Ordinal));
        var diagnostics = diagnosticArgument is null ? Path.Combine(AppContext.BaseDirectory, "ui-regression.txt") : Path.GetFullPath(diagnosticArgument);
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
                new KeyService(), new ProfileStore(directory), new ReportExporter());
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
            var task = ExerciseAsync(application.Dispatcher, window, model, engine, outcomes);
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
        ProgressFixtureEngine engine, List<string> outcomes)
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
    }

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
