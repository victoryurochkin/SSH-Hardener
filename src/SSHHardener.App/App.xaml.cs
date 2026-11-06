using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using SSHHardener.Core;
using SSHHardener.Profiles;
using SSHHardener.Reports;
using SSHHardener.Ssh;

namespace SSHHardener.App;

public partial class App : Application
{
    private ServiceProvider? _services;
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SSHHardener", "logs");
        Directory.CreateDirectory(directory);
        Log.Logger = new LoggerConfiguration().WriteTo.File(Path.Combine(directory, "application-.log"), rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14).CreateLogger();
        var services = new ServiceCollection();
        services.AddSingleton<KnownHostsStore>();
        services.AddSingleton<IRemoteSessionFactory, SshRemoteSessionFactory>();
        services.AddSingleton<IAuditService, AuditService>();
        services.AddSingleton<IPlanBuilder, PlanBuilder>();
        services.AddSingleton<IHardeningEngine, HardeningEngine>();
        services.AddSingleton<KeyService>();
        services.AddSingleton<ProfileStore>();
        services.AddSingleton<ReportExporter>();
        services.AddSingleton<MainViewModel>();
        services.AddSingleton<MainWindow>();
        _services = services.BuildServiceProvider();
        var selfTest = e.Args.Contains("--self-test", StringComparer.Ordinal);
        var diagnosticsPath = Path.Combine(AppContext.BaseDirectory, "startup-check.txt");
        var selfTestIndex = Array.IndexOf(e.Args, "--self-test");
        var selfTestPaths = selfTestIndex >= 0 ? e.Args.Skip(selfTestIndex + 1).TakeWhile(x => !x.StartsWith("--", StringComparison.Ordinal)).ToArray() : [];
        if (selfTestPaths.Length > 0) diagnosticsPath = Path.GetFullPath(selfTestPaths[0]);
        var selfTestFailed = false;
        DispatcherUnhandledException += (_, exception) =>
        {
            if (selfTest)
            {
                selfTestFailed = true;
                Log.Error(exception.Exception, "Headless startup failed");
                Directory.CreateDirectory(Path.GetDirectoryName(diagnosticsPath)!);
                File.WriteAllText(diagnosticsPath, exception.Exception.ToString());
                exception.Handled = true;
                Shutdown(1);
                return;
            }
            // Do not persist exception objects: SSH libraries can embed connection information.
            Log.Error("Unhandled UI failure of type {FailureType}", exception.Exception.GetType().Name);
            MessageBox.Show("Не удалось выполнить операцию / Operation failed.", "SSH Hardener", MessageBoxButton.OK, MessageBoxImage.Error);
            exception.Handled = true;
        };
        Log.Information("SSH Hardener started");
        try
        {
            var window = _services.GetRequiredService<MainWindow>();
            if (selfTest)
            {
                var width = ReadPreviewNumber(e.Args, "--width", 1180);
                var height = ReadPreviewNumber(e.Args, "--height", 820);
                var tab = ReadPreviewNumber(e.Args, "--tab", 0);
                if (width is < 920 or > 2560 || height is < 640 or > 1440 || tab is < 0 or > 5)
                    throw new ArgumentException("Preview bounds: width 920–2560, height 640–1440, tab 0–5.");
                window.Width = width;
                window.Height = height;
                window.ConfigurePreview(e.Args.Contains("--dark", StringComparer.Ordinal), e.Args.Contains("--english", StringComparer.Ordinal), tab);
                // Construct and lay out the actual controls/resources without showing a window or connecting.
                window.Measure(new Size(width, height));
                window.Arrange(new Rect(0, 0, width, height));
                window.UpdateLayout();
                Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ApplicationIdle);
                if (selfTestFailed) return;
                if (selfTestPaths.Length > 1)
                {
                    var previewPath = Path.GetFullPath(selfTestPaths[1]);
                    var visual = window.Content as FrameworkElement ?? throw new InvalidOperationException("Window has no renderable content.");
                    visual.Measure(new Size(width, height));
                    visual.Arrange(new Rect(0, 0, width, height));
                    visual.UpdateLayout();
                    Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ApplicationIdle);
                    if (selfTestFailed) return;
                    var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
                    bitmap.Render(visual);
                    var encoder = new PngBitmapEncoder();
                    encoder.Frames.Add(BitmapFrame.Create(bitmap));
                    Directory.CreateDirectory(Path.GetDirectoryName(previewPath)!);
                    using var preview = File.Create(previewPath);
                    encoder.Save(preview);
                }
                Directory.CreateDirectory(Path.GetDirectoryName(diagnosticsPath)!);
                File.WriteAllText(diagnosticsPath, "PASS: startup, dependency resolution, WPF resources and initial layout. No network connection performed.");
                Shutdown(0);
                return;
            }
            window.Show();
        }
        catch (Exception exception)
        {
            // Startup runs before any credentials are entered, so full diagnostics contain no user secrets.
            Log.Error(exception, "Startup failed");
            if (selfTest)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(diagnosticsPath)!);
                File.WriteAllText(diagnosticsPath, exception.ToString());
            }
            else MessageBox.Show(exception.GetBaseException().Message, "SSH Hardener — startup", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    private static int ReadPreviewNumber(string[] args, string name, int fallback)
    {
        var index = Array.IndexOf(args, name);
        var combined = args.FirstOrDefault(x => x.StartsWith(name + "=", StringComparison.Ordinal));
        var text = index >= 0 ? (index + 1 < args.Length ? args[index + 1] : "") : combined?[(name.Length + 1)..];
        return text is null ? fallback : int.TryParse(text, out var value) ? value : throw new ArgumentException("Invalid preview option: " + name);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Log.Information("SSH Hardener closed");
        Log.CloseAndFlush();
        _services?.DisposeAsync().AsTask().GetAwaiter().GetResult();
        base.OnExit(e);
    }
}
