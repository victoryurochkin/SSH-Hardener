using System.ComponentModel;
using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace SSHHardener.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private bool _dark;
    private DispatcherOperation? _logScrollOperation;
    private bool _logScrollDisposed;

    public MainWindow(MainViewModel viewModel)
    {
        _viewModel = viewModel;
        InitializeComponent();
        DataContext = viewModel;
        viewModel.ReadConnectionSecrets = () => new ConnectionSecrets(ConnectionPassword.Password, ConnectionPassphrase.Password, ConnectionSudoPassword.Password);
        viewModel.ReadNewKeyPassphrase = () => NewKeyPassphrase.Password;
        viewModel.ClearConnectionSecrets = () => { ConnectionPassword.Clear(); ConnectionPassphrase.Clear(); ConnectionSudoPassword.Clear(); };
        viewModel.Log.CollectionChanged += OnLogCollectionChanged;
        ActionLog.Loaded += OnActionLogLoaded;
        ActionLog.Unloaded += OnActionLogUnloaded;
        Closed += OnWindowClosed;
        Loaded += async (_, _) => await viewModel.InitializeAsync();
    }

    private void ConnectionSecretChanged(object sender, RoutedEventArgs e) => _viewModel?.InvalidateConnection();
    private void NewKeySecretChanged(object sender, RoutedEventArgs e) => _viewModel?.InvalidatePlan();

    private void OnLogCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e) => ScheduleLogScroll();

    private void OnActionLogLoaded(object sender, RoutedEventArgs e) => ScheduleLogScroll();

    private void OnActionLogUnloaded(object sender, RoutedEventArgs e) => CancelLogScroll();

    private void ScheduleLogScroll()
    {
        if (_logScrollDisposed || !ActionLog.IsLoaded || !ActionLog.IsVisible ||
            Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished || _viewModel.Log.Count == 0)
            return;
        if (_logScrollOperation is { Status: DispatcherOperationStatus.Pending or DispatcherOperationStatus.Executing })
            return;

        // Never enter item generation while ObservableCollection is notifying its listeners.
        // One background callback runs after pending binding, render and loaded work.
        _logScrollOperation = Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
        {
            _logScrollOperation = null;
            if (_logScrollDisposed || !ActionLog.IsLoaded || !ActionLog.IsVisible || _viewModel.Log.Count == 0)
                return;
            ActionLog.ScrollIntoView(_viewModel.Log[^1]);
        }));
    }

    private void CancelLogScroll()
    {
        if (_logScrollOperation is { Status: DispatcherOperationStatus.Pending })
            _logScrollOperation.Abort();
        _logScrollOperation = null;
    }

    private void OnWindowClosed(object? sender, EventArgs e)
    {
        _logScrollDisposed = true;
        CancelLogScroll();
        _viewModel.Log.CollectionChanged -= OnLogCollectionChanged;
        ActionLog.Loaded -= OnActionLogLoaded;
        ActionLog.Unloaded -= OnActionLogUnloaded;
        Closed -= OnWindowClosed;
    }

    private void ComboBoxDropDownOpened(object? sender, EventArgs e)
    {
        if (sender is not ComboBox comboBox) return;
        comboBox.Focus();
        Keyboard.Focus(comboBox);
    }

    private void ToggleTheme(object sender, RoutedEventArgs e) => SetTheme(!_dark);

    public void ConfigurePreview(bool dark, bool english, int tab)
    {
        SetTheme(dark);
        if (_viewModel.L.English != english) _viewModel.LanguageCommand.Execute(null);
        _viewModel.SelectedTab = tab;
    }

    private void SetTheme(bool dark)
    {
        _dark = dark;
        var colors = _dark
            ? new[] { "#151E2D", "#202C3E", "#E5EDF7", "#ABBCD1", "#36455C", "#182436", "#FFB5A5", "#9D655B", "#183D3B", "#35625A", "#A1DEC8", "#263D42", "#52677B" }
            : new[] { "#F3F5F9", "#FFFFFF", "#18243A", "#5E6B80", "#DCE2EB", "#FFFFFF", "#9F4130", "#CBA89F", "#E1F0EB", "#B7D9CC", "#145E54", "#EDF3F1", "#9AA9B3" };
        var names = new[] { "BackgroundBrush", "CardBrush", "ForegroundBrush", "MutedBrush", "BorderBrush", "InputBrush", "WarningBrush", "WarningBorderBrush", "NavigationBrush", "NavigationBorderBrush", "NavigationTextBrush", "HoverBrush", "ScrollThumbBrush" };
        for (var i = 0; i < names.Length; i++) Application.Current.Resources[names[i]] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colors[i]));
    }

    private void WindowClosing(object? sender, CancelEventArgs e)
    {
        if (!_viewModel.Busy) return;
        e.Cancel = true;
        MessageBox.Show(_viewModel.L["CloseBusy"], "SSH Hardener", MessageBoxButton.OK, MessageBoxImage.Information);
    }

}
