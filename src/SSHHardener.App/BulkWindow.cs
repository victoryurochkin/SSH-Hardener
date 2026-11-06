using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Microsoft.Win32;
using SSHHardener.Core;
using SSHHardener.Profiles;

namespace SSHHardener.App;

/// <summary>Isolated batch UI. All host trust and credential dialogs are serialized on its dispatcher.</summary>
public sealed class BulkWindow : Window
{
    private readonly BulkViewModel _viewModel;
    private readonly SemaphoreSlim _dialogs = new(1, 1);
    private bool _closingAfterRecovery;

    public BulkWindow(BulkViewModel viewModel)
    {
        _viewModel = viewModel;
        DataContext = viewModel;
        Title = viewModel.L["BulkTitle"];
        Width = 1120; Height = 820; MinWidth = 860; MinHeight = 620;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        SetResourceReference(BackgroundProperty, "BackgroundBrush");
        SetResourceReference(ForegroundProperty, "ForegroundBrush");
        if (TryFindResource("ShieldLockIcon") is ImageSource icon) Icon = icon;
        Content = BuildContent();
        viewModel.Dispatch = action => { if (Dispatcher.CheckAccess()) action(); else Dispatcher.Invoke(action); };
        viewModel.RequestCredentials = (target, template, ct) => DialogAsync(() => FeatureDialogs.ShowCredentials(this, viewModel.L, target, template, ct), ct);
        viewModel.RequestEnrollment = (target, ct) => DialogAsync(() => FeatureDialogs.EnrollTotp(this, viewModel.L, target.DisplayName + " · " + templateLabel(target), ct), ct);
        viewModel.RequestOtp = (target, ct) => DialogAsync(() => FeatureDialogs.ShowOtp(this, viewModel.L, templateLabel(target), ct), ct);
        viewModel.RequestTrust = (target, identity, ct) => identity.IsKnown ? Task.FromResult(true) : DialogAsync(() =>
            MessageBox.Show(this, viewModel.L["BulkTrustHint"] + "\n\n" + target.Host + ":" + target.Port + "\n" + identity.Algorithm + "\n" + identity.Fingerprint,
                viewModel.L["BulkTrustTitle"], MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) == MessageBoxResult.Yes, ct);
        viewModel.ConfirmApply = count => DialogAsync(() => MessageBox.Show(this,
            viewModel.L["BulkApplyConfirmation"] + " " + count + "\n\n" + viewModel.PolicySummary + "\n\n" + viewModel.L["BulkIndependentTransactions"],
            viewModel.L["BulkApply"], MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes, CancellationToken.None);
        Closing += OnClosing;
        Closed += (_, _) => { viewModel.Dispose(); _dialogs.Dispose(); };
        static string templateLabel(BulkTarget target) => target.Username + "@" + target.Host;
    }

    private UIElement BuildContent()
    {
        var l = _viewModel.L;
        var root = new Grid { Margin = new Thickness(22) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        var heading = new StackPanel();
        heading.Children.Add(new TextBlock { Text = l["BulkTitle"], FontSize = 24, FontWeight = FontWeights.SemiBold });
        heading.Children.Add(new TextBlock { Text = l["BulkIndependentTransactions"], TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 12) });
        var summary = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) };
        summary.SetBinding(TextBlock.TextProperty, new Binding(nameof(BulkViewModel.PolicySummary)));
        heading.Children.Add(summary); root.Children.Add(heading);

        var import = new StackPanel(); Grid.SetRow(import, 1); root.Children.Add(import);
        var expander = new Expander { Header = l["BulkImportHeading"], IsExpanded = true, Margin = new Thickness(0, 0, 0, 12) };
        expander.SetBinding(IsEnabledProperty, new Binding(nameof(BulkViewModel.Idle)));
        var input = new StackPanel(); expander.Content = input;
        input.Children.Add(new TextBlock { Text = l["BulkCsvHint"], TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) });
        var csv = new TextBox { AcceptsReturn = true, AcceptsTab = true, Height = 86, MaxLength = BulkHardeningCoordinator.MaximumCsvCharacters,
            FontFamily = new FontFamily("Consolas"), FontSize = 12, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto };
        csv.SetBinding(TextBox.TextProperty, new Binding(nameof(BulkViewModel.Csv)) { UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged });
        input.Children.Add(csv);
        var imports = new WrapPanel(); input.Children.Add(imports);
        var browse = new Button { Content = l["BulkBrowseCsv"] }; browse.Click += BrowseCsv; imports.Children.Add(browse);
        imports.Children.Add(CommandButton(l["BulkImportCsv"], nameof(BulkViewModel.ImportCsvCommand)));
        imports.Children.Add(CommandButton(l["BulkImportProfiles"], nameof(BulkViewModel.ImportProfilesCommand)));
        import.Children.Add(expander);

        var center = new Grid(); Grid.SetRow(center, 2); root.Children.Add(center);
        center.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1.05, GridUnitType.Star) });
        center.RowDefinitions.Add(new RowDefinition { Height = new GridLength(8) });
        center.RowDefinitions.Add(new RowDefinition { Height = new GridLength(0.95, GridUnitType.Star) });
        var hosts = new DataGrid
        {
            AutoGenerateColumns = false, CanUserAddRows = false, CanUserDeleteRows = false,
            HeadersVisibility = DataGridHeadersVisibility.Column, SelectionMode = DataGridSelectionMode.Single,
            GridLinesVisibility = DataGridGridLinesVisibility.Horizontal, RowHeaderWidth = 0,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };
        hosts.SetBinding(ItemsControl.ItemsSourceProperty, new Binding(nameof(BulkViewModel.Hosts)));
        hosts.SetBinding(DataGrid.SelectedItemProperty, new Binding(nameof(BulkViewModel.SelectedHost)) { Mode = BindingMode.TwoWay });
        hosts.SetBinding(IsEnabledProperty, new Binding(nameof(BulkViewModel.Idle)));
        hosts.SetResourceReference(BackgroundProperty, "InputBrush"); hosts.SetResourceReference(ForegroundProperty, "ForegroundBrush");
        hosts.SetResourceReference(Control.BorderBrushProperty, "BorderBrush"); hosts.SetResourceReference(DataGrid.RowBackgroundProperty, "InputBrush");
        var header = new Style(typeof(System.Windows.Controls.Primitives.DataGridColumnHeader));
        header.Setters.Add(new Setter(BackgroundProperty, new DynamicResourceExtension("CardBrush")));
        header.Setters.Add(new Setter(ForegroundProperty, new DynamicResourceExtension("ForegroundBrush")));
        header.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(8)));
        hosts.ColumnHeaderStyle = header;
        hosts.Columns.Add(new DataGridCheckBoxColumn { Header = "✓", Binding = new Binding(nameof(BulkHostRow.Selected)) { UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged }, Width = 42 });
        hosts.Columns.Add(Column(l["BulkHost"], "Target.DisplayName", 150));
        hosts.Columns.Add(Column(l["Host"], "Target.Host", 160));
        hosts.Columns.Add(Column(l["Port"], "Target.Port", 65));
        hosts.Columns.Add(Column(l["Username"], "Target.Username", 100));
        hosts.Columns.Add(Column(l["BulkState"], nameof(BulkHostRow.State), 185));
        hosts.Columns.Add(Column("%", nameof(BulkHostRow.Percent), 50));
        hosts.Columns.Add(new DataGridTextColumn { Header = l["BulkDetail"], Binding = new Binding(nameof(BulkHostRow.Detail)), Width = new DataGridLength(1, DataGridLengthUnitType.Star), IsReadOnly = true });
        center.Children.Add(hosts);
        var splitter = new GridSplitter { Height = 6, HorizontalAlignment = HorizontalAlignment.Stretch, Background = Brushes.Transparent };
        Grid.SetRow(splitter, 1); center.Children.Add(splitter);
        var details = new TextBox { IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.NoWrap,
            FontFamily = new FontFamily("Consolas"), FontSize = 12, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0) };
        details.SetBinding(TextBox.TextProperty, new Binding(nameof(BulkViewModel.SelectedDetails)) { Mode = BindingMode.OneWay });
        Grid.SetRow(details, 2); center.Children.Add(details);

        var bottom = new StackPanel { Margin = new Thickness(0, 12, 0, 0) }; Grid.SetRow(bottom, 3); root.Children.Add(bottom);
        var controls = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };
        var settings = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        settings.SetBinding(IsEnabledProperty, new Binding(nameof(BulkViewModel.Idle)));
        settings.Children.Add(new TextBlock { Text = l["BulkConcurrency"], VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
        var concurrency = new ComboBox { Width = 64, Margin = new Thickness(0, 0, 16, 0) };
        concurrency.SetBinding(ItemsControl.ItemsSourceProperty, new Binding(nameof(BulkViewModel.ConcurrencyChoices)));
        concurrency.SetBinding(ComboBox.SelectedItemProperty, new Binding(nameof(BulkViewModel.Concurrency)) { Mode = BindingMode.TwoWay });
        settings.Children.Add(concurrency);
        var stop = new CheckBox { Content = l["BulkStopOnFailure"], VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 18, 0) };
        stop.SetBinding(System.Windows.Controls.Primitives.ToggleButton.IsCheckedProperty, new Binding(nameof(BulkViewModel.StopOnFirstFailure)) { Mode = BindingMode.TwoWay });
        settings.Children.Add(stop); controls.Children.Add(settings);
        controls.Children.Add(CommandButton(l["BulkPreview"], nameof(BulkViewModel.PreviewCommand)));
        controls.Children.Add(CommandButton(l["BulkApply"], nameof(BulkViewModel.ApplyCommand)));
        controls.Children.Add(CommandButton(l["BulkCancel"], nameof(BulkViewModel.CancelCommand)));
        bottom.Children.Add(controls);
        var status = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 0) };
        status.SetBinding(TextBlock.TextProperty, new Binding(nameof(BulkViewModel.Status))); bottom.Children.Add(status);
        return root;
    }

    private async Task<T> DialogAsync<T>(Func<T> show, CancellationToken ct)
    {
        await _dialogs.WaitAsync(ct);
        try
        {
            ct.ThrowIfCancellationRequested();
            return await Dispatcher.InvokeAsync(() => { ct.ThrowIfCancellationRequested(); return show(); });
        }
        finally { _dialogs.Release(); }
    }
    private void BrowseCsv(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "CSV|*.csv|Text|*.txt", CheckFileExists = true };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            if (new FileInfo(dialog.FileName).Length > BulkHardeningCoordinator.MaximumCsvCharacters) throw new InvalidDataException();
            _viewModel.Csv = File.ReadAllText(dialog.FileName);
            _viewModel.ImportCsvCommand.Execute(null);
        }
        catch (Exception) { MessageBox.Show(this, _viewModel.L["BulkInputFailed"], Title, MessageBoxButton.OK, MessageBoxImage.Error); }
    }
    private async void OnClosing(object? sender, CancelEventArgs e)
    {
        if (_closingAfterRecovery || !_viewModel.Busy) return;
        e.Cancel = true; _viewModel.Cancel();
        await _viewModel.WaitForIdleAsync();
        _closingAfterRecovery = true;
        // WaitForIdleAsync can finish synchronously while WPF is still dispatching Closing.
        _ = Dispatcher.BeginInvoke(new Action(Close));
    }
    private static DataGridTextColumn Column(string title, string path, double width) => new()
    { Header = title, Binding = new Binding(path), Width = width, IsReadOnly = true };
    private static Button CommandButton(string title, string command)
    { var button = new Button { Content = title }; button.SetBinding(Button.CommandProperty, new Binding(command)); return button; }
}
