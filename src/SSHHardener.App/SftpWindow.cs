using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using SSHHardener.Core;

namespace SSHHardener.App;

/// <summary>A real SFTP client window. Every mutation is initiated explicitly by the user.</summary>
public sealed class SftpWindow : Window
{
    private readonly SftpBrowserViewModel _vm;
    private readonly PasswordBox _password = new() { MaxLength = 1024 };
    private readonly PasswordBox _passphrase = new() { MaxLength = 4096 };
    private bool _closing;

    public SftpWindow(SftpBrowserViewModel vm)
    {
        _vm = vm; DataContext = vm;
        Title = vm.L["SftpTitle"]; Width = 1040; Height = 820; MinWidth = 760; MinHeight = 620;
        WindowStartupLocation = WindowStartupLocation.CenterOwner; FontFamily = new FontFamily("Segoe UI"); FontSize = 14;
        SetResourceReference(BackgroundProperty, "BackgroundBrush"); SetResourceReference(ForegroundProperty, "ForegroundBrush");
        if (TryFindResource("ShieldLockIcon") is ImageSource icon) Icon = icon;
        vm.ReadSecrets = () => new SftpConnectionSecrets(_password.Password, _passphrase.Password);
        vm.ClearSecrets = () => { _password.Clear(); _passphrase.Clear(); };
        vm.TrustHost = TrustHostAsync;
        vm.RequestOneTimeCode = ct => Dispatcher.InvokeAsync(() =>
        {
            ct.ThrowIfCancellationRequested();
            var code = FeatureDialogs.ShowOtp(this, vm.L, vm.Username + "@" + vm.Host);
            ct.ThrowIfCancellationRequested();
            return code ?? throw new OperationCanceledException(ct);
        }).Task;
        Content = BuildContent();
        Closing += ClosingAsync;
    }

    private UIElement BuildContent()
    {
        var root = new Grid { Margin = new Thickness(24, 18, 24, 16) };
        foreach (var height in new[] { GridLength.Auto, GridLength.Auto, GridLength.Auto, GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto })
            root.RowDefinitions.Add(new RowDefinition { Height = height });
        var heading = new StackPanel();
        heading.Children.Add(new TextBlock { Text = _vm.L["SftpTitle"], FontSize = 25, FontWeight = FontWeights.SemiBold });
        heading.Children.Add(new TextBlock { Text = _vm.L["SftpHint"], TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 14) });
        root.Children.Add(heading);

        var connection = new Grid();
        connection.SetBinding(IsEnabledProperty, new Binding(nameof(_vm.Idle)));
        connection.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });
        connection.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
        connection.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });
        foreach (var unused in Enumerable.Range(0, 3)) connection.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        Field(connection, 0, 0, _vm.L["Host"], Input(nameof(_vm.Host)));
        Field(connection, 0, 1, _vm.L["Port"], Input(nameof(_vm.Port)));
        Field(connection, 0, 2, _vm.L["Username"], Input(nameof(_vm.Username)));
        Field(connection, 1, 0, _vm.L["Password"], _password);
        Field(connection, 1, 2, _vm.L["Passphrase"], _passphrase);
        var keyRow = new DockPanel();
        var browse = Button(_vm.L["Browse"], () => BrowseKeyAsync());
        browse.Style = TryFindResource("SecondaryButton") as Style;
        DockPanel.SetDock(browse, Dock.Right); keyRow.Children.Add(browse); keyRow.Children.Add(Input(nameof(_vm.PrivateKeyPath)));
        var keyField = Field(connection, 2, 0, _vm.L["PrivateKey"], keyRow); Grid.SetColumnSpan(keyField, 3);
        Grid.SetRow(connection, 1); root.Children.Add(connection);

        var connectionActions = new WrapPanel { Margin = new Thickness(0, 0, 0, 4) };
        connectionActions.Children.Add(Button(_vm.L["SftpConnect"], _vm.ConnectAsync, nameof(_vm.CanConnect)));
        var mfa = new CheckBox { Content = _vm.L["SftpUseMfa"], VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(14, 0, 12, 6) };
        mfa.SetBinding(System.Windows.Controls.Primitives.ToggleButton.IsCheckedProperty, new Binding(nameof(_vm.UseOneTimeCode)) { Mode = BindingMode.TwoWay });
        mfa.SetBinding(IsEnabledProperty, new Binding(nameof(_vm.Idle))); connectionActions.Children.Add(mfa);
        connectionActions.Children.Add(Button(_vm.L["SftpCancel"], () => { _vm.Cancel(); return Task.CompletedTask; }, nameof(_vm.Busy)));
        Grid.SetRow(connectionActions, 2); root.Children.Add(connectionActions);

        var navigation = new DockPanel();
        var go = Button(_vm.L["SftpGo"], _vm.RefreshAsync, nameof(_vm.CanBrowse)); DockPanel.SetDock(go, Dock.Right); navigation.Children.Add(go);
        var up = Button(_vm.L["SftpUp"], _vm.UpAsync, nameof(_vm.CanUp)); DockPanel.SetDock(up, Dock.Left); navigation.Children.Add(up);
        var path = Input(nameof(_vm.DirectoryPath)); path.FontFamily = new FontFamily("Consolas");
        path.SetBinding(IsEnabledProperty, new Binding(nameof(_vm.Idle)));
        path.KeyDown += async (_, args) => { if (args.Key == Key.Enter && _vm.CanBrowse) { args.Handled = true; await _vm.RefreshAsync(); } };
        navigation.Children.Add(path); Grid.SetRow(navigation, 3); root.Children.Add(navigation);

        var browser = new Grid(); browser.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        browser.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        var tools = new WrapPanel();
        tools.Children.Add(Button(_vm.L["SftpRefresh"], _vm.RefreshAsync, nameof(_vm.CanBrowse)));
        tools.Children.Add(Button(_vm.L["SftpOpen"], _vm.OpenSelectedAsync, nameof(_vm.CanOpen)));
        tools.Children.Add(Button(_vm.L["SftpUpload"], UploadAsync, nameof(_vm.CanMutate)));
        tools.Children.Add(Button(_vm.L["SftpDownload"], DownloadAsync, nameof(_vm.CanDownload)));
        tools.Children.Add(Button(_vm.L["SftpNewFolder"], NewFolderAsync, nameof(_vm.CanMutate)));
        tools.Children.Add(Button(_vm.L["SftpRename"], RenameAsync, nameof(_vm.CanUseSelection)));
        tools.Children.Add(Button(_vm.L["SftpDelete"], DeleteAsync, nameof(_vm.CanUseSelection)));
        browser.Children.Add(tools);
        var files = new DataGrid { AutoGenerateColumns = false, IsReadOnly = true, CanUserAddRows = false,
            CanUserDeleteRows = false, SelectionMode = DataGridSelectionMode.Single, HeadersVisibility = DataGridHeadersVisibility.Column,
            GridLinesVisibility = DataGridGridLinesVisibility.Horizontal, RowHeight = 34, Margin = new Thickness(0, 0, 0, 10) };
        files.SetResourceReference(BackgroundProperty, "CardBrush"); files.SetResourceReference(ForegroundProperty, "ForegroundBrush");
        files.SetResourceReference(Control.BorderBrushProperty, "BorderBrush"); files.SetResourceReference(DataGrid.RowBackgroundProperty, "CardBrush");
        files.SetResourceReference(DataGrid.AlternatingRowBackgroundProperty, "HoverBrush");
        var cellStyle = new Style(typeof(DataGridCell));
        cellStyle.Setters.Add(new Setter(Control.ForegroundProperty, new DynamicResourceExtension("ForegroundBrush")));
        cellStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.Transparent));
        cellStyle.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
        cellStyle.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(8, 3, 8, 3)));
        var selectedCell = new Trigger { Property = DataGridCell.IsSelectedProperty, Value = true };
        selectedCell.Setters.Add(new Setter(Control.BackgroundProperty, new DynamicResourceExtension("AccentBrush")));
        selectedCell.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.White));
        cellStyle.Triggers.Add(selectedCell); files.CellStyle = cellStyle;
        var headerStyle = new Style(typeof(DataGridColumnHeader));
        headerStyle.Setters.Add(new Setter(Control.BackgroundProperty, new DynamicResourceExtension("NavigationBrush")));
        headerStyle.Setters.Add(new Setter(Control.ForegroundProperty, new DynamicResourceExtension("ForegroundBrush")));
        headerStyle.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(10, 9, 10, 9))); files.ColumnHeaderStyle = headerStyle;
        files.Columns.Add(new DataGridTextColumn { Header = _vm.L["SftpName"], Binding = new Binding(nameof(SftpBrowserEntry.Name)), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        files.Columns.Add(new DataGridTextColumn { Header = _vm.L["SftpType"], Binding = new Binding(nameof(SftpBrowserEntry.Type)), Width = 110 });
        files.Columns.Add(new DataGridTextColumn { Header = _vm.L["SftpSize"], Binding = new Binding(nameof(SftpBrowserEntry.Size)), Width = 120 });
        files.Columns.Add(new DataGridTextColumn { Header = _vm.L["SftpModified"], Binding = new Binding(nameof(SftpBrowserEntry.Modified)), Width = 150 });
        files.SetBinding(ItemsControl.ItemsSourceProperty, new Binding(nameof(_vm.Entries)));
        files.SetBinding(DataGrid.SelectedItemProperty, new Binding(nameof(_vm.SelectedEntry)) { Mode = BindingMode.TwoWay });
        files.SetBinding(IsEnabledProperty, new Binding(nameof(_vm.Idle)));
        files.MouseDoubleClick += async (_, _) => { if (_vm.CanOpen) await _vm.OpenSelectedAsync(); };
        Grid.SetRow(files, 1); browser.Children.Add(files); Grid.SetRow(browser, 4); root.Children.Add(browser);

        var status = new TextBlock { TextWrapping = TextWrapping.Wrap, MinHeight = 24 };
        status.SetBinding(TextBlock.TextProperty, new Binding(nameof(_vm.Status)));
        Grid.SetRow(status, 5); root.Children.Add(status);
        return root;
    }

    private TextBox Input(string property)
    {
        var box = new TextBox();
        box.SetBinding(TextBox.TextProperty, new Binding(property) { UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged });
        return box;
    }

    private static StackPanel Field(Grid grid, int row, int column, string label, UIElement input)
    {
        var field = new StackPanel { Margin = new Thickness(0, 0, column == 2 ? 0 : 14, 0) };
        field.Children.Add(new TextBlock { Text = label }); field.Children.Add(input);
        Grid.SetRow(field, row); Grid.SetColumn(field, column); grid.Children.Add(field); return field;
    }

    private Button Button(string label, Func<Task> action, string? enabled = null)
    {
        var button = new Button { Content = label, Margin = new Thickness(0, 4, 8, 10), Padding = new Thickness(14, 9, 14, 9) };
        if (enabled is not null) button.SetBinding(IsEnabledProperty, new Binding(enabled));
        button.Click += async (_, _) =>
        {
            try { await action(); }
            catch { MessageBox.Show(this, _vm.L["SftpFailed"], _vm.L["SftpTitle"], MessageBoxButton.OK, MessageBoxImage.Error); }
        };
        return button;
    }

    private Task BrowseKeyAsync()
    {
        var dialog = new OpenFileDialog { Filter = _vm.L["SftpKeyFilter"], CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) _vm.PrivateKeyPath = dialog.FileName;
        return Task.CompletedTask;
    }

    private async Task UploadAsync()
    {
        var dialog = new OpenFileDialog { CheckFileExists = true };
        if (dialog.ShowDialog(this) != true) return;
        var name = System.IO.Path.GetFileName(dialog.FileName);
        var exists = _vm.Entries.Any(entry => entry.Name == name);
        if (exists && !Confirm(_vm.L["SftpOverwrite"] + "\n\n" + name)) return;
        await _vm.UploadAsync(dialog.FileName, overwrite: exists);
    }

    private async Task DownloadAsync()
    {
        var selected = _vm.SelectedEntry;
        if (selected is null) return;
        var dialog = new SaveFileDialog { FileName = selected.Name, OverwritePrompt = false };
        if (dialog.ShowDialog(this) != true) return;
        var exists = System.IO.File.Exists(dialog.FileName);
        if (exists && !Confirm(_vm.L["SftpOverwrite"] + "\n\n" + dialog.FileName)) return;
        await _vm.DownloadSelectedAsync(dialog.FileName, overwrite: exists);
    }

    private async Task NewFolderAsync()
    {
        var name = PromptName(_vm.L["SftpNewFolder"], "");
        if (name is not null) await _vm.CreateDirectoryAsync(name);
    }
    private async Task RenameAsync()
    {
        if (_vm.SelectedEntry is not { } selected) return;
        var name = PromptName(_vm.L["SftpRename"], selected.Name);
        if (name is not null) await _vm.RenameSelectedAsync(name);
    }
    private async Task DeleteAsync()
    {
        if (_vm.SelectedEntry is not { } selected || !Confirm(_vm.L["SftpDeleteConfirm"] + "\n\n" + selected.Name)) return;
        await _vm.DeleteSelectedAsync();
    }

    private string? PromptName(string title, string initial)
    {
        var panel = new StackPanel { Margin = new Thickness(24) };
        panel.Children.Add(new TextBlock { Text = _vm.L["SftpEnterName"], TextWrapping = TextWrapping.Wrap });
        var name = new TextBox { Text = initial, MaxLength = 255 }; panel.Children.Add(name);
        var window = new Window { Title = title, Owner = this, Width = 450, SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, ResizeMode = ResizeMode.NoResize, Content = panel };
        window.SetResourceReference(BackgroundProperty, "BackgroundBrush"); window.SetResourceReference(ForegroundProperty, "ForegroundBrush");
        var row = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var cancel = new Button { Content = _vm.L["SftpCancel"], IsCancel = true };
        var okay = new Button { Content = _vm.L["SftpContinue"], IsDefault = true };
        okay.Click += (_, _) => { if (!string.IsNullOrWhiteSpace(name.Text)) window.DialogResult = true; };
        row.Children.Add(cancel); row.Children.Add(okay); panel.Children.Add(row);
        window.Loaded += (_, _) => { name.Focus(); name.SelectAll(); };
        return window.ShowDialog() == true ? name.Text : null;
    }

    private bool Confirm(string message) => MessageBox.Show(this, message, _vm.L["SftpTitle"], MessageBoxButton.YesNo,
        MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes;

    private Task<bool> TrustHostAsync(HostIdentity identity) => identity.IsKnown ? Task.FromResult(true) : Dispatcher.InvokeAsync(() =>
        Confirm(identity.Host + ":" + identity.Port + "\n" + identity.Algorithm + "\n\n" + identity.Fingerprint + "\n\n" + _vm.L["ConfirmHost"])).Task;

    private async void ClosingAsync(object? sender, CancelEventArgs args)
    {
        if (_closing) return;
        args.Cancel = true; IsEnabled = false; _vm.Cancel();
        try { await _vm.DisposeAsync(); }
        catch { /* Close releases credentials and remote handles even after a connection error. */ }
        finally
        {
            _password.Clear(); _passphrase.Clear(); _closing = true;
            // Disposal may complete synchronously; defer Close until this Closing event has returned.
            _ = Dispatcher.BeginInvoke(new Action(Close));
        }
    }
}
