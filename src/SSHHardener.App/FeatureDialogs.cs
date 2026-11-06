using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SSHHardener.Core;

namespace SSHHardener.App;

public sealed record TotpEnrollment(string Secret, string Code, DateTimeOffset ConfirmedAt, string[] RecoveryCodes)
{
    public override string ToString() => "TOTP enrollment (secrets hidden)";
}
public sealed record BulkCredentials(string? Password, string? KeyPassphrase, string? SudoPassword, string? TargetAccountPassword)
{
    public override string ToString() => "Transient credentials (secrets hidden)";
}

/// <summary>User-driven secret entry only; these dialogs never persist or log their values.</summary>
public static class FeatureDialogs
{
    public static string? ShowOtp(Window? owner, Localization l, string label, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var panel = new StackPanel();
        var window = Dialog(owner, l["MfaCodeTitle"], panel);
        panel.Children.Add(Text(label, 17, true));
        panel.Children.Add(Text(l["MfaCodeHint"]));
        var code = new PasswordBox { MaxLength = 8 };
        panel.Children.Add(code);
        var error = Text(""); panel.Children.Add(error);
        string? result = null;
        Buttons(panel, window, l, () =>
        {
            var value = code.Password.Trim();
            if (value.Length is not (6 or 8) || value.Any(c => c is < '0' or > '9'))
            { error.Text = l["MfaInvalidCode"]; return; }
            result = value; code.Clear(); window.DialogResult = true;
        });
        window.Loaded += (_, _) => code.Focus();
        using var cancellation = CloseOnCancellation(window, ct);
        try { return window.ShowDialog() == true && !ct.IsCancellationRequested ? result : null; }
        finally { code.Clear(); }
    }

    public static TotpEnrollment? EnrollTotp(Window? owner, Localization l, string label, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var secret = TotpService.GenerateSecret();
        var recovery = TotpService.GenerateRecoveryCodes().ToArray();
        var panel = new StackPanel();
        var window = Dialog(owner, l["MfaEnrollmentTitle"], panel, 620);
        panel.Children.Add(Text(label, 17, true));
        panel.Children.Add(Text(l["MfaEnrollmentHint"]));
        panel.Children.Add(Text(l["MfaSecretLabel"], bold: true));
        panel.Children.Add(ReadOnly(secret));
        var uri = "otpauth://totp/" + Uri.EscapeDataString("SSHHardener:" + label) + "?secret=" + secret + "&issuer=SSHHardener&algorithm=SHA1&digits=6&period=30";
        panel.Children.Add(Text(l["MfaUriLabel"]));
        panel.Children.Add(ReadOnly(uri));
        panel.Children.Add(Text(l["MfaRecoveryLabel"], bold: true));
        panel.Children.Add(ReadOnly(string.Join("  ", recovery.Chunk(4).First()) + "\n" + string.Join("  ", recovery.Chunk(4).Last()), multiline: true));
        var saved = new CheckBox { Content = l["MfaRecoverySaved"] }; panel.Children.Add(saved);
        panel.Children.Add(Text(l["MfaConfirmCode"]));
        var code = new PasswordBox { MaxLength = 6 }; panel.Children.Add(code);
        var error = Text(""); panel.Children.Add(error);
        TotpEnrollment? result = null;
        Buttons(panel, window, l, () =>
        {
            var now = DateTimeOffset.UtcNow;
            var value = code.Password.Trim();
            if (saved.IsChecked != true) { error.Text = l["MfaSaveRecoveryFirst"]; return; }
            if (!TotpService.VerifyCode(secret, value, now)) { error.Text = l["MfaInvalidCode"]; return; }
            result = new TotpEnrollment(secret, value, now, (string[])recovery.Clone());
            code.Clear(); window.DialogResult = true;
        });
        using var cancellation = CloseOnCancellation(window, ct);
        try { return window.ShowDialog() == true && !ct.IsCancellationRequested ? result : null; }
        finally { code.Clear(); Array.Clear(recovery); }
    }

    public static BulkCredentials? ShowCredentials(Window? owner, Localization l, BulkTarget target, HardeningOptions template, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var panel = new StackPanel();
        var window = Dialog(owner, l["BulkCredentialsTitle"], panel);
        panel.Children.Add(Text(target.DisplayName + " · " + target.Username + "@" + target.Host + ":" + target.Port, 17, true));
        panel.Children.Add(Text(l["BulkCredentialsHint"]));
        var usingKey = !string.IsNullOrEmpty(target.PrivateKeyPath);
        panel.Children.Add(Text(usingKey ? l["BulkSourceKey"] + "\n" + target.PrivateKeyPath : l["BulkSourcePassword"], bold: true));
        var source = new PasswordBox { MaxLength = 4096 }; panel.Children.Add(source);
        panel.Children.Add(Text(l["BulkSourceSudo"]));
        var sudo = new PasswordBox { MaxLength = 256 }; panel.Children.Add(sudo);
        var targetPassword = new PasswordBox { MaxLength = 256 };
        var passwordPolicy = AccessPolicy.EffectiveSudo(template) == SudoPolicyMode.Password;
        var legacyPassword = AccessPolicy.EffectiveSudo(template) == SudoPolicyMode.Legacy && template.Username != "root";
        if (passwordPolicy || legacyPassword)
        {
            panel.Children.Add(Text(l[legacyPassword ? "BulkTargetVerificationPassword" : "BulkTargetPassword"] + " · " + template.Username));
            panel.Children.Add(targetPassword);
        }
        var error = Text(""); panel.Children.Add(error);
        BulkCredentials? result = null;
        Buttons(panel, window, l, () =>
        {
            if (!usingKey && string.IsNullOrEmpty(source.Password)) { error.Text = l["BulkCredentialRequired"]; return; }
            if (passwordPolicy && (targetPassword.Password.Length == 0 || template.CreateUser && targetPassword.Password.Length < 12))
            { error.Text = l["BulkTargetPasswordHint"]; return; }
            result = new BulkCredentials(usingKey ? null : source.Password, usingKey ? source.Password : null,
                string.IsNullOrEmpty(sudo.Password) ? null : sudo.Password,
                passwordPolicy || legacyPassword && !string.IsNullOrEmpty(targetPassword.Password) ? targetPassword.Password : null);
            source.Clear(); sudo.Clear(); targetPassword.Clear(); window.DialogResult = true;
        });
        window.Loaded += (_, _) => source.Focus();
        using var cancellation = CloseOnCancellation(window, ct);
        try { return window.ShowDialog() == true && !ct.IsCancellationRequested ? result : null; }
        finally { source.Clear(); sudo.Clear(); targetPassword.Clear(); }
    }

    private static CancellationTokenRegistration CloseOnCancellation(Window window, CancellationToken ct) => ct.Register(() =>
    {
        try { window.Dispatcher.BeginInvoke(new Action(() => { if (window.IsVisible) window.DialogResult = false; })); }
        catch (InvalidOperationException) { /* The owning dispatcher has already closed. */ }
    });

    private static Window Dialog(Window? owner, string title, StackPanel panel, double width = 520)
    {
        var window = new Window
        {
            Title = title, Width = width, MinWidth = 420, SizeToContent = SizeToContent.Height,
            MaxHeight = Math.Max(500, SystemParameters.WorkArea.Height - 80), ResizeMode = ResizeMode.CanResize,
            WindowStartupLocation = owner is null ? WindowStartupLocation.CenterScreen : WindowStartupLocation.CenterOwner,
            Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto }
        };
        if (owner?.IsVisible == true) window.Owner = owner;
        window.SetResourceReference(Window.BackgroundProperty, "BackgroundBrush");
        window.SetResourceReference(Window.ForegroundProperty, "ForegroundBrush");
        panel.Margin = new Thickness(24);
        return window;
    }
    private static TextBlock Text(string value, double size = 14, bool bold = false) => new()
    { Text = value, TextWrapping = TextWrapping.Wrap, FontSize = size, FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal, Margin = new Thickness(0, 0, 0, 12) };
    private static TextBox ReadOnly(string value, bool multiline = false) => new()
    { Text = value, IsReadOnly = true, FontFamily = new FontFamily("Consolas"), TextWrapping = TextWrapping.Wrap, AcceptsReturn = multiline, MinHeight = multiline ? 64 : 42 };
    private static void Buttons(Panel panel, Window window, Localization l, Action accept)
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
        var cancel = new Button { Content = l["BulkCancel"], IsCancel = true, MinWidth = 100 };
        var okay = new Button { Content = l["BulkContinue"], IsDefault = true, MinWidth = 100 };
        okay.Click += (_, _) => accept();
        row.Children.Add(cancel); row.Children.Add(okay); panel.Children.Add(row);
    }
}
