using System.Collections.ObjectModel;
using System.IO;
using System.Net;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Serilog;
using SSHHardener.Core;
using SSHHardener.Reports;
using SSHHardener.Ssh;

namespace SSHHardener.App;

public sealed record ConnectionSecrets(string Password, string Passphrase, string SudoPassword);

public sealed class MainViewModel : ObservableObject, IAsyncDisposable
{
    private readonly IRemoteSessionFactory _sessions;
    private readonly IAuditService _auditor;
    private readonly IPlanBuilder _planner;
    private readonly IHardeningEngine _engine;
    private readonly KeyService _keys;
    private readonly ProfileStore _profiles;
    private readonly ReportExporter _reports;
    private IRemoteSession? _session;
    private ServerAudit? _audit;
    private HardeningPlan? _plan;
    private HardeningResult? _result;
    private CancellationTokenSource? _operation;
    private TaskCompletionSource? _operationCompletion;
    private bool _uiFailed;
    private bool _connectionChanged;
    private bool _busy;
    private string _host = "", _port = "22", _username = "root", _privateKey = "";
    private string _newPort = "22022", _newUsername = "sshadmin", _newPrivateKey = "", _publicKey = "";
    private bool _createUser = true, _grantSudo, _noPasswordSudo, _disablePassword = true, _closeOldPort, _disableForwarding, _fail2Ban = true;
    private string _rootPolicy = "prohibit-password", _maxRetry = "3", _maxAuthTries = "3", _findTimeMinutes = "10", _banSeconds = "3600", _whitelist = "", _rollbackMinutes = "10";
    private string _status = "", _auditText = "", _previewText = "", _banText = "", _banIp = "", _summary = "", _keyFingerprint = "";
    private int _progress, _selectedTab;
    private ServerProfile? _selectedProfile;

    public MainViewModel(IRemoteSessionFactory sessions, IAuditService auditor, IPlanBuilder planner,
        IHardeningEngine engine, KeyService keys, ProfileStore profiles, ReportExporter reports)
    {
        (_sessions, _auditor, _planner, _engine, _keys, _profiles, _reports) = (sessions, auditor, planner, engine, keys, profiles, reports);
        Status = L["Ready"];
        AuditText = L["EmptyAudit"];
        PreviewText = L["EmptyPlan"];
        BanText = L["EmptyBans"];
        Summary = L["Disconnected"];
        ConnectCommand = new AsyncRelayCommand(() => RunAsync(ConnectAsync));
        AuditCommand = new AsyncRelayCommand(() => RunAsync(AuditAsync));
        BuildPlanCommand = new AsyncRelayCommand(() => RunAsync(BuildPlanAsync));
        ApplyCommand = new AsyncRelayCommand(() => RunAsync(ApplyAsync));
        RollbackCommand = new AsyncRelayCommand(() => RunAsync(RollbackAsync));
        RefreshBansCommand = new AsyncRelayCommand(() => RunAsync(RefreshBansAsync));
        UnbanCommand = new AsyncRelayCommand(() => RunAsync(UnbanAsync));
        ExportCommand = new AsyncRelayCommand(() => RunAsync(ExportAsync));
        GenerateKeyCommand = new AsyncRelayCommand(() => RunAsync(GenerateKeyAsync));
        ExportPuttyKeyCommand = new AsyncRelayCommand(() => RunAsync(ExportPuttyKeyAsync));
        ReadPublicKeyCommand = new AsyncRelayCommand(() => RunAsync(ReadPublicKeyAsync));
        SaveProfileCommand = new AsyncRelayCommand(() => RunAsync(SaveProfileAsync));
        LoadProfileCommand = new RelayCommand(LoadProfile);
        ImportPublicKeyCommand = new RelayCommand(ImportPublicKey);
        BrowseKeyCommand = new RelayCommand(() => { var path = BrowsePrivateKey(); if (path is not null) PrivateKey = path; });
        BrowseNewKeyCommand = new RelayCommand(() => { var path = BrowsePrivateKey(); if (path is not null) NewPrivateKey = path; });
        CancelCommand = new RelayCommand(() => _operation?.Cancel());
        LanguageCommand = new RelayCommand(() =>
        {
            var knownStatus = new[] { "Ready", "Connecting", "Auditing", "Connected", "AuditReadOnlyStatus", "PlanReady", "Applying", "Failed", "OperationCancelled" }
                .FirstOrDefault(key => Status == L[key]);
            var emptyBans = BanText == L["EmptyBans"];
            L.Toggle();
            if (_audit is null) AuditText = L["EmptyAudit"];
            if (_plan is null) PreviewText = L["EmptyPlan"];
            if (emptyBans) BanText = L["EmptyBans"];
            if (_session is null) Summary = L["Disconnected"];
            if (knownStatus is not null) Status = L[knownStatus];
            NotifyAvailability();
        });
    }

    public Localization L { get; } = new();
    public Func<ConnectionSecrets>? ReadConnectionSecrets { get; set; }
    public Func<string>? ReadNewKeyPassphrase { get; set; }
    public Action? ClearConnectionSecrets { get; set; }
    public ObservableCollection<ServerProfile> Profiles { get; } = [];
    public ObservableCollection<string> Log { get; } = [];
    public string[] RootPolicies { get; } = ["prohibit-password", "no"];
    public bool Busy { get => _busy; private set { SetProperty(ref _busy, value); OnPropertyChanged(nameof(Idle)); NotifyAvailability(); } }
    public bool Idle => !Busy && !_uiFailed;
    private bool SessionAvailable => _session is not null && !_connectionChanged;
    public bool CanConnect => Idle && !string.IsNullOrWhiteSpace(Host) && !string.IsNullOrWhiteSpace(Username) && int.TryParse(Port, out var port) && port is > 0 and < 65536;
    public bool CanAudit => Idle && SessionAvailable;
    public bool CanBuildPlan => CanAudit && _audit?.HasRoot == true;
    public bool HasPlanBlocker => !CanBuildPlan;
    public string PlanAvailabilityMessage => Busy ? L["PlanBusy"]
        : _session is null ? L["PlanConnectRequired"]
        : _connectionChanged ? L["PlanReconnectRequired"]
        : _audit is null ? L["PlanAuditRequired"]
        : !_audit.HasRoot ? L["PlanAdminRequired"] : "";
    public string AuditPrivilegeMessage => _audit is null ? ""
        : L[_audit.HasRoot ? "AuditAdminVerified" : "AuditReadOnly"];
    public bool CanApply => CanAudit && _plan is not null;
    public bool CanRollback => Idle && _session is not null && _executedPlan is not null;
    public bool CanExport => Idle && (_audit is not null || _executedPlan is not null);
    public bool CanManageBans => CanAudit && _audit?.HasRoot == true;
    public bool CanUnban => CanManageBans && IPAddress.TryParse(BanIp.Trim(), out _);
    public bool CanLoadProfile => Idle && SelectedProfile is not null;
    public bool CanExportPuttyKey => Idle && !string.IsNullOrWhiteSpace(NewPrivateKey);
    public string Host { get => _host; set => SetConnection(ref _host, value); }
    public string Port { get => _port; set => SetConnection(ref _port, value); }
    public string Username { get => _username; set => SetConnection(ref _username, value); }
    public string PrivateKey { get => _privateKey; set => SetConnection(ref _privateKey, value); }
    public string NewPort { get => _newPort; set => SetOption(ref _newPort, value); }
    public string NewUsername { get => _newUsername; set => SetOption(ref _newUsername, value); }
    public string NewPrivateKey { get => _newPrivateKey; set => SetOption(ref _newPrivateKey, value); }
    public string PublicKey
    {
        get => _publicKey;
        set
        {
            SetOption(ref _publicKey, value);
            try { KeyFingerprint = KeyService.Fingerprint(value); }
            catch (Exception ex) when (ex is FormatException or IndexOutOfRangeException or ArgumentException) { KeyFingerprint = ""; }
        }
    }
    public string KeyFingerprint { get => _keyFingerprint; private set => SetProperty(ref _keyFingerprint, value); }
    public bool CreateUser { get => _createUser; set => SetOption(ref _createUser, value); }
    public bool GrantSudo { get => _grantSudo; set { SetOption(ref _grantSudo, value); if (!value) NoPasswordSudo = false; } }
    public bool NoPasswordSudo { get => _noPasswordSudo; set => SetOption(ref _noPasswordSudo, value); }
    public bool DisablePassword { get => _disablePassword; set => SetOption(ref _disablePassword, value); }
    public bool CloseOldPort { get => _closeOldPort; set => SetOption(ref _closeOldPort, value); }
    public bool DisableForwarding { get => _disableForwarding; set => SetOption(ref _disableForwarding, value); }
    public bool Fail2Ban { get => _fail2Ban; set => SetOption(ref _fail2Ban, value); }
    public string RootPolicy { get => _rootPolicy; set => SetOption(ref _rootPolicy, value); }
    public string MaxRetry { get => _maxRetry; set => SetOption(ref _maxRetry, value); }
    public string MaxAuthTries { get => _maxAuthTries; set => SetOption(ref _maxAuthTries, value); }
    public string FindTimeMinutes { get => _findTimeMinutes; set => SetOption(ref _findTimeMinutes, value); }
    public string BanSeconds { get => _banSeconds; set => SetOption(ref _banSeconds, value); }
    public string Whitelist { get => _whitelist; set => SetOption(ref _whitelist, value); }
    public string RollbackMinutes { get => _rollbackMinutes; set => SetOption(ref _rollbackMinutes, value); }
    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    public string AuditText { get => _auditText; private set => SetProperty(ref _auditText, value); }
    public string PreviewText { get => _previewText; private set => SetProperty(ref _previewText, value); }
    public string BanText { get => _banText; private set => SetProperty(ref _banText, value); }
    public string BanIp { get => _banIp; set { SetProperty(ref _banIp, value); NotifyAvailability(); } }
    public string Summary { get => _summary; private set => SetProperty(ref _summary, value); }
    public int Progress { get => _progress; private set => SetProperty(ref _progress, value); }
    public int SelectedTab { get => _selectedTab; set => SetProperty(ref _selectedTab, value); }
    public ServerProfile? SelectedProfile { get => _selectedProfile; set { SetProperty(ref _selectedProfile, value); NotifyAvailability(); } }
    public IAsyncRelayCommand ConnectCommand { get; }
    public IAsyncRelayCommand AuditCommand { get; }
    public IAsyncRelayCommand BuildPlanCommand { get; }
    public IAsyncRelayCommand ApplyCommand { get; }
    public IAsyncRelayCommand RollbackCommand { get; }
    public IAsyncRelayCommand RefreshBansCommand { get; }
    public IAsyncRelayCommand UnbanCommand { get; }
    public IAsyncRelayCommand ExportCommand { get; }
    public IAsyncRelayCommand GenerateKeyCommand { get; }
    public IAsyncRelayCommand ExportPuttyKeyCommand { get; }
    public IAsyncRelayCommand ReadPublicKeyCommand { get; }
    public IAsyncRelayCommand SaveProfileCommand { get; }
    public IRelayCommand LoadProfileCommand { get; }
    public IRelayCommand ImportPublicKeyCommand { get; }
    public IRelayCommand BrowseKeyCommand { get; }
    public IRelayCommand BrowseNewKeyCommand { get; }
    public IRelayCommand CancelCommand { get; }
    public IRelayCommand LanguageCommand { get; }

    public async Task InitializeAsync()
    {
        try { foreach (var profile in await _profiles.LoadAsync(CancellationToken.None)) Profiles.Add(profile); }
        catch (Exception ex) { AddLog(ex.Message); }
    }

    public void InvalidatePlan()
    {
        _plan = null;
        PreviewText = L["EmptyPlan"];
        NotifyAvailability();
    }

    private void NotifyAvailability()
    {
        foreach (var name in new[] { nameof(CanConnect), nameof(CanAudit), nameof(CanBuildPlan), nameof(HasPlanBlocker),
            nameof(PlanAvailabilityMessage), nameof(AuditPrivilegeMessage), nameof(CanApply),
            nameof(CanRollback), nameof(CanExport), nameof(CanManageBans), nameof(CanUnban), nameof(CanLoadProfile), nameof(CanExportPuttyKey) })
            OnPropertyChanged(name);
    }

    public void InvalidateConnection()
    {
        _connectionChanged = true;
        _audit = null;
        AuditText = L["EmptyAudit"];
        Summary = L["Disconnected"];
        InvalidatePlan();
    }

    private void SetConnection<T>(ref T field, T value, [System.Runtime.CompilerServices.CallerMemberName] string? name = null)
    {
        if (SetProperty(ref field, value, name)) InvalidateConnection();
    }

    private void SetOption<T>(ref T field, T value, [System.Runtime.CompilerServices.CallerMemberName] string? name = null)
    {
        if (SetProperty(ref field, value, name)) InvalidatePlan();
    }

    private async Task RunAsync(Func<CancellationToken, Task> action)
    {
        if (Busy || _uiFailed) return;
        Busy = true;
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _operationCompletion = completion;
        using var cancellation = new CancellationTokenSource();
        _operation = cancellation;
        var actionName = action.Method.Name;
        Serilog.Log.Information("Operation {Operation} started", actionName);
        try
        {
            await action(cancellation.Token);
            Serilog.Log.Information("Operation {Operation} completed", actionName);
        }
        catch (OperationCanceledException)
        {
            Serilog.Log.Information("Operation {Operation} cancelled", actionName);
            if (_uiFailed) return;
            Status = L["OperationCancelled"]; AddLog(Status);
        }
        catch (Exception ex)
        {
            Serilog.Log.Warning("Operation {Operation} failed with {FailureType}", actionName, ex.GetType().Name);
            if (_uiFailed) return;
            Status = L["Failed"];
            AddLog(ex.Message);
            MessageBox.Show(ex.Message, L["Error"], MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            _operation = null;
            try { Busy = false; }
            finally { _operationCompletion = null; completion.TrySetResult(); }
        }
    }

    public Task StopForUiFailureAsync()
    {
        _uiFailed = true;
        try { _operation?.Cancel(); }
        catch (AggregateException error)
        {
            Serilog.Log.Error("UI failure cancellation callback failed with {FailureType}", error.GetType().Name);
        }
        return _operationCompletion?.Task ?? Task.CompletedTask;
    }

    private async Task ConnectAsync(CancellationToken ct)
    {
        Status = L["Connecting"];
        if (string.IsNullOrWhiteSpace(Host) || string.IsNullOrWhiteSpace(Username)) throw new ArgumentException(L["Host"] + " / " + L["Username"]);
        var secrets = ReadConnectionSecrets?.Invoke() ?? new ConnectionSecrets("", "", "");
        var options = new ConnectionOptions(Host.Trim(), ParsePort(Port), Username.Trim(),
            string.IsNullOrEmpty(PrivateKey) ? secrets.Password : null, NullIfEmpty(PrivateKey), NullIfEmpty(secrets.Passphrase), NullIfEmpty(secrets.SudoPassword));
        if (_session is not null) { await _session.DisposeAsync(); _session = null; }
        _audit = null;
        InvalidatePlan();
        _session = await _sessions.ConnectAsync(options, TrustHostAsync, ct);
        if (_executedPlan is not null &&
            (!string.Equals(_executedPlan.OriginalConnection.Host, options.Host, StringComparison.OrdinalIgnoreCase) ||
             !string.Equals(_executedIdentityKey, _session.Identity.KeyBase64, StringComparison.Ordinal)))
        {
            _executedPlan = null;
            _result = null;
            _executedIdentityKey = null;
        }
        _connectionChanged = false;
        await AuditAsync(ct);
    }

    private Task<bool> TrustHostAsync(HostIdentity host)
    {
        if (host.IsKnown) return Task.FromResult(true);
        return Application.Current.Dispatcher.InvokeAsync(() =>
            MessageBox.Show($"{host.Host}:{host.Port}\n{host.Algorithm}\n\n{host.Fingerprint}\n\n{L["ConfirmHost"]}",
                "SSH host key", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes).Task;
    }

    private IRemoteSession RequireSession()
    {
        if (_session is null) throw new InvalidOperationException(L["NoConnection"]);
        if (_connectionChanged) throw new InvalidOperationException(L["StaleConnection"]);
        return _session;
    }

    private async Task AuditAsync(CancellationToken ct)
    {
        var session = RequireSession();
        Status = L["Auditing"];
        InvalidatePlan();
        _audit = null;
        _audit = await _auditor.AuditAsync(session, ct);
        AuditText = _audit.RawReport + "\n\n" + _audit.EffectiveConfig + "\n\n" + string.Join("\n", _audit.Warnings);
        Summary = $"{_audit.Description}  •  {_audit.OpenSshVersion}\n{_audit.Firewall}  /  {_audit.InitSystem}  /  SELinux: {_audit.Selinux}";
        Status = L[_audit.HasRoot ? "Connected" : "AuditReadOnlyStatus"];
        AddLog(Status + ": " + _audit.Description);
        SelectedTab = 1;
    }

    private async Task BuildPlanAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var session = RequireSession();
        if (_audit is null) throw new InvalidOperationException(L["EmptyAudit"]);
        if (!int.TryParse(MaxRetry, out var retries) || !int.TryParse(MaxAuthTries, out var maxAuthTries) ||
            !int.TryParse(FindTimeMinutes, out var findMinutes) || findMinutes is < 1 or > 1440 ||
            !int.TryParse(BanSeconds, out var ban) || !int.TryParse(RollbackMinutes, out var rollback)) throw new ArgumentException(L["NumberInvalid"]);
        var options = new HardeningOptions
        {
            NewPort = ParsePort(NewPort), Username = NewUsername.Trim(), PublicKey = PublicKey.Trim(),
            PrivateKeyPath = NewPrivateKey, KeyPassphrase = NullIfEmpty(ReadNewKeyPassphrase?.Invoke()),
            CreateUser = CreateUser, GrantSudo = GrantSudo, NoPasswordSudo = NoPasswordSudo,
            DisablePasswordAuthentication = DisablePassword, PermitRootLogin = RootPolicy,
            CloseOldPort = CloseOldPort, DisableForwarding = DisableForwarding,
            ConfigureFail2Ban = Fail2Ban, MaxRetry = retries, MaxAuthTries = maxAuthTries, FindTimeSeconds = findMinutes * 60, BanSeconds = ban,
            IgnoreAddresses = Whitelist.Split([',', ';', '\n', '\r'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries),
            RollbackMinutes = rollback
        };
        if (!File.Exists(options.PrivateKeyPath)) throw new ArgumentException(L["NewPrivateKey"]);
        var derived = await Task.Run(() => _keys.ReadPublicKey(options.PrivateKeyPath, options.KeyPassphrase), ct);
        if (string.IsNullOrWhiteSpace(options.PublicKey)) { PublicKey = derived; options = options with { PublicKey = derived }; }
        if (!KeyIdentity(options.PublicKey).Equals(KeyIdentity(derived), StringComparison.Ordinal)) throw new ArgumentException(L.English ? "Public and private keys do not match." : "Публичный и приватный ключи не совпадают.");
        _plan = _planner.Build(_audit, session.Options, options);
        PreviewText = string.Join("\n", _plan.Warnings.Select(x => "# WARNING: " + x)) + "\n\n" + _plan.Preview;
        Status = L["PlanReady"];
        SelectedTab = 3;
    }

    private async Task ApplyAsync(CancellationToken ct)
    {
        var session = RequireSession();
        var plan = _plan ?? throw new InvalidOperationException(L["StalePlan"]);
        if ((plan.Options.NoPasswordSudo || plan.Options.BanSeconds == -1) &&
            !Confirm(L["ConfirmRisk"] + "\n\n" + plan.Audit.AdminAddress)) return;
        if (!Confirm(L["ConfirmApply"])) return;
        SelectedTab = 4;
        Progress = 0;
        Status = L["Applying"];
        _executedPlan = plan;
        _executedIdentityKey = session.Identity.KeyBase64;
        _result = null;
        IProgress<OperationProgress> uiProgress = new Progress<OperationProgress>(value =>
        {
            if (_uiFailed) return;
            Progress = value.Percent; Status = value.Message; AddLog($"{value.Step}: {value.Message}");
        });
        // Record stage starts before queuing UI work, so a stalled dispatcher cannot hide later steps.
        var progress = new InlineProgress<OperationProgress>(value =>
        {
            Serilog.Log.Information("Transaction {TransactionId} stage {Stage} at {Percent} percent", plan.TransactionId, value.Step, value.Percent);
            uiProgress.Report(value);
        });
        try
        {
            _result = await _engine.ApplyAsync(session, plan, progress, ct);
            Serilog.Log.Information("Transaction {TransactionId} finished: committed={Committed}, rolledBack={RolledBack}",
                plan.TransactionId, _result.Committed, _result.RolledBack);
            if (_uiFailed) return;
            Status = _result.Message;
            AddLog(Status);
        }
        finally
        {
            InvalidatePlan();
            // Any attempt may change the server, including attempts interrupted by network failure.
            _connectionChanged = true;
        }
    }

    private HardeningPlan? _executedPlan;
    private string? _executedIdentityKey;

    private async Task RollbackAsync(CancellationToken ct)
    {
        var plan = _executedPlan ?? throw new InvalidOperationException(L.English ? "No transaction has been applied yet." : "Пока не было попыток применения транзакции.");
        if (!Confirm(L["ConfirmRollback"])) return;
        if (_session is null) throw new InvalidOperationException(L["NoConnection"]);
        if (!string.Equals(_executedIdentityKey, _session.Identity.KeyBase64, StringComparison.Ordinal))
            throw new InvalidOperationException("Rollback server identity mismatch.");
        await _engine.RollbackAsync(_session, plan.TransactionId, ct);
        _result = new HardeningResult(plan.TransactionId, false, true, L["RollbackComplete"], DateTimeOffset.UtcNow);
        InvalidateConnection();
        Status = L["RollbackComplete"];
        AddLog(Status + ": " + plan.TransactionId);
    }

    private async Task RefreshBansAsync(CancellationToken ct)
    {
        var result = await RequireSession().ExecuteAsync("fail2ban-client status sshhardener-sshd", true, ct);
        result.EnsureSuccess("fail2ban");
        BanText = result.Output;
    }

    private async Task UnbanAsync(CancellationToken ct)
    {
        if (!IPAddress.TryParse(BanIp.Trim(), out var ip)) throw new ArgumentException(L["BanIp"]);
        var result = await RequireSession().ExecuteAsync("fail2ban-client set sshhardener-sshd unbanip '" + ip + "'", true, ct);
        result.EnsureSuccess("unban");
        await RefreshBansAsync(ct);
    }

    private async Task ExportAsync(CancellationToken ct)
    {
        var audit = _audit ?? _executedPlan?.Audit ?? throw new InvalidOperationException(L["NoAudit"]);
        var dialog = new SaveFileDialog { FileName = "SSHHardener-report.html", Filter = "HTML|*.html|Markdown|*.md", AddExtension = true };
        if (dialog.ShowDialog() != true) return;
        await _reports.ExportAsync(dialog.FileName, audit, _executedPlan ?? _plan, _result, ct);
        AddLog(L["ReportSaved"]);
    }

    private async Task GenerateKeyAsync(CancellationToken ct)
    {
        var dialog = new SaveFileDialog { FileName = "sshadmin", Filter = "Encrypted PuTTY PPK v3 (RDM / PuTTY)|*.ppk|Encrypted PKCS#8 PEM|*.pem", FilterIndex = 1, AddExtension = true, OverwritePrompt = false };
        if (dialog.ShowDialog() != true) return;
        if (File.Exists(dialog.FileName) || File.Exists(dialog.FileName + ".pub")) throw new IOException(L["KeyExists"]);
        var format = dialog.FilterIndex == 1 ? PrivateKeyFormat.EncryptedPuttyV3 : PrivateKeyFormat.EncryptedPkcs8Pem;
        PublicKey = await _keys.GenerateRsaAsync(dialog.FileName, ReadNewKeyPassphrase?.Invoke() ?? "", ct, format);
        NewPrivateKey = dialog.FileName;
        AddLog(L["KeyGenerated"]);
        MessageBox.Show($"{L["KeyGenerated"]}\n\n{dialog.FileName}\n{dialog.FileName}.pub", "SSH Hardener", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async Task ExportPuttyKeyAsync(CancellationToken ct)
    {
        var source = NewPrivateKey;
        if (!File.Exists(source)) throw new ArgumentException(L["NewPrivateKey"]);
        var dialog = new SaveFileDialog
        {
            Title = L["ExportPuttyTitle"],
            FileName = Path.GetFileNameWithoutExtension(source) + ".ppk",
            Filter = "Encrypted PuTTY PPK v3|*.ppk", AddExtension = true, DefaultExt = ".ppk", OverwritePrompt = false
        };
        if (dialog.ShowDialog() != true) return;
        var passphrase = ReadNewKeyPassphrase?.Invoke() ?? "";
        var publicKey = await _keys.ExportRsaToPuttyAsync(source, dialog.FileName, passphrase, passphrase, ct);
        AddLog(L["PuttyKeyExported"]);
        MessageBox.Show($"{L["PuttyKeyExported"]}\n\n{dialog.FileName}\n\n{KeyService.Fingerprint(publicKey)}", "SSH Hardener", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async Task ReadPublicKeyAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var path = NewPrivateKey;
        var passphrase = ReadNewKeyPassphrase?.Invoke();
        PublicKey = await Task.Run(() => _keys.ReadPublicKey(path, passphrase), ct);
    }

    private void ImportPublicKey()
    {
        var dialog = new OpenFileDialog { Filter = "OpenSSH public key|*.pub|All files|*.*" };
        if (dialog.ShowDialog() != true) return;
        if (new FileInfo(dialog.FileName).Length > 16384) throw new IOException("Public key file exceeds 16 KiB.");
        PublicKey = File.ReadAllText(dialog.FileName).Trim();
    }

    private async Task SaveProfileAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(Host) || string.IsNullOrWhiteSpace(Username)) throw new ArgumentException(L["Host"] + " / " + L["Username"]);
        var profile = new ServerProfile($"{Username}@{Host}:{Port}", Host.Trim(), ParsePort(Port), Username.Trim(), NullIfEmpty(PrivateKey));
        var profiles = Profiles.Where(x => x.Name != profile.Name).Append(profile).ToArray();
        await _profiles.SaveAsync(profiles, ct);
        Profiles.Clear(); foreach (var item in profiles) Profiles.Add(item);
        SelectedProfile = profile;
        AddLog(L["ProfileSaved"]);
    }

    private void LoadProfile()
    {
        if (Busy || SelectedProfile is not { } profile) return;
        Host = profile.Host; Port = profile.Port.ToString(); Username = profile.Username; PrivateKey = profile.PrivateKeyPath ?? "";
        ClearConnectionSecrets?.Invoke();
        InvalidateConnection();
    }

    private static string? BrowsePrivateKey()
    {
        var dialog = new OpenFileDialog { Filter = "Private key|*.ppk;*.pem;*.key;id_*|All files|*.*" };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    private static string KeyIdentity(string value) => string.Join(" ", value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Take(2));
    private int ParsePort(string value) => int.TryParse(value, out var port) && port is > 0 and < 65536 ? port : throw new ArgumentException(L["PortInvalid"]);
    private static string? NullIfEmpty(string? value) => string.IsNullOrEmpty(value) ? null : value;
    private bool Confirm(string text) => MessageBox.Show(text, "SSH Hardener", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes;
    private void AddLog(string value) { Log.Add($"{DateTimeOffset.Now:HH:mm:ss}  {value}"); while (Log.Count > 1000) Log.RemoveAt(0); }

    private sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }

    public async ValueTask DisposeAsync()
    {
        _operation?.Cancel();
        var session = _session;
        _session = null;
        if (session is not null) await session.DisposeAsync().ConfigureAwait(false);
    }
}
