using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SSHHardener.Core;
using SSHHardener.Profiles;
using SSHHardener.Ssh;

namespace SSHHardener.App;

public sealed class BulkHostRow(BulkTarget target, string initialState) : ObservableObject
{
    public BulkTarget Target { get; } = target;
    private bool _selected = true;
    private string _state = initialState, _detail = "";
    private int _percent;
    public bool Selected { get => _selected; set => SetProperty(ref _selected, value); }
    public string State { get => _state; set => SetProperty(ref _state, value); }
    public string Detail { get => _detail; set => SetProperty(ref _detail, value); }
    public int Percent { get => _percent; set => SetProperty(ref _percent, value); }
}

public sealed class BulkViewModel : ObservableObject, IDisposable
{
    private readonly BulkHardeningCoordinator _coordinator;
    private readonly ProfileStore _profiles;
    private HardeningOptions _template;
    private readonly ConcurrentDictionary<string, TotpEnrollment> _enrollments = new(StringComparer.Ordinal);
    private BulkPreview? _preview;
    private BulkHostRow? _selectedHost;
    private CancellationTokenSource? _operation;
    private TaskCompletionSource? _completion;
    private bool _busy, _applied, _stopOnFirstFailure = true;
    private int _concurrency = 1;
    private string _csv = "host,port,username,privateKeyPath,displayName\n", _status = "";

    public BulkViewModel(BulkHardeningCoordinator coordinator, ProfileStore profiles, HardeningOptions template, Localization localization)
    {
        _coordinator = coordinator; _profiles = profiles; _template = template; L = localization;
        Status = L["BulkReady"];
        ImportCsvCommand = new RelayCommand(() => RunLocal(ImportCsv), () => !Busy);
        ImportProfilesCommand = new AsyncRelayCommand(() => RunAsync(ImportProfilesAsync), () => !Busy);
        PreviewCommand = new AsyncRelayCommand(() => RunAsync(PreviewAsync), () => !Busy && Hosts.Any(x => x.Selected));
        ApplyCommand = new AsyncRelayCommand(() => RunAsync(ApplyAsync), () => CanApply);
        CancelCommand = new RelayCommand(Cancel, () => Busy);
    }
    public Localization L { get; }
    public ObservableCollection<BulkHostRow> Hosts { get; } = [];
    public int[] ConcurrencyChoices { get; } = [1, 2, 3, 4];
    public string Csv { get => _csv; set => SetProperty(ref _csv, value); }
    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    public bool Busy { get => _busy; private set { if (SetProperty(ref _busy, value)) RefreshCommands(); } }
    public bool Idle => !Busy;
    public bool CanApply => !Busy && !_applied && _preview is not null && _preview.Hosts.Count > 0 && _preview.Hosts.All(x => x.IsReady);
    public int Concurrency { get => _concurrency; set => SetProperty(ref _concurrency, value); }
    public bool StopOnFirstFailure { get => _stopOnFirstFailure; set => SetProperty(ref _stopOnFirstFailure, value); }
    public BulkHostRow? SelectedHost { get => _selectedHost; set { if (SetProperty(ref _selectedHost, value)) OnPropertyChanged(nameof(SelectedDetails)); } }
    public string SelectedDetails
    {
        get
        {
            var entry = _preview?.Hosts.FirstOrDefault(x => x.Target.Id == SelectedHost?.Target.Id);
            return entry?.IsReady == true ? L["BulkAuditLabel"] + "\n" + entry.Audit!.RawReport + "\n\n" + L["BulkPlanLabel"] + "\n" + entry.Plan!.Preview
                : SelectedHost?.Detail ?? L["BulkSelectHost"];
        }
    }
    public string PolicySummary
    {
        get
        {
            string fingerprint;
            try { fingerprint = KeyService.Fingerprint(_template.PublicKey); } catch (Exception) { fingerprint = L["BulkInvalidKey"]; }
            return L["BulkPolicySummary"] + "\n" + _template.Username + " · " + _template.NewPort + " · " + _template.AccountAccess + " · sudo=" + AccessPolicy.EffectiveSudo(_template) +
                " · MFA=" + (_template.EnableTotp ? L["BulkYes"] : L["BulkNo"]) + "\n" + L["BulkSharedKey"] + " " + fingerprint;
        }
    }
    public Func<BulkTarget, HardeningOptions, CancellationToken, Task<BulkCredentials?>>? RequestCredentials { get; set; }
    public Func<BulkTarget, CancellationToken, Task<TotpEnrollment?>>? RequestEnrollment { get; set; }
    public Func<BulkTarget, CancellationToken, Task<string?>>? RequestOtp { get; set; }
    public Func<BulkTarget, HostIdentity, CancellationToken, Task<bool>>? RequestTrust { get; set; }
    public Func<int, Task<bool>>? ConfirmApply { get; set; }
    public Action<Action>? Dispatch { get; set; }
    public IRelayCommand ImportCsvCommand { get; }
    public IAsyncRelayCommand ImportProfilesCommand { get; }
    public IAsyncRelayCommand PreviewCommand { get; }
    public IAsyncRelayCommand ApplyCommand { get; }
    public IRelayCommand CancelCommand { get; }
    public void Cancel() { _operation?.Cancel(); Status = L["BulkCancelling"]; }
    public Task WaitForIdleAsync() => _completion?.Task ?? Task.CompletedTask;

    private void ImportCsv() => ReplaceTargets(BulkHardeningCoordinator.ParseCsv(Csv));
    private async Task ImportProfilesAsync(CancellationToken ct)
    {
        var profiles = await _profiles.LoadAsync(ct);
        ReplaceTargets(profiles.Select((profile, index) => new BulkTarget("profile-" + (index + 1), profile.Name, profile.Host, profile.Port, profile.Username, profile.PrivateKeyPath)).ToArray());
    }
    private void ReplaceTargets(IReadOnlyList<BulkTarget> targets)
    {
        // Reuse strict endpoint, duplicate and size validation before admitting saved profiles.
        var csv = "host,port,username,privateKeyPath,id,displayName\n" + string.Join("\n", targets.Select(x => string.Join(',',
            new[] { x.Host, x.Port.ToString(System.Globalization.CultureInfo.InvariantCulture), x.Username, x.PrivateKeyPath ?? "", x.Id, x.DisplayName }.Select(QuoteCsv))));
        var checkedTargets = BulkHardeningCoordinator.ParseCsv(csv);
        foreach (var host in Hosts) host.PropertyChanged -= HostChanged;
        Hosts.Clear(); _enrollments.Clear(); InvalidatePreview();
        foreach (var target in checkedTargets)
        {
            var row = new BulkHostRow(target, L["BulkWaiting"]);
            row.PropertyChanged += HostChanged; Hosts.Add(row);
        }
        SelectedHost = Hosts.FirstOrDefault(); Status = L["BulkImported"] + " " + Hosts.Count;
        RefreshCommands();
    }
    private void HostChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    { if (e.PropertyName == nameof(BulkHostRow.Selected)) InvalidatePreview(); }
    private void InvalidatePreview()
    { _preview = null; _applied = false; OnPropertyChanged(nameof(SelectedDetails)); RefreshCommands(); }

    private async Task PreviewAsync(CancellationToken ct)
    {
        _preview = null; _applied = false;
        // Verify the explicitly shared target private/public pair locally, before contacting a host.
        var actual = await Task.Run(() => new KeyService().ReadPublicKey(_template.PrivateKeyPath, _template.KeyPassphrase), ct);
        if (KeyService.Fingerprint(actual) != KeyService.Fingerprint(_template.PublicKey)) throw new InvalidOperationException(L["BulkInvalidKey"]);
        foreach (var host in Hosts.Where(x => x.Selected)) { host.State = L["BulkWaiting"]; host.Detail = ""; host.Percent = 0; }
        _preview = await _coordinator.PreviewAsync(Hosts.Where(x => x.Selected).Select(x => x.Target).ToArray(), ConfigurationAsync,
            (target, identity, token) => RequestTrust?.Invoke(target, identity, token) ?? Task.FromResult(false), Settings(), Progress(), ct);
        foreach (var entry in _preview.Hosts)
        {
            var row = Hosts.First(x => x.Target.Id == entry.Target.Id);
            row.State = L[entry.IsReady ? "BulkPreviewReady" : "BulkFailed"];
            row.Detail = entry.IsReady ? L["BulkReviewHost"] : L["BulkPreviewFailed"] + " " + entry.Error;
        }
        Status = _preview.Hosts.All(x => x.IsReady) ? L["BulkReviewAll"] : L["BulkPreviewFailed"];
        OnPropertyChanged(nameof(SelectedDetails));
    }

    private async Task ApplyAsync(CancellationToken ct)
    {
        if (_preview is null || !_preview.Hosts.All(x => x.IsReady)) throw new InvalidOperationException(L["BulkReviewAll"]);
        if (ConfirmApply is null || !await ConfirmApply(_preview.Hosts.Count)) return;
        _applied = true; // A preview is a single attempt, including interrupted or failed attempts.
        var result = await _coordinator.ApplyAsync(_preview, ConfigurationAsync, Settings(), Progress(), ct);
        foreach (var outcome in result.Hosts)
        {
            var row = Hosts.First(x => x.Target.Id == outcome.Target.Id);
            row.State = L["BulkState" + outcome.State];
            row.Detail = row.State + (outcome.State is BulkHostState.Committed or BulkHostState.RolledBack && !outcome.HistoryUpdated ? " · " + L["HistorySaveFailed"] : "") +
                (outcome.TransactionId is null ? "" : "\n" + outcome.TransactionId) + "\n" + outcome.Message;
            if (outcome.State == BulkHostState.Committed) row.Percent = 100;
        }
        Status = L["BulkFinished"] + " " + string.Join(" · ", result.Hosts.GroupBy(x => x.State).Select(group => L["BulkState" + group.Key] + ": " + group.Count()));
        OnPropertyChanged(nameof(SelectedDetails));
    }

    private async Task<BulkHostConfiguration> ConfigurationAsync(BulkTarget target, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var credentials = RequestCredentials is null ? null : await RequestCredentials(target, _template, ct);
        if (credentials is null) { _operation?.Cancel(); throw new OperationCanceledException(ct); }
        var options = _template with
        {
            NewUserSudoPassword = AccessPolicy.EffectiveSudo(_template) == SudoPolicyMode.Password ? credentials.TargetAccountPassword : null,
            VerificationSudoPassword = AccessPolicy.EffectiveSudo(_template) == SudoPolicyMode.Legacy ? credentials.TargetAccountPassword : null,
            VerificationOneTimeCodeProvider = async token => await (RequestOtp?.Invoke(target, token) ?? Task.FromResult<string?>(null)) ??
                throw new OperationCanceledException("The one-time code dialog was cancelled.", token),
            IgnoreAddresses = (string[])_template.IgnoreAddresses.Clone(),
            RestrictedSudoCommands = (RestrictedSudoCommand[])_template.RestrictedSudoCommands.Clone(),
            TotpSecret = null, TotpEnrollmentCode = null, TotpEnrollmentConfirmedAt = null, TotpRecoveryCodes = []
        };
        if (options.EnableTotp)
        {
            if (!_enrollments.TryGetValue(target.Id, out var enrollment))
            {
                enrollment = RequestEnrollment is null ? null : await RequestEnrollment(target, ct);
                if (enrollment is null) { _operation?.Cancel(); throw new OperationCanceledException(ct); }
                _enrollments[target.Id] = enrollment;
            }
            if (enrollment.ConfirmedAt < DateTimeOffset.UtcNow.AddMinutes(-25))
            {
                var proof = RequestOtp is null ? null : await RequestOtp(target, ct);
                var now = DateTimeOffset.UtcNow;
                if (proof is null || !TotpService.VerifyCode(enrollment.Secret, proof, now)) throw new InvalidOperationException(L["MfaInvalidCode"]);
                enrollment = enrollment with { Code = proof, ConfirmedAt = now };
                _enrollments[target.Id] = enrollment;
            }
            options = options with { TotpSecret = enrollment.Secret, TotpEnrollmentCode = enrollment.Code,
                TotpEnrollmentConfirmedAt = enrollment.ConfirmedAt, TotpRecoveryCodes = (string[])enrollment.RecoveryCodes.Clone() };
        }
        var connection = new ConnectionOptions(target.Host, target.Port, target.Username, credentials.Password,
            target.PrivateKeyPath, credentials.KeyPassphrase, credentials.SudoPassword)
        {
            OneTimeCodeProvider = async token => await (RequestOtp?.Invoke(target, token) ?? Task.FromResult<string?>(null)) ??
                throw new OperationCanceledException("The one-time code dialog was cancelled.", token)
        };
        return new BulkHostConfiguration(connection, options);
    }

    private BulkRunSettings Settings() => new(Concurrency, StopOnFirstFailure);
    private IProgress<BulkProgress> Progress() => new ImmediateProgress(value =>
    {
        void Update()
        {
            var row = Hosts.FirstOrDefault(x => x.Target.Id == value.TargetId);
            if (row is null) return;
            row.State = L["BulkRunning"]; row.Detail = value.Stage; row.Percent = value.Percent;
        }
        if (Dispatch is null) Update(); else Dispatch(Update);
    });
    private void RunLocal(Action action)
    { try { action(); } catch (Exception error) { Status = L["BulkInputFailed"] + " (" + error.GetType().Name + ")."; } }
    private async Task RunAsync(Func<CancellationToken, Task> action)
    {
        if (Busy) return;
        Busy = true; _operation = new CancellationTokenSource(); _completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        try { await action(_operation.Token); }
        catch (OperationCanceledException) { Status = L["BulkCancelled"]; }
        catch (Exception error) { Status = L["BulkOperationFailed"] + " (" + error.GetType().Name + ")."; }
        finally
        {
            _operation.Dispose(); _operation = null; Busy = false; _completion.TrySetResult();
        }
    }
    private void RefreshCommands()
    {
        OnPropertyChanged(nameof(Idle)); OnPropertyChanged(nameof(CanApply));
        ImportCsvCommand?.NotifyCanExecuteChanged(); ImportProfilesCommand?.NotifyCanExecuteChanged();
        PreviewCommand?.NotifyCanExecuteChanged(); ApplyCommand?.NotifyCanExecuteChanged(); CancelCommand?.NotifyCanExecuteChanged();
    }
    public void Dispose()
    {
        _operation?.Cancel();
        foreach (var host in Hosts) host.PropertyChanged -= HostChanged;
        _enrollments.Clear(); _preview = null;
        _template = _template with { KeyPassphrase = null, NewUserSudoPassword = null, VerificationSudoPassword = null,
            VerificationOneTimeCodeProvider = null, TotpSecret = null, TotpEnrollmentCode = null, TotpRecoveryCodes = [] };
        RequestCredentials = null; RequestEnrollment = null; RequestOtp = null; RequestTrust = null; ConfirmApply = null; Dispatch = null;
    }
    private static string QuoteCsv(string value) => "\"" + value.Replace("\"", "\"\"") + "\"";
    private sealed class ImmediateProgress(Action<BulkProgress> report) : IProgress<BulkProgress>
    { public void Report(BulkProgress value) => report(value); }
}
