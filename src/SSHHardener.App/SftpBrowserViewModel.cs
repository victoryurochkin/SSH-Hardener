using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using SSHHardener.Core;
using SSHHardener.Ssh;

namespace SSHHardener.App;

public sealed record SftpConnectionSecrets(string Password, string Passphrase)
{
    public override string ToString() => "Transient SFTP credentials (hidden)";
}

public sealed record SftpBrowserEntry(RemoteFileEntry Remote, string Type, string Size, string Modified)
{
    public string Name => Remote.Name;
}

/// <summary>A user-driven browser. Credentials stay in the active connection and are never persisted or logged.</summary>
public sealed class SftpBrowserViewModel : ObservableObject, IAsyncDisposable
{
    private readonly ISftpSessionFactory _factory;
    private readonly ConnectionOptions _initialEndpoint;
    private Func<CancellationToken, Task<string>>? _initialOtp;
    private ISftpSession? _session;
    private CancellationTokenSource? _operation;
    private TaskCompletionSource? _operationFinished;
    private string _host, _port, _username, _privateKeyPath, _directoryPath = "/", _listedPath = "", _status;
    private (string Host, string Port, string User, string Key)? _activeEndpoint;
    private bool _busy, _disposed, _useOneTimeCode;
    private SftpBrowserEntry? _selectedEntry;

    public SftpBrowserViewModel(ISftpSessionFactory factory, ConnectionOptions initial, Localization l)
    {
        _factory = factory;
        L = l;
        _host = initial.Host; _port = initial.Port.ToString(CultureInfo.InvariantCulture);
        _username = initial.Username; _privateKeyPath = initial.PrivateKeyPath ?? "";
        // Keep only endpoint metadata and the explicit OTP callback; never retain the caller's passwords.
        _initialEndpoint = initial with { Password = null, Passphrase = null, SudoPassword = null, OneTimeCodeProvider = null };
        _initialOtp = initial.OneTimeCodeProvider;
        _useOneTimeCode = _initialOtp is not null;
        _status = L["SftpDisconnected"];
    }

    public Localization L { get; }
    public ObservableCollection<SftpBrowserEntry> Entries { get; } = [];
    public Func<SftpConnectionSecrets>? ReadSecrets { get; set; }
    public Action? ClearSecrets { get; set; }
    public Func<HostIdentity, Task<bool>> TrustHost { get; set; } = identity => Task.FromResult(identity.IsKnown);
    public Func<CancellationToken, Task<string>>? RequestOneTimeCode { get; set; }
    public string Host { get => _host; set { if (SetProperty(ref _host, value)) NotifyAvailability(); } }
    public string Port { get => _port; set { if (SetProperty(ref _port, value)) NotifyAvailability(); } }
    public string Username { get => _username; set { if (SetProperty(ref _username, value)) NotifyAvailability(); } }
    public string PrivateKeyPath { get => _privateKeyPath; set { if (SetProperty(ref _privateKeyPath, value)) NotifyAvailability(); } }
    public bool UseOneTimeCode { get => _useOneTimeCode; set => SetProperty(ref _useOneTimeCode, value); }
    public string DirectoryPath { get => _directoryPath; set { if (SetProperty(ref _directoryPath, value)) NotifyAvailability(); } }
    public SftpBrowserEntry? SelectedEntry { get => _selectedEntry; set { if (SetProperty(ref _selectedEntry, value)) NotifyAvailability(); } }
    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    public bool Busy { get => _busy; private set { if (SetProperty(ref _busy, value)) NotifyAvailability(); } }
    public bool Idle => !Busy && !_disposed;
    public bool CanConnect => Idle && !string.IsNullOrWhiteSpace(Host) && !string.IsNullOrWhiteSpace(Username) &&
        int.TryParse(Port, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port is >= 1 and <= 65535;
    public bool CanBrowse => Idle && _session is not null && _activeEndpoint == Endpoint;
    public bool CanMutate => CanBrowse && _listedPath == DirectoryPath;
    public bool CanUseSelection => CanMutate && SelectedEntry is not null && !SelectedEntry.Remote.IsSymbolicLink;
    public bool CanDownload => CanUseSelection && SelectedEntry!.Remote is { IsDirectory: false, IsSymbolicLink: false };
    public bool CanOpen => CanUseSelection && SelectedEntry!.Remote is { IsDirectory: true, IsSymbolicLink: false };
    public bool CanUp => CanBrowse && _listedPath != "/" && _listedPath.Length > 0;
    private (string Host, string Port, string User, string Key) Endpoint => (Host, Port, Username, PrivateKeyPath);

    public Task ConnectAsync() => RunAsync(async ct =>
    {
        try
        {
        if (!int.TryParse(Port, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
            throw new ArgumentException();
        var secrets = ReadSecrets?.Invoke() ?? new SftpConnectionSecrets("", "");
        var sameInitial = string.Equals(Host, _initialEndpoint.Host, StringComparison.OrdinalIgnoreCase) &&
            port == _initialEndpoint.Port && Username == _initialEndpoint.Username;
        var provider = UseOneTimeCode ? sameInitial && _initialOtp is not null ? _initialOtp : RequestOneTimeCode : null;
        if (UseOneTimeCode && provider is null) throw new InvalidOperationException();
        var connection = new ConnectionOptions(Host, port, Username,
            string.IsNullOrWhiteSpace(PrivateKeyPath) ? secrets.Password : null,
            string.IsNullOrWhiteSpace(PrivateKeyPath) ? null : PrivateKeyPath,
            string.IsNullOrEmpty(secrets.Passphrase) ? null : secrets.Passphrase) { OneTimeCodeProvider = provider };
            if (_session is not null) { await _session.DisposeAsync(); _session = null; }
            _activeEndpoint = null; _listedPath = ""; Entries.Clear(); SelectedEntry = null;
            _session = await _factory.ConnectSftpAsync(connection, TrustHost, ct);
            _activeEndpoint = Endpoint;
            DirectoryPath = "/";
            await RefreshCoreAsync(ct);
        }
        finally { ClearSecrets?.Invoke(); }
    }, "SftpConnecting");

    public Task RefreshAsync() => RunAsync(RefreshCoreAsync);
    public Task UpAsync() => RunAsync(async ct =>
    {
        RequireSession();
        if (_listedPath.Length == 0 || _listedPath == "/") return;
        var slash = _listedPath.LastIndexOf('/');
        DirectoryPath = slash <= 0 ? "/" : _listedPath[..slash];
        await RefreshCoreAsync(ct);
    });
    public Task OpenSelectedAsync() => RunAsync(async ct =>
    {
        var selected = RequireSelected();
        if (!selected.Remote.IsDirectory || selected.Remote.IsSymbolicLink) throw new InvalidOperationException();
        DirectoryPath = selected.Remote.FullPath;
        await RefreshCoreAsync(ct);
    });

    public Task UploadAsync(string localPath, bool overwrite = false) => RunAsync(async ct =>
    {
        var session = RequireListedSession();
        var destination = ChildPath(Path.GetFileName(localPath));
        await using var source = new FileStream(localPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81_920, true);
        await session.UploadAsync(source, destination, overwrite, ct);
        await RefreshCoreAsync(ct);
    }, "SftpTransferring");

    public Task DownloadSelectedAsync(string localPath, bool overwrite = false) => RunAsync(async ct =>
    {
        var session = RequireListedSession();
        var selected = RequireSelected();
        if (selected.Remote.IsDirectory || selected.Remote.IsSymbolicLink) throw new InvalidOperationException();
        var destination = Path.GetFullPath(localPath);
        var temporary = destination + "." + Guid.NewGuid().ToString("N") + ".partial";
        var created = false;
        try
        {
            await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81_920, true))
            {
                created = true;
                await session.DownloadAsync(selected.Remote.FullPath, output, ct);
                await output.FlushAsync(ct); output.Flush(true);
            }
            ct.ThrowIfCancellationRequested();
            // The save dialog is responsible for explicit overwrite approval.
            File.Move(temporary, destination, overwrite);
            created = false;
        }
        finally { if (created) File.Delete(temporary); }
    }, "SftpTransferring");

    public Task CreateDirectoryAsync(string name) => RunAsync(async ct =>
    {
        await RequireListedSession().CreateDirectoryAsync(ChildPath(name), ct);
        await RefreshCoreAsync(ct);
    });
    public Task RenameSelectedAsync(string name) => RunAsync(async ct =>
    {
        var selected = RequireSelected();
        await RequireListedSession().RenameAsync(selected.Remote.FullPath, ChildPath(name), ct);
        await RefreshCoreAsync(ct);
    });
    public Task DeleteSelectedAsync() => RunAsync(async ct =>
    {
        var selected = RequireSelected();
        if (selected.Remote.IsSymbolicLink) throw new InvalidOperationException();
        await RequireListedSession().DeleteAsync(selected.Remote.FullPath, selected.Remote.IsDirectory, ct);
        await RefreshCoreAsync(ct);
    });

    public void Cancel() => _operation?.Cancel();

    private async Task RefreshCoreAsync(CancellationToken ct)
    {
        var rows = await RequireSession().ListAsync(DirectoryPath, ct);
        var culture = CultureInfo.GetCultureInfo(L.English ? "en" : "ru");
        var projected = rows.Select(row => new SftpBrowserEntry(row,
            L[row.IsSymbolicLink ? "SftpLink" : row.IsDirectory ? "SftpFolder" : "SftpFile"],
            row.IsDirectory ? "—" : row.Length.ToString("N0", culture) + " B", row.LastWriteTime.ToLocalTime().ToString("g", culture))).ToArray();
        Entries.Clear(); foreach (var row in projected) Entries.Add(row);
        _listedPath = DirectoryPath; SelectedEntry = null;
        NotifyAvailability();
    }

    private ISftpSession RequireSession() => _session is not null && _activeEndpoint == Endpoint ? _session : throw new InvalidOperationException();
    private ISftpSession RequireListedSession() => _listedPath == DirectoryPath ? RequireSession() : throw new InvalidOperationException();
    private SftpBrowserEntry RequireSelected() => _listedPath == DirectoryPath && SelectedEntry is not null ? SelectedEntry : throw new InvalidOperationException();
    private string ChildPath(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name is "." or ".." || name.Length > 255 || name.IndexOfAny(['/', '\\']) >= 0 || name.Any(char.IsControl))
            throw new ArgumentException();
        return _listedPath == "/" ? "/" + name : _listedPath + "/" + name;
    }

    private async Task RunAsync(Func<CancellationToken, Task> operation, string busyKey = "SftpWorking")
    {
        if (Busy || _disposed) return;
        using var cancellation = new CancellationTokenSource();
        _operation = cancellation; _operationFinished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Busy = true; Status = L[busyKey];
        try { await operation(cancellation.Token); Status = L["SftpReady"]; }
        catch (OperationCanceledException) { Status = L["SftpCancelled"]; }
        catch (UnauthorizedAccessException) { Status = L["SftpDenied"]; }
        catch (HostKeyChangedException) { Status = L["SftpHostChanged"]; }
        catch { Status = L["SftpFailed"]; }
        finally
        {
            _operation = null; Busy = false;
            _operationFinished.TrySetResult();
        }
    }

    private void NotifyAvailability()
    {
        foreach (var property in new[] { nameof(Idle), nameof(CanConnect), nameof(CanBrowse), nameof(CanMutate), nameof(CanUseSelection), nameof(CanDownload), nameof(CanOpen), nameof(CanUp) })
            OnPropertyChanged(property);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true; Cancel();
        if (_operationFinished is { Task.IsCompleted: false }) await _operationFinished.Task;
        if (_session is not null) { await _session.DisposeAsync(); _session = null; }
        ClearSecrets?.Invoke(); ReadSecrets = null; ClearSecrets = null; RequestOneTimeCode = null; _initialOtp = null;
        Entries.Clear(); NotifyAvailability();
    }
}
