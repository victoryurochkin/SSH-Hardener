using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SSHHardener.Core;

namespace SSHHardener.Ssh;

/// <summary>Per-user trust store. Changed identities are rejected before credentials are sent.</summary>
public sealed class KnownHostsStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);
    public KnownHostsStore(string? directory = null)
    {
        var folder = directory ?? AppPaths.DataDirectory;
        Directory.CreateDirectory(folder);
        _path = Path.Combine(folder, "known-hosts.json");
    }

    public async Task VerifyAsync(HostIdentity identity, Func<HostIdentity, Task<bool>> confirm, CancellationToken ct)
    {
        // Do not hold the persistence lock across a user dialog.
        var existing = await ReadAsync(ct).ConfigureAwait(false);
        var endpoint = Endpoint(identity);
        if (existing.TryGetValue(endpoint, out var keys))
        {
            if (!keys.Contains(identity.KeyBase64, StringComparer.Ordinal))
                throw new HostKeyChangedException($"Host key changed for {identity.Host}:{identity.Port}. Verify the server through a trusted console before changing known-hosts.json.");
            if (!await confirm(identity with { IsKnown = true }).ConfigureAwait(false))
                throw new InvalidOperationException("Server identity rejected by connection policy.");
            return;
        }
        if (!await confirm(identity).ConfigureAwait(false))
            throw new InvalidOperationException("Server identity was not approved.");

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var current = await ReadUnsafeAsync(ct).ConfigureAwait(false);
            if (current.TryGetValue(endpoint, out var previous) && !previous.Contains(identity.KeyBase64, StringComparer.Ordinal))
                throw new HostKeyChangedException("Server identity changed during confirmation.");
            current[endpoint] = [identity.KeyBase64];
            await AtomicJson.WriteAsync(_path, current, ct).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }
    private static string Endpoint(HostIdentity identity) => $"[{identity.Host.Trim().ToLowerInvariant()}]:{identity.Port}";
    private async Task<Dictionary<string, string[]>> ReadAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try { return await ReadUnsafeAsync(ct).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }
    private async Task<Dictionary<string, string[]>> ReadUnsafeAsync(CancellationToken ct) =>
        File.Exists(_path) ? JsonSerializer.Deserialize<Dictionary<string, string[]>>(await File.ReadAllTextAsync(_path, ct).ConfigureAwait(false))
            ?? throw new InvalidDataException("Invalid known-hosts file.") : new(StringComparer.Ordinal);
}
public sealed class HostKeyChangedException(string message) : Exception(message);

public static class AppPaths
{
    public static string DataDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SSHHardener");
}
internal static class AtomicJson
{
    public static async Task WriteAsync<T>(string path, T value, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true }), ct).ConfigureAwait(false);
            File.Move(temp, path, true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}

public sealed record ServerProfile(string Name, string Host, int Port, string Username, string? PrivateKeyPath = null);
public sealed class ProfileStore
{
    private readonly string _path;
    public ProfileStore(string? directory = null) => _path = Path.Combine(directory ?? AppPaths.DataDirectory, "profiles.json");
    public async Task<IReadOnlyList<ServerProfile>> LoadAsync(CancellationToken ct = default) => File.Exists(_path)
        ? JsonSerializer.Deserialize<List<ServerProfile>>(await File.ReadAllTextAsync(_path, ct).ConfigureAwait(false)) ?? [] : [];
    public Task SaveAsync(IEnumerable<ServerProfile> profiles, CancellationToken ct = default) => AtomicJson.WriteAsync(_path, profiles.ToArray(), ct);
}

/// <summary>Optional storage for a user-selected secret; not used by profiles by default.</summary>
public sealed class SecretStore
{
    private readonly string _directory;
    public SecretStore(string? directory = null) => _directory = Path.Combine(directory ?? AppPaths.DataDirectory, "secrets");
    public async Task SaveAsync(Guid id, string secret, CancellationToken ct = default)
    {
        Directory.CreateDirectory(_directory);
        var bytes = Encoding.UTF8.GetBytes(secret);
        try
        {
            var encrypted = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
            var path = Path.Combine(_directory, id.ToString("N") + ".dpapi");
            await File.WriteAllBytesAsync(path, encrypted, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public async Task<string> ReadAsync(Guid id, CancellationToken ct = default)
    {
        var encrypted = await File.ReadAllBytesAsync(Path.Combine(_directory, id.ToString("N") + ".dpapi"), ct).ConfigureAwait(false);
        var bytes = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
        try { return Encoding.UTF8.GetString(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public void Delete(Guid id) => File.Delete(Path.Combine(_directory, id.ToString("N") + ".dpapi"));
}
