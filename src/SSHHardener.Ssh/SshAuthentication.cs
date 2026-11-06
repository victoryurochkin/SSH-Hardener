using Renci.SshNet;
using SSHHardener.Core;

namespace SSHHardener.Ssh;

internal sealed class SshAuthenticationContext(ConnectionInfo connection, PrivateKeyFile? key) : IDisposable
{
    public ConnectionInfo ConnectionInfo { get; } = connection;
    public Exception? ChallengeError { get; set; }
    public void Dispose() => key?.Dispose();
}

internal static class SshAuthentication
{
    internal static SshAuthenticationContext Create(ConnectionOptions options, CancellationToken ct)
    {
        var methods = new List<AuthenticationMethod>();
        PrivateKeyFile? key = null;
        try
        {
            if (!string.IsNullOrWhiteSpace(options.PrivateKeyPath))
            {
                key = KeyService.OpenPrivateKey(options.PrivateKeyPath, options.Passphrase);
                methods.Add(new PrivateKeyAuthenticationMethod(options.Username, key));
            }
            else if (options.Password is not null)
                methods.Add(new PasswordAuthenticationMethod(options.Username, options.Password));
            else throw new ArgumentException("A private key or password is required.");

            KeyboardInteractiveAuthenticationMethod? keyboard = null;
            if (options.OneTimeCodeProvider is not null)
            {
                keyboard = new KeyboardInteractiveAuthenticationMethod(options.Username);
                methods.Add(keyboard);
            }
            var info = new ConnectionInfo(options.Host, options.Port, options.Username, methods.ToArray())
            {
                Timeout = TimeSpan.FromSeconds(keyboard is null ? 20 : 120), RetryAttempts = 3
            };
            SshAlgorithmPolicy.Apply(info);
            var context = new SshAuthenticationContext(info, key);
            var challenges = 0;
            if (keyboard is not null)
                keyboard.AuthenticationPrompt += (_, args) =>
                {
                    try
                    {
                        ct.ThrowIfCancellationRequested();
                        var prompts = args.Prompts.ToArray();
                        if (++challenges > 3 || prompts.Length != 1 || prompts[0].IsEchoed)
                            throw new InvalidOperationException("The server requested an unsupported interactive authentication challenge.");
                        var request = prompts[0].Request;
                        if (request.Length > 256 || !(request.Contains("code", StringComparison.OrdinalIgnoreCase) ||
                            request.Contains("otp", StringComparison.OrdinalIgnoreCase) || request.Contains("token", StringComparison.OrdinalIgnoreCase)))
                            throw new InvalidOperationException("Only a one-time verification code can be supplied to this challenge.");
                        var answer = options.OneTimeCodeProvider!(ct).GetAwaiter().GetResult();
                        if (answer.Length is not (6 or 8) || answer.Any(x => x is < '0' or > '9'))
                            throw new InvalidOperationException("Enter a six-digit authenticator code or an eight-digit recovery code.");
                        prompts[0].Response = answer;
                    }
                    catch (Exception failure)
                    {
                        context.ChallengeError = failure;
                        foreach (var prompt in args.Prompts) prompt.Response = "";
                    }
                };
            return context;
        }
        catch { key?.Dispose(); throw; }
    }
}
