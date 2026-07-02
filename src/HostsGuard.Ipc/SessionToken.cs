using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace HostsGuard.Ipc;

/// <summary>
/// Per-session bearer token for IPC. The elevated service mints a token on start
/// and writes it to an ACL'd handshake file readable only by the current user +
/// Administrators; clients read it and send it as gRPC metadata. Defense-in-depth
/// on top of the pipe ACL. Mirrors the Python HG_TOKEN design.
/// </summary>
public static class SessionToken
{
    public const string MetadataKey = "x-hg-token";

    /// <summary>Generate a 256-bit token as lowercase hex.</summary>
    public static string Generate() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

    /// <summary>Constant-time comparison to avoid token-timing side channels.</summary>
    public static bool ConstantTimeEquals(string? a, string? b)
    {
        if (a is null || b is null)
        {
            return false;
        }

        var ba = System.Text.Encoding.UTF8.GetBytes(a);
        var bb = System.Text.Encoding.UTF8.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(ba, bb);
    }

    /// <summary>
    /// Write the token to a file with a protected ACL: current user +
    /// Administrators full control; when minted by the LocalSystem service,
    /// Authenticated Users additionally get read so the unelevated user-session
    /// UI can complete the handshake (WFCP-000b — the pipe ACL admits them,
    /// this token is what authorizes them).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static void WriteHandshake(string path, string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        File.WriteAllText(path, token);

        var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User
            ?? throw new InvalidOperationException("Cannot determine current user SID.");
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(currentUser, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
        if (identity.IsSystem)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                FileSystemRights.Read,
                AccessControlType.Allow));
        }

        new FileInfo(path).SetAccessControl(security);
    }

    public static string ReadHandshake(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return File.ReadAllText(path).Trim();
    }
}
