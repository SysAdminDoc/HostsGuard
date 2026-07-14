using System.Globalization;
using System.Security.Cryptography;

namespace HostsGuard.Core;

/// <summary>
/// Self-describing PBKDF2-SHA256 password hashing for the settings lock
/// (NET-079). Format: <c>pbkdf2_sha256$iterations$salt_b64$hash_b64</c>. Verify
/// is constant-time. Pure and deterministic given salt; the service persists
/// only the encoded string, never the plaintext.
/// </summary>
public static class PasswordHash
{
    /// <summary>Work factor used for newly-created settings-lock hashes.</summary>
    public const int Iterations = 600_000;

    /// <summary>Oldest work factor accepted for an existing settings-lock hash.</summary>
    public const int MinimumAcceptedIterations = 210_000;

    /// <summary>Largest work factor accepted from persisted or imported state.</summary>
    public const int MaximumAcceptedIterations = Iterations;

    private const int SaltBytes = 16;
    private const int HashBytes = 32;
    private const string Prefix = "pbkdf2_sha256";
    private const int SaltBase64Length = 24;
    private const int HashBase64Length = 44;
    private const int EncodedLength = 90;

    /// <summary>Hash a password with a fresh random salt.</summary>
    public static string Hash(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Derive(password, salt, Iterations);
        return $"{Prefix}${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    /// <summary>Verify a candidate password against an encoded hash (constant-time).</summary>
    public static bool Verify(string password, string? encoded) =>
        Verify(password, encoded, out _);

    /// <summary>
    /// Verify a candidate and report whether a successful match should be
    /// replaced with the current work factor.
    /// </summary>
    public static bool Verify(string password, string? encoded, out bool needsRehash)
    {
        needsRehash = false;
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(encoded))
        {
            return false;
        }

        if (!TryParse(encoded, out var iterations, out var salt, out var expected))
        {
            return false;
        }

        var actual = Derive(password, salt, iterations);
        var verified = CryptographicOperations.FixedTimeEquals(actual, expected);
        if (verified)
        {
            needsRehash = iterations != Iterations;
        }

        return verified;
    }

    /// <summary>
    /// Validate an encoded hash without performing PBKDF2 work. Only the known
    /// format, bounded work factor, 16-byte salt, and 32-byte output are accepted.
    /// </summary>
    public static bool IsValidEncoding(string? encoded) =>
        !string.IsNullOrEmpty(encoded) && TryParse(encoded, out _, out _, out _);

    private static bool TryParse(
        string encoded,
        out int iterations,
        out byte[] salt,
        out byte[] expected)
    {
        iterations = 0;
        salt = Array.Empty<byte>();
        expected = Array.Empty<byte>();

        // Every accepted iteration count has six digits. Reject oversized input
        // before Split/Base64 decoding so attacker-controlled policy strings
        // cannot amplify allocations.
        if (encoded.Length != EncodedLength)
        {
            return false;
        }

        var parts = encoded.Split('$');
        if (parts.Length != 4 ||
            !string.Equals(parts[0], Prefix, StringComparison.Ordinal) ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out iterations) ||
            iterations < MinimumAcceptedIterations ||
            iterations > MaximumAcceptedIterations ||
            parts[2].Length != SaltBase64Length ||
            parts[3].Length != HashBase64Length)
        {
            return false;
        }

        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
            return salt.Length == SaltBytes && expected.Length == HashBytes;
        }
        catch (FormatException)
        {
            salt = Array.Empty<byte>();
            expected = Array.Empty<byte>();
            return false;
        }
    }

    private static byte[] Derive(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, HashBytes);
}
