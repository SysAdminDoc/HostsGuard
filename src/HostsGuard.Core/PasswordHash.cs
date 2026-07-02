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
    public const int Iterations = 210_000; // OWASP 2023 PBKDF2-SHA256 floor
    private const int SaltBytes = 16;
    private const int HashBytes = 32;
    private const string Prefix = "pbkdf2_sha256";

    /// <summary>Hash a password with a fresh random salt.</summary>
    public static string Hash(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Derive(password, salt, Iterations);
        return $"{Prefix}${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    /// <summary>Verify a candidate password against an encoded hash (constant-time).</summary>
    public static bool Verify(string password, string? encoded)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(encoded))
        {
            return false;
        }

        var parts = encoded.Split('$');
        if (parts.Length != 4 || parts[0] != Prefix || !int.TryParse(parts[1], out var iterations) || iterations < 1)
        {
            return false;
        }

        byte[] salt, expected;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        var actual = Derive(password, salt, iterations, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static byte[] Derive(string password, byte[] salt, int iterations, int length = HashBytes) =>
        Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, length);
}
