using System.Security.Cryptography;
using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>NET-079: PBKDF2 password hashing for the settings lock.</summary>
public class PasswordHashTests
{
    [Fact]
    public void Hash_is_self_describing_and_salted()
    {
        var a = PasswordHash.Hash("correct horse");
        var b = PasswordHash.Hash("correct horse");

        a.Should().StartWith("pbkdf2_sha256$");
        a.Should().StartWith($"pbkdf2_sha256${PasswordHash.Iterations}$");
        a.Split('$').Should().HaveCount(4);
        a.Should().NotBe(b); // random salt → different encodings
    }

    [Fact]
    public void Verify_accepts_the_right_password_and_rejects_wrong()
    {
        var encoded = PasswordHash.Hash("s3cret!");

        PasswordHash.Verify("s3cret!", encoded).Should().BeTrue();
        PasswordHash.Verify("S3cret!", encoded).Should().BeFalse();
        PasswordHash.Verify("", encoded).Should().BeFalse();
        PasswordHash.Verify("s3cret!", null).Should().BeFalse();
    }

    [Theory]
    [InlineData("not-a-hash")]
    [InlineData("pbkdf2_sha256$abc$salt$hash")]
    [InlineData("pbkdf2_sha256$1000$!!!$!!!")]
    [InlineData("scrypt$600000$MDEyMzQ1Njc4OWFiY2RlZg==$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")]
    [InlineData("pbkdf2_sha256$209999$MDEyMzQ1Njc4OWFiY2RlZg==$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")]
    [InlineData("pbkdf2_sha256$600001$MDEyMzQ1Njc4OWFiY2RlZg==$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")]
    public void Verify_rejects_malformed_encodings(string encoded) =>
        PasswordHash.Verify("anything", encoded).Should().BeFalse();

    [Fact]
    public void Legacy_hash_verifies_and_requests_rehash()
    {
        const string password = "legacy-password";
        var salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            PasswordHash.MinimumAcceptedIterations,
            HashAlgorithmName.SHA256,
            32);
        var encoded = $"pbkdf2_sha256${PasswordHash.MinimumAcceptedIterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";

        PasswordHash.Verify(password, encoded, out var needsRehash).Should().BeTrue();
        needsRehash.Should().BeTrue();
        PasswordHash.IsValidEncoding(encoded).Should().BeTrue();
    }

    [Fact]
    public void Validation_rejects_oversized_salt_and_output_before_derivation()
    {
        var oversized = new string('A', 1024);

        PasswordHash.IsValidEncoding($"pbkdf2_sha256$600000${oversized}$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=").Should().BeFalse();
        PasswordHash.IsValidEncoding($"pbkdf2_sha256$600000$MDEyMzQ1Njc4OWFiY2RlZg==${oversized}").Should().BeFalse();
    }
}
