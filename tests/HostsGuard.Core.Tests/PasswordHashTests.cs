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
    public void Verify_rejects_malformed_encodings(string encoded) =>
        PasswordHash.Verify("anything", encoded).Should().BeFalse();
}
