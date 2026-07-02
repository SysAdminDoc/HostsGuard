using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public class RedactionTests
{
    [Fact]
    public void RedactText_scrubs_url()
    {
        var outp = Redaction.RedactText("posting to https://hooks.example.com/abc?secret=1 now");
        outp.Should().NotContain("hooks.example.com");
        outp.Should().Contain("<REDACTED_URL:");
    }

    [Fact]
    public void RedactText_scrubs_public_ip_but_keeps_private()
    {
        Redaction.RedactText("connect 8.8.8.8").Should().Contain("<REDACTED_IP:");
        Redaction.RedactText("lan host 192.168.1.5").Should().Contain("192.168.1.5");
    }

    [Fact]
    public void RedactText_scrubs_domain()
    {
        var outp = Redaction.RedactText("blocked ads.tracker.com today");
        outp.Should().NotContain("ads.tracker.com");
        outp.Should().Contain("<REDACTED_DOMAIN:");
    }

    [Fact]
    public void RedactText_scrubs_long_hex_secret()
    {
        var token = new string('a', 40);
        Redaction.RedactText($"token={token}").Should().Contain("<REDACTED_SECRET>").And.NotContain(token);
    }

    [Theory]
    [InlineData("webhook_url", "https://x.example.com/y")]
    [InlineData("service_token", "deadbeefdeadbeef")]
    [InlineData("api_key", "sk-1234567890")]
    public void RedactScalar_scrubs_by_key_or_value(string key, string value)
    {
        var outp = Redaction.RedactScalar(key, value);
        outp.Should().NotContain(value);
    }

    [Fact]
    public void RedactScalar_program_path_keeps_only_filename()
    {
        Redaction.RedactScalar("program", @"C:\Users\alice\secret app\chrome.exe").Should().Be("chrome.exe");
    }

    [Fact]
    public void RedactScalar_leaves_ordinary_scalars()
    {
        Redaction.RedactScalar("status", "blocked").Should().Be("blocked");
    }

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("1.1.1.1", true)]
    [InlineData("192.168.1.1", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("not-an-ip", false)]
    public void LooksLikePublicIp_classifies(string ip, bool expected) =>
        Redaction.LooksLikePublicIp(ip).Should().Be(expected);
}
