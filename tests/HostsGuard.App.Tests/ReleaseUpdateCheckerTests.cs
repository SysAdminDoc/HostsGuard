using System.Net;
using System.Net.Http;
using System.Text;
using System.Globalization;
using FluentAssertions;
using HostsGuard.App.Services;

namespace HostsGuard.App.Tests;

public sealed class ReleaseUpdateCheckerTests
{
    [Fact]
    public async Task CheckAsync_reports_newer_latest_release_with_asset_hash()
    {
        var handler = new StaticHandler(_ => Json("""
            {
              "tag_name": "v0.12.16",
              "published_at": "2026-07-07T12:00:00Z",
              "assets": [
                {
                  "name": "HostsGuard-v0.12.16-dotnet-Setup.exe",
                  "size": 12582912,
                  "digest": "sha256:abc123",
                  "browser_download_url": "https://github.com/SysAdminDoc/HostsGuard/releases/download/v0.12.16/HostsGuard-v0.12.16-dotnet-Setup.exe"
                }
              ]
            }
            """));
        using var http = new HttpClient(handler);
        var checker = new ReleaseUpdateChecker(
            http, TimeSpan.FromSeconds(1), new Uri("https://example.invalid/latest"));

        var result = await checker.CheckAsync("0.12.15");

        result.State.Should().Be(ReleaseUpdateState.UpdateAvailable);
        result.LatestVersion.Should().Be("v0.12.16");
        result.Message.Should().Contain("Update available")
            .And.Contain("v0.12.16")
            .And.Contain("2026")
            .And.Contain("HostsGuard-v0.12.16-dotnet-Setup.exe")
            .And.Contain("sha256:abc123")
            .And.Contain("No auto-install");
        handler.UserAgent.Should().Be("HostsGuard/0.12.15");
        handler.Accept.Should().Contain("application/vnd.github+json");
    }

    [Fact]
    public async Task CheckAsync_reports_up_to_date_when_versions_match()
    {
        var handler = new StaticHandler(_ => Json("""
            {
              "tag_name": "v0.12.16",
              "published_at": "2026-07-07T12:00:00Z",
              "assets": []
            }
            """));
        using var http = new HttpClient(handler);
        var checker = new ReleaseUpdateChecker(
            http, TimeSpan.FromSeconds(1), new Uri("https://example.invalid/latest"));

        var result = await checker.CheckAsync("0.12.16");

        result.State.Should().Be(ReleaseUpdateState.UpToDate);
        result.Message.Should().Contain("up to date").And.Contain("No release assets listed");
    }

    [Fact]
    public async Task CheckAsync_turns_transport_failures_into_status_text()
    {
        var handler = new StaticHandler(_ => throw new HttpRequestException("offline"));
        using var http = new HttpClient(handler);
        var checker = new ReleaseUpdateChecker(
            http, TimeSpan.FromSeconds(1), new Uri("https://example.invalid/latest"));

        var result = await checker.CheckAsync("0.12.15");

        result.State.Should().Be(ReleaseUpdateState.Unavailable);
        result.Message.Should().Be("Update check failed: GitHub request failed: offline");
    }

    [Theory]
    [InlineData("es-ES", "Actualización disponible", "2 archivos")]
    [InlineData("de-DE", "Update verfügbar", "2 Dateien")]
    [InlineData("fr-FR", "Mise à jour disponible", "2 fichiers")]
    public async Task CheckAsync_localizes_interpolation_plural_and_published_date(
        string cultureName,
        string expectedHeading,
        string expectedPlural)
    {
        var handler = new StaticHandler(_ => Json(ReleaseWithTwoAssets));
        using var http = new HttpClient(handler);
        var checker = new ReleaseUpdateChecker(
            http, TimeSpan.FromSeconds(1), new Uri("https://example.invalid/latest"));
        var culture = CultureInfo.GetCultureInfo(cultureName);
        var originalCulture = CultureInfo.CurrentCulture;
        var originalUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = culture;
            CultureInfo.CurrentUICulture = culture;

            var result = await checker.CheckAsync("0.12.15");

            result.Message.Should().Contain(expectedHeading)
                .And.Contain(expectedPlural)
                .And.Contain(new DateTimeOffset(2026, 7, 7, 12, 0, 0, TimeSpan.Zero).ToString("d", culture))
                .And.Contain("v0.12.16")
                .And.Contain("sha256:abc123");
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
            CultureInfo.CurrentUICulture = originalUiCulture;
        }
    }

    [Fact]
    public async Task Pseudo_locale_preserves_runtime_values_across_nested_release_messages()
    {
        var handler = new StaticHandler(_ => Json(ReleaseWithTwoAssets));
        using var http = new HttpClient(handler);
        var checker = new ReleaseUpdateChecker(
            http, TimeSpan.FromSeconds(1), new Uri("https://example.invalid/latest"));
        var originalCulture = CultureInfo.CurrentCulture;
        var originalUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("en-US");
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("qps-ploc");

            var result = await checker.CheckAsync("0.12.15");

            result.Message.Should().StartWith("[!! ")
                .And.Contain("v0.12.16")
                .And.Contain("7/7/2026")
                .And.Contain("2")
                .And.Contain("sha256:abc123")
                .And.Contain("ásséts");
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
            CultureInfo.CurrentUICulture = originalUiCulture;
        }
    }

    private const string ReleaseWithTwoAssets = """
        {
          "tag_name": "v0.12.16",
          "published_at": "2026-07-07T12:00:00Z",
          "assets": [
            {
              "name": "HostsGuard-v0.12.16-dotnet-Setup.exe",
              "size": 12582912,
              "digest": "sha256:abc123"
            },
            {
              "name": "HostsGuard-v0.12.16-portable.zip",
              "size": 2048,
              "digest": "sha256:def456"
            }
          ]
        }
        """;

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };

    private sealed class StaticHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public string? UserAgent { get; private set; }

        public string? Accept { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            UserAgent = request.Headers.UserAgent.ToString();
            Accept = request.Headers.Accept.ToString();
            return Task.FromResult(respond(request));
        }
    }
}
