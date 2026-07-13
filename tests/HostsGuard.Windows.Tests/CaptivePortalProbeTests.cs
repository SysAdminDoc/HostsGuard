using System.Net;
using FluentAssertions;
using HostsGuard.Windows;

namespace HostsGuard.Windows.Tests;

public sealed class CaptivePortalProbeTests
{
    [Fact]
    public async Task Expected_ncsi_response_is_clear()
    {
        using var probe = Create(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(WindowsNcsiCaptivePortalProbe.ExpectedBody),
        });

        var result = await probe.CheckAsync(CancellationToken.None);

        result.State.Should().Be(CaptivePortalState.Clear);
        result.HttpStatus.Should().Be(200);
        result.Redirected.Should().BeFalse();
    }

    [Fact]
    public async Task Redirect_is_reported_without_following_or_exposing_path()
    {
        var calls = 0;
        using var probe = Create(_ =>
        {
            calls++;
            var response = new HttpResponseMessage(HttpStatusCode.Redirect);
            response.Headers.Location = new Uri("http://login.hotspot.example/session?token=secret");
            return response;
        });

        var result = await probe.CheckAsync(CancellationToken.None);

        result.State.Should().Be(CaptivePortalState.Suspected);
        result.Redirected.Should().BeTrue();
        result.ObservedHost.Should().Be("login.hotspot.example");
        result.Detail.Should().NotContain("session").And.NotContain("secret");
        calls.Should().Be(1);
    }

    [Fact]
    public async Task Unexpected_success_body_is_suspected()
    {
        using var probe = Create(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("Sign in to continue"),
        });

        var result = await probe.CheckAsync(CancellationToken.None);

        result.State.Should().Be(CaptivePortalState.Suspected);
        result.Detail.Should().Contain("unexpected content");
    }

    [Fact]
    public async Task No_available_network_skips_http_and_is_offline()
    {
        var called = false;
        using var client = new HttpClient(new StubHandler(_ =>
        {
            called = true;
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));
        using var probe = new WindowsNcsiCaptivePortalProbe(client, () => false);

        var result = await probe.CheckAsync(CancellationToken.None);

        result.State.Should().Be(CaptivePortalState.Offline);
        called.Should().BeFalse();
    }

    private static WindowsNcsiCaptivePortalProbe Create(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        var client = new HttpClient(new StubHandler(respond));
        return new WindowsNcsiCaptivePortalProbe(client, () => true, ownsClient: true);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
