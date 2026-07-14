using System.Diagnostics;
using FluentAssertions;
using HostsGuard.Diagnostics;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Xunit;

namespace HostsGuard.Diagnostics.Tests;

public class RedactingSinkTests
{
    /// <summary>A sink that captures rendered output for assertions.</summary>
    private sealed class CapturingSink : ILogEventSink
    {
        public List<string> Rendered { get; } = new();
        public List<LogEvent> Events { get; } = new();

        public void Emit(LogEvent logEvent)
        {
            Events.Add(logEvent);
            Rendered.Add(logEvent.RenderMessage());
        }
    }

    private static (ILogger logger, CapturingSink sink) Build()
    {
        var capture = new CapturingSink();
        var logger = new LoggerConfiguration()
            .MinimumLevel.Verbose()
            .WriteTo.RedactedSink(capture)
            .CreateLogger();
        return (logger, capture);
    }

    [Fact]
    public void Secret_in_message_template_never_reaches_sink()
    {
        var (logger, sink) = Build();
        var token = new string('d', 48);
        logger.Information("service token is {token} for session", token);

        var all = string.Join("\n", sink.Rendered) + "\n" + string.Join("\n", sink.Events.SelectMany(e => e.Properties.Values.Select(v => v.ToString())));
        all.Should().NotContain(token);
        all.Should().Contain("<REDACTED_SECRET>");
    }

    [Fact]
    public void Webhook_url_property_is_redacted()
    {
        var (logger, sink) = Build();
        logger.Information("delivering to webhook {webhook_url}", "https://hooks.example.com/x/y");

        var joined = string.Join("\n", sink.Rendered) + "\n" +
                     string.Join("\n", sink.Events.SelectMany(e => e.Properties.Values.Select(v => v.ToString())));
        joined.Should().NotContain("hooks.example.com");
    }

    [Fact]
    public void Public_ip_in_message_is_redacted_private_kept()
    {
        var (logger, sink) = Build();
        logger.Warning("blocked 8.8.8.8 and allowed 192.168.0.9");
        var msg = sink.Rendered[0];
        msg.Should().NotContain("8.8.8.8");
        msg.Should().Contain("192.168.0.9");
    }

    [Fact]
    public void Ordinary_message_passes_through()
    {
        var (logger, sink) = Build();
        logger.Information("blocked count is {count}", 42);
        sink.Rendered[0].Should().Contain("42");
    }

    [Fact]
    public void Exception_message_and_tostring_are_redacted_before_the_sink()
    {
        var (logger, sink) = Build();
        // An exception carrying a credentialed URL and a public IP, as an
        // HttpRequestException/UriFormatException realistically would.
        var inner = new InvalidOperationException("failed calling https://user:s3cr3t@hooks.example.com/deliver from 8.8.8.8");
        logger.Error(inner, "delivery failed");

        var ex = sink.Events.Should().ContainSingle().Subject.Exception;
        ex.Should().NotBeNull();
        var full = ex!.ToString() + "\n" + ex.Message;
        full.Should().NotContain("hooks.example.com");
        full.Should().NotContain("s3cr3t");
        full.Should().NotContain("8.8.8.8");
    }

    [Fact]
    public void Null_exception_stays_null()
    {
        var (logger, sink) = Build();
        logger.Information("no exception here");
        sink.Events.Should().ContainSingle().Which.Exception.Should().BeNull();
    }

    [Fact]
    public void Redaction_preserves_ambient_trace_and_span_ids()
    {
        using var activity = new Activity("redaction-test");
        activity.SetIdFormat(ActivityIdFormat.W3C);
        activity.Start();
        var (logger, sink) = Build();

        logger.Information("blocked {Target}", "example.com");

        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.TraceId?.ToHexString().Should().Be(activity.TraceId.ToHexString());
        logEvent.SpanId?.ToHexString().Should().Be(activity.SpanId.ToHexString());
        (logger as IDisposable)?.Dispose();
    }
}
