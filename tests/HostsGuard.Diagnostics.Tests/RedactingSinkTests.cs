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
}
