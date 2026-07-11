using Serilog;
using Serilog.Configuration;
using Serilog.Core;
using Serilog.Events;

namespace HostsGuard.Diagnostics;

/// <summary>Serilog wiring for HostsGuard with mandatory redaction on every sink.</summary>
public static class Logging
{
    /// <summary>
    /// Wrap a sink so all events pass through <see cref="RedactingSink"/> first.
    /// Use in place of a direct sink registration to guarantee redaction.
    /// </summary>
    public static LoggerConfiguration RedactedSink(
        this LoggerSinkConfiguration config,
        ILogEventSink inner,
        LogEventLevel restrictedToMinimumLevel = LogEventLevel.Verbose)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(inner);
        return config.Sink(new RedactingSink(inner), restrictedToMinimumLevel);
    }

    /// <summary>
    /// Build the default HostsGuard logger: a rotating, size-capped file sink in
    /// <paramref name="logDirectory"/>, always redacted.
    /// </summary>
    public static Logger CreateFileLogger(string logDirectory, LogEventLevel minimumLevel = LogEventLevel.Information)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logDirectory);
        Directory.CreateDirectory(logDirectory);
        var path = Path.Combine(logDirectory, "hostsguard-.log");

        var fileSink = new LoggerConfiguration()
            .WriteTo.File(
                path,
                rollingInterval: RollingInterval.Day,
                fileSizeLimitBytes: 5_000_000,
                rollOnFileSizeLimit: true,
                retainedFileCountLimit: 5,
                shared: true,
                // NET-180: render the ambient W3C activity so a GUI-initiated RPC
                // and its service-side handling correlate across both log files.
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {TraceId} {Message:lj}{NewLine}{Exception}")
            .CreateLogger();

        return new LoggerConfiguration()
            .MinimumLevel.Is(minimumLevel)
            .WriteTo.RedactedSink(fileSink)
            .CreateLogger();
    }
}
