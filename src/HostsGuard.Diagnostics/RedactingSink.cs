using HostsGuard.Core;
using Serilog.Core;
using Serilog.Events;
using Serilog.Parsing;

namespace HostsGuard.Diagnostics;

/// <summary>
/// A Serilog sink decorator that runs every event's rendered message and scalar
/// property values through <see cref="Redaction"/> before forwarding to the inner
/// sink. This is the enforcement boundary: secrets, URLs, public IPs, domains and
/// filesystem paths cannot reach a file/EventLog sink even if a caller logs them.
/// </summary>
public sealed class RedactingSink : ILogEventSink, IDisposable
{
    private readonly ILogEventSink _inner;

    public RedactingSink(ILogEventSink inner) => _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    public void Emit(LogEvent logEvent)
    {
        ArgumentNullException.ThrowIfNull(logEvent);

        // Redact scalar string property values by name.
        var props = new List<LogEventProperty>();
        foreach (var kv in logEvent.Properties)
        {
            props.Add(new LogEventProperty(kv.Key, Redact(kv.Key, kv.Value)));
        }

        // Redact the fully rendered message and carry it as a single literal token
        // (so any secret embedded directly in a template literal is scrubbed too).
        var rendered = Redaction.RedactText(logEvent.RenderMessage());
        var template = new MessageTemplate(new MessageTemplateToken[] { new TextToken(rendered) });

        // The exception is the last un-redacted egress: a file/EventLog sink renders
        // it via ToString(), which can carry a credentialed URL, a path, or a public
        // IP in its message/inner-exception. Wrap it so every rendering is scrubbed.
        var exception = logEvent.Exception is null ? null : new RedactedException(logEvent.Exception);

        var redacted = new LogEvent(
            logEvent.Timestamp,
            logEvent.Level,
            exception,
            template,
            props,
            // Rebuild must not drop the W3C correlation ids (NET-180) — they are
            // opaque hex, never sensitive, and the whole point of the trace.
            logEvent.TraceId ?? default,
            logEvent.SpanId ?? default);

        _inner.Emit(redacted);
    }

    private static LogEventPropertyValue Redact(string name, LogEventPropertyValue value)
    {
        switch (value)
        {
            case ScalarValue { Value: string s }:
                return new ScalarValue(Redaction.RedactScalar(name, s));
            case SequenceValue seq:
                return new SequenceValue(seq.Elements.Select(e => Redact(name, e)));
            case StructureValue sv:
                return new StructureValue(sv.Properties.Select(p => new LogEventProperty(p.Name, Redact(p.Name, p.Value))), sv.TypeTag);
            case DictionaryValue dv:
                return new DictionaryValue(dv.Elements.Select(kv =>
                    new KeyValuePair<ScalarValue, LogEventPropertyValue>(kv.Key, Redact(kv.Key.Value?.ToString() ?? string.Empty, kv.Value))));
            default:
                return value;
        }
    }

    public void Dispose() => (_inner as IDisposable)?.Dispose();

    /// <summary>
    /// Carries a fully-redacted rendering of a real exception. Serilog's file and
    /// EventLog sinks format exceptions through <see cref="Exception.ToString"/> and
    /// read <see cref="Exception.Message"/>; both are pre-scrubbed here so no secret,
    /// URL, path, or public IP inside an exception can reach a persistent sink.
    /// </summary>
    private sealed class RedactedException : Exception
    {
        private readonly string _redacted;

        public RedactedException(Exception inner)
            : base(Redaction.RedactText(inner.Message)) =>
            _redacted = Redaction.RedactText(inner.ToString());

        public override string ToString() => _redacted;

        // Never surface the original stack/inner separately — the redacted
        // ToString() above already includes them, scrubbed.
        public override string? StackTrace => null;
    }
}
