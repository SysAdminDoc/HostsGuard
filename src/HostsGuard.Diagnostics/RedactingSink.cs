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

        var redacted = new LogEvent(
            logEvent.Timestamp,
            logEvent.Level,
            logEvent.Exception,
            template,
            props);

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
}
