using System.Runtime.Versioning;
using Grpc.Core;
using HostsGuard.Contracts;

namespace HostsGuard.Service;

/// <summary>
/// Server-streaming live feeds. Each watcher subscribes to the in-process
/// EventBus; the stream ends when the client disconnects. The engines (ETW DNS,
/// connection monitor, temp-allow scheduler) publish onto the bus.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class MonitoringServiceImpl : Monitoring.MonitoringBase
{
    private readonly ServiceState _state;

    public MonitoringServiceImpl(ServiceState state) => _state = state;

    public override Task WatchDns(Empty request, IServerStreamWriter<DnsEvent> responseStream, ServerCallContext context)
        => Pump(responseStream, context);

    public override Task WatchConnections(Empty request, IServerStreamWriter<ConnectionEvent> responseStream, ServerCallContext context)
        => Pump(responseStream, context);

    public override Task WatchEvents(Empty request, IServerStreamWriter<ActivityEvent> responseStream, ServerCallContext context)
        => Pump(responseStream, context);

    private async Task Pump<T>(IServerStreamWriter<T> stream, ServerCallContext context)
    {
        using var sub = _state.Bus.Subscribe<T>();
        try
        {
            await foreach (var item in sub.Reader.ReadAllAsync(context.CancellationToken))
            {
                await stream.WriteAsync(item, context.CancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Client went away — normal stream termination.
        }
    }
}
