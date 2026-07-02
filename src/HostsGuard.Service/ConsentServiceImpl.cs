using System.Runtime.Versioning;
using Grpc.Core;
using HostsGuard.Contracts;

namespace HostsGuard.Service;

/// <summary>Exposes the consent broker (mode, decisions, history) over the pipe.</summary>
[SupportedOSPlatform("windows")]
public sealed class ConsentServiceImpl : Consent.ConsentBase
{
    private readonly ServiceState _state;

    public ConsentServiceImpl(ServiceState state) => _state = state;

    public override async Task WatchDecisions(
        Empty request, IServerStreamWriter<ConnectionDecisionRequest> responseStream, ServerCallContext context)
    {
        using var sub = _state.Bus.Subscribe<ConnectionDecisionRequest>();
        try
        {
            await foreach (var item in sub.Reader.ReadAllAsync(context.CancellationToken))
            {
                await responseStream.WriteAsync(item, context.CancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Client went away — normal stream termination.
        }
    }

    public override Task<Ack> Decide(ConnectionDecision request, ServerCallContext context)
        => Task.FromResult(_state.Consent.Decide(request));

    public override Task<FilteringMode> GetMode(Empty request, ServerCallContext context)
        => Task.FromResult(new FilteringMode
        {
            Mode = _state.Consent.Mode,
            DetectionArmed = _state.Consent.DetectionArmed,
        });

    public override Task<Ack> SetMode(FilteringMode request, ServerCallContext context)
        => Task.FromResult(_state.Consent.SetMode(request.Mode));

    public override Task<DecisionHistory> GetDecisionHistory(HistoryRequest request, ServerCallContext context)
        => Task.FromResult(_state.Consent.History(request.Limit));
}
