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
            ChildInherit = _state.Consent.ChildInherit,
            LearnMinutes = _state.Consent.LearnMinutesRemaining,
        });

    public override Task<Ack> SetChildInherit(ChildInheritRequest request, ServerCallContext context)
        => Task.FromResult(_state.GateWhenLocked() ?? _state.Consent.SetChildInherit(request.Enabled));

    public override Task<Ack> SetMode(FilteringMode request, ServerCallContext context)
        => Task.FromResult(_state.GateWhenLocked() ?? _state.Consent.SetMode(request.Mode, request.LearnMinutes));

    public override Task<DecisionHistory> GetDecisionHistory(HistoryRequest request, ServerCallContext context)
        => Task.FromResult(_state.Consent.History(request.Limit));

    public override Task<BaselineList> GetBaseline(Empty request, ServerCallContext context)
    {
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var list = new BaselineList();
        foreach (var entry in Core.KnownSafeBaseline.Entries)
        {
            list.Items.Add(new BaselineItem
            {
                FileName = entry.FileName,
                Description = entry.Description,
                Present = entry.FileName == "System" || System.IO.File.Exists(System.IO.Path.Combine(system32, entry.FileName)),
            });
        }

        return Task.FromResult(list);
    }

    public override Task<Ack> ApplyBaseline(Empty request, ServerCallContext context)
    {
        var created = _state.Consent.ApplyBaseline();
        return Task.FromResult(new Ack { Ok = true, Message = $"applied {created} known-safe baseline allow rules" });
    }

    public override Task<LearnedList> GetLearned(Empty request, ServerCallContext context)
        => Task.FromResult(_state.Consent.ListLearned());

    public override Task<Ack> ReviewLearned(LearnedReviewRequest request, ServerCallContext context)
        => Task.FromResult(_state.Consent.ReviewLearned(request));
}
