using Grpc.Core;
using HostsGuard.Contracts;

namespace HostsGuard.Service;

/// <summary>Creates, verifies, previews, and stages coherent local recovery points.</summary>
public sealed class RecoveryServiceImpl : Recovery.RecoveryBase
{
    private readonly ServiceState _state;

    public RecoveryServiceImpl(ServiceState state) => _state = state;

    public override Task<FullStateSnapshot> CreateFullStateSnapshot(Empty request, ServerCallContext context)
    {
        try
        {
            var info = _state.Snapshots.Create();
            _state.Db.LogEvent("recovery", "snapshot_created", details: info.Id, reason: "operator");
            return Task.FromResult(ToContract(info));
        }
        catch (Exception ex) when (IsExpected(ex))
        {
            throw RpcFailure(StatusCode.Internal, "snapshot_create_failed", ex.Message);
        }
    }

    public override Task<FullStateSnapshotList> ListFullStateSnapshots(Empty request, ServerCallContext context)
    {
        var result = new FullStateSnapshotList();
        result.Snapshots.AddRange(_state.Snapshots.List().Select(ToContract));
        return Task.FromResult(result);
    }

    public override Task<FullStateRestorePreview> PreviewFullStateRestore(
        FullStateSnapshotRef request,
        ServerCallContext context)
    {
        try
        {
            var preview = _state.Snapshots.Preview(request.SnapshotId);
            var result = new FullStateRestorePreview
            {
                Ok = true,
                Message = preview.Summary,
                SnapshotId = preview.Snapshot.Id,
                Sha256 = preview.Snapshot.Sha256,
                AppVersion = preview.Snapshot.AppVersion,
                SchemaVersion = preview.Snapshot.DatabaseSchemaVersion,
            };
            result.Changes.AddRange(preview.Changes.Select(change => $"{change.Component}: {change.ChangeKind}"));
            return Task.FromResult(result);
        }
        catch (Exception ex) when (IsExpected(ex))
        {
            return Task.FromResult(new FullStateRestorePreview
            {
                Ok = false,
                Message = ex.Message,
                ErrorCode = "hostsguard.error.v1/snapshot_invalid",
                SnapshotId = request.SnapshotId,
            });
        }
    }

    public override Task<Ack> RestoreFullStateSnapshot(FullStateRestoreRequest request, ServerCallContext context)
    {
        if (!request.CreatePreRestore)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "A pre-restore recovery point is required.",
                ErrorCode = "hostsguard.error.v1/pre_restore_required",
            });
        }

        try
        {
            var info = _state.Snapshots.StageForStartup(request.SnapshotId, request.ExpectedSha256);
            _state.Db.LogEvent("recovery", "snapshot_restore_staged", details: info.Id, reason: "operator");
            return Task.FromResult(new Ack
            {
                Ok = true,
                Message = $"Verified snapshot {info.Id} is staged. Restart HostsGuardSvc to apply it; startup creates a pre-restore snapshot and rolls back automatically if validation fails.",
            });
        }
        catch (Exception ex) when (IsExpected(ex))
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = ex.Message,
                ErrorCode = "hostsguard.error.v1/snapshot_restore_refused",
            });
        }
    }

    private static FullStateSnapshot ToContract(StateSnapshotInfo info)
    {
        var result = new FullStateSnapshot
        {
            SnapshotId = info.Id,
            Created = info.CreatedUtc.ToString("O"),
            AppVersion = info.AppVersion,
            SchemaVersion = info.DatabaseSchemaVersion,
            Sha256 = info.Sha256,
            SizeBytes = info.SizeBytes,
            Verified = info.Verified,
        };
        result.Components.AddRange(info.Components);
        return result;
    }

    private static bool IsExpected(Exception ex) =>
        ex is StateSnapshotException or IOException or UnauthorizedAccessException or InvalidOperationException;

    private static RpcException RpcFailure(StatusCode status, string code, string message) =>
        new(new Status(status, message), new Metadata { { "x-hostsguard-error", $"hostsguard.error.v1/{code}" } });
}
