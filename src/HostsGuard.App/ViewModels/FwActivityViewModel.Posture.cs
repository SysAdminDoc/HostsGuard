using Grpc.Core;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.ViewModels;

public sealed partial class FwActivityViewModel
{
    // ─── Modes: lockdown (service posture) + learning/observe (config) ───────

    /// <summary>Pull the current default-outbound posture from the service.</summary>
    public async Task LoadPostureAsync()
    {
        await RunServiceActionAsync("Load firewall posture", s => PostureText = s, async () =>
        {
            var posture = await _client.Firewall.GetPostureAsync(new Empty());
            _suppressPostureWrite = true;
            try
            {
                Lockdown = posture.Available && posture.Lockdown;
            }
            finally
            {
                _suppressPostureWrite = false;
            }

            PostureText = !posture.Available
                ? "Firewall posture unavailable"
                : string.Join("  ", posture.Profiles.Select(p =>
                    $"{p.Name}: {(p.Enabled ? "on" : "OFF")}/{(p.OutboundBlock ? "block" : "allow")}"));
        });
    }

    public async Task LoadFlowTeardownAsync()
    {
        await RunServiceActionAsync("Load TCP teardown mode", s => FlowTeardownText = s, async () =>
        {
            var status = await _client.Firewall.GetFlowTeardownAsync(new Empty());
            _suppressFlowTeardownWrite = true;
            try
            {
                FlowTeardownEnabled = status.Enabled;
            }
            finally
            {
                _suppressFlowTeardownWrite = false;
            }

            FlowTeardownText = status.Available
                ? $"TCP teardown: {(status.Enabled ? "on" : "off")} ({status.Limit})"
                : "TCP teardown unavailable";
        });
    }

    partial void OnFlowTeardownEnabledChanged(bool value)
    {
        if (!_suppressFlowTeardownWrite)
        {
            _ = ApplyFlowTeardownAsync(value);
        }
    }

    private async Task ApplyFlowTeardownAsync(bool enabled)
    {
        try
        {
            var ack = await _client.Firewall.SetFlowTeardownAsync(new FlowTeardownRequest { Enabled = enabled });
            SetOperatorStatus(ack.Message);
            if (!ack.Ok)
            {
                _suppressFlowTeardownWrite = true;
                FlowTeardownEnabled = !enabled;
                _suppressFlowTeardownWrite = false;
            }

            await LoadFlowTeardownAsync();
        }
        catch (Exception ex) when (ex is RpcException || ServiceErrors.IsConnectivity(ex))
        {
            SetOperatorStatus(ServiceErrors.DescribeActionFailure("Apply TCP teardown mode", ex));
            _suppressFlowTeardownWrite = true;
            FlowTeardownEnabled = !enabled;
            _suppressFlowTeardownWrite = false;
        }
    }

    partial void OnLockdownChanged(bool value)
    {
        if (_suppressPostureWrite)
        {
            return;
        }

        _ = ApplyLockdownAsync(value);
    }

    private async Task ApplyLockdownAsync(bool enable)
    {
        if (enable && !_confirm.Confirm("Enable lockdown",
            "Block new outbound traffic on every firewall profile unless an allow rule already covers it?"))
        {
            _suppressPostureWrite = true;
            Lockdown = false;
            _suppressPostureWrite = false;
            return;
        }

        try
        {
            var ack = await _client.Firewall.SetDefaultOutboundAsync(new OutboundRequest { Block = enable });
            SetOperatorStatus(ack.Message);
            if (!ack.Ok)
            {
                // Don't pretend: revert the toggle when the policy change failed.
                _suppressPostureWrite = true;
                Lockdown = !enable;
                _suppressPostureWrite = false;
            }

            await LoadPostureAsync();
        }
        catch (Exception ex) when (ex is RpcException || ServiceErrors.IsConnectivity(ex))
        {
            SetOperatorStatus(ServiceErrors.DescribeActionFailure("Apply lockdown posture", ex));
            _suppressPostureWrite = true;
            Lockdown = !enable;
            _suppressPostureWrite = false;
        }
    }

    partial void OnLearningModeChanged(bool value)
    {
        if (!_suppressModeWrite)
        {
            _config?.SaveModes(value, ObserveMode);
        }
    }

    partial void OnObserveModeChanged(bool value)
    {
        if (!_suppressModeWrite)
        {
            _config?.SaveModes(LearningMode, value);
        }
    }
}
