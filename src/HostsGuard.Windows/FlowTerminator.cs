using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HostsGuard.Windows;

public sealed record FlowTuple(
    string Protocol,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string Process = "");

public sealed record FlowTerminationResult(bool Ok, string Message, string ErrorCode = "");

public interface IFlowTerminator
{
    FlowTerminationResult CloseTcp4(FlowTuple flow);
}

/// <summary>Terminates established IPv4 TCP flows with IPHLPAPI SetTcpEntry.</summary>
[SupportedOSPlatform("windows")]
public sealed class FlowTerminator : IFlowTerminator
{
    private const uint DeleteTcb = 12;

    public FlowTerminationResult CloseTcp4(FlowTuple flow)
    {
        ArgumentNullException.ThrowIfNull(flow);
        if (!string.Equals(flow.Protocol, "TCP", StringComparison.OrdinalIgnoreCase))
        {
            return new FlowTerminationResult(false, "only TCP flows can be closed", "hostsguard.error.v1/unsupported_protocol");
        }

        if (!TryParseEndpoint(flow.LocalAddress, flow.LocalPort, out var local, out var localPortError))
        {
            return new FlowTerminationResult(false, localPortError, "hostsguard.error.v1/invalid_local_endpoint");
        }

        if (!TryParseEndpoint(flow.RemoteAddress, flow.RemotePort, out var remote, out var remotePortError))
        {
            return new FlowTerminationResult(false, remotePortError, "hostsguard.error.v1/invalid_remote_endpoint");
        }

        if (local.AddressFamily != AddressFamily.InterNetwork || remote.AddressFamily != AddressFamily.InterNetwork)
        {
            return new FlowTerminationResult(false, "only IPv4 TCP flows can be closed; IPv6 requires a different Windows path", "hostsguard.error.v1/ipv6_unsupported");
        }

        var row = new MIB_TCPROW
        {
            dwState = DeleteTcb,
            dwLocalAddr = AddressToUInt(local),
            dwLocalPort = PortToDword(flow.LocalPort),
            dwRemoteAddr = AddressToUInt(remote),
            dwRemotePort = PortToDword(flow.RemotePort),
        };
        var code = SetTcpEntry(ref row);
        return code == 0
            ? new FlowTerminationResult(true, "closed IPv4 TCP flow")
            : new FlowTerminationResult(false, $"SetTcpEntry failed with code {code}", $"hostsguard.error.v1/set_tcp_entry_{code}");
    }

    private static bool TryParseEndpoint(string address, int port, out IPAddress ip, out string error)
    {
        if (!IPAddress.TryParse(address, out ip!))
        {
            error = $"'{address}' is not an IP address";
            return false;
        }

        if (port is < 1 or > 65535)
        {
            error = $"port {port} is outside 1-65535";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static uint AddressToUInt(IPAddress address) => BitConverter.ToUInt32(address.GetAddressBytes(), 0);

    private static uint PortToDword(int port) => ((uint)(port & 0xFF) << 8) | ((uint)((port >> 8) & 0xFF));

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetTcpEntry(ref MIB_TCPROW row);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }
}
