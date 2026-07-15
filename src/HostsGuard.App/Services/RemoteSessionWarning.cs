using System.Globalization;
using Grpc.Core;
using HostsGuard.Contracts;

namespace HostsGuard.App.Services;

/// <summary>Builds localized, just-in-time RDP lockout warnings for restrictive changes.</summary>
public static class RemoteSessionWarning
{
    public static async Task<string> DescribeAsync(HostsServiceClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        try
        {
            var status = await client.Diagnostics.GetStatusAsync(new Empty());
            return Describe(status);
        }
        catch (RpcException ex)
        {
            return I18n.T(
                "RemoteSession_UnavailableWarning",
                "Remote Desktop session state is unavailable ({0}); this change may disconnect a remote operator.",
                ex.StatusCode.ToString());
        }
    }

    internal static string Describe(ServiceStatus status)
    {
        ArgumentNullException.ThrowIfNull(status);
        if (!status.RemoteSessionObservationAvailable)
        {
            var error = string.IsNullOrWhiteSpace(status.RemoteSessionObservationError)
                ? I18n.T("RemoteSession_NotReported", "not reported")
                : status.RemoteSessionObservationError;
            return I18n.T(
                "RemoteSession_UnavailableWarning",
                "Remote Desktop session state is unavailable ({0}); this change may disconnect a remote operator.",
                error);
        }

        var active = status.RemoteSessions.Where(session => session.Active).ToArray();
        if (active.Length == 0)
        {
            return string.Empty;
        }

        var evidence = string.Join(", ", active.Take(3).Select(session =>
        {
            var source = session.SourceAddress.Length != 0
                ? session.SourceAddress
                : session.ClientName.Length != 0
                    ? session.ClientName
                    : I18n.T("RemoteSession_SourceUnknown", "source unavailable");
            return I18n.T(
                "RemoteSession_Evidence",
                "session {0} from {1}",
                session.SessionId.ToString(CultureInfo.InvariantCulture),
                source);
        }));
        if (active.Length > 3)
        {
            evidence += I18n.T(
                "RemoteSession_MoreEvidence",
                " and {0} more",
                (active.Length - 3).ToString(CultureInfo.InvariantCulture));
        }

        return I18n.T(
            "RemoteSession_ActiveWarning",
            "An active Remote Desktop session may be disconnected: {0}. Continue only if you can reconnect locally.",
            evidence);
    }

    public static string AppendTo(string message, string warning)
        => warning.Length == 0 ? message : message + Environment.NewLine + Environment.NewLine + warning;
}
