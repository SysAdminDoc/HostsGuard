using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.Contracts;

namespace HostsGuard.App.Tests;

public sealed class RemoteSessionWarningTests
{
    [Fact]
    public void Active_session_warning_carries_bounded_source_evidence()
    {
        var status = new ServiceStatus { RemoteSessionObservationAvailable = true };
        status.RemoteSessions.Add(new RemoteSessionInfo
        {
            SessionId = 12,
            Active = true,
            State = "active",
            ClientName = "OPS-LAPTOP",
            SourceAddress = "198.51.100.20",
        });

        RemoteSessionWarning.Describe(status).Should()
            .Contain("active Remote Desktop session")
            .And.Contain("session 12 from 198.51.100.20")
            .And.Contain("reconnect locally");
    }

    [Fact]
    public void Unavailable_observation_warns_instead_of_claiming_no_session()
    {
        var status = new ServiceStatus
        {
            RemoteSessionObservationAvailable = false,
            RemoteSessionObservationError = "wts_enumeration_failed",
        };

        RemoteSessionWarning.Describe(status).Should()
            .Contain("unavailable")
            .And.Contain("wts_enumeration_failed")
            .And.Contain("may disconnect");
    }

    [Fact]
    public void Available_local_only_state_needs_no_extra_warning()
        => RemoteSessionWarning.Describe(new ServiceStatus
        {
            RemoteSessionObservationAvailable = true,
        }).Should().BeEmpty();
}
