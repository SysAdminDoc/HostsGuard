using FluentAssertions;

namespace HostsGuard.Windows.Tests;

public sealed class RemoteSessionSourceTests
{
    [Fact]
    public void Session_evidence_removes_control_and_bidi_format_characters()
    {
        RemoteSessionText.Clean("  client\0\u202E-name\r\n  ", 64, "fallback")
            .Should().Be("client-name");
        RemoteSessionText.Clean("\0\r\n", 64, "fallback").Should().Be("fallback");
        RemoteSessionText.Clean(new string('a', 100), 16, "fallback").Should().HaveLength(16);
    }

    [Theory]
    [InlineData((int)WindowsRemoteSessionSource.WtsConnectState.Active, "active")]
    [InlineData((int)WindowsRemoteSessionSource.WtsConnectState.Disconnected, "disconnected")]
    [InlineData((int)WindowsRemoteSessionSource.WtsConnectState.ConnectQuery, "connect-query")]
    public void Wts_states_use_stable_contract_names(int state, string expected)
        => WindowsRemoteSessionSource.StateName((WindowsRemoteSessionSource.WtsConnectState)state)
            .Should().Be(expected);

    [Fact]
    public void Live_wts_probe_returns_a_typed_snapshot_without_mutation()
    {
        var snapshot = new WindowsRemoteSessionSource().Snapshot();

        snapshot.CheckedAtUtc.Kind.Should().Be(DateTimeKind.Utc);
        if (snapshot.Available)
        {
            snapshot.ErrorCode.Should().BeEmpty();
            snapshot.Sessions.Should().OnlyContain(session =>
                session.State.Length != 0 && session.ClientName.Length <= 64);
        }
        else
        {
            snapshot.ErrorCode.Should().BeOneOf("wts_enumeration_failed", "wts_api_unavailable");
            snapshot.Sessions.Should().BeEmpty();
        }
    }
}
