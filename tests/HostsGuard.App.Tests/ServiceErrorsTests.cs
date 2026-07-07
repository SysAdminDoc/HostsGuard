using System.IO;
using FluentAssertions;
using Grpc.Core;
using HostsGuard.App.Services;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>
/// The global error dialog must distinguish "service unreachable" from
/// "service handler failed" — telling the user to restart a healthy service
/// sends them down the wrong path.
/// </summary>
public sealed class ServiceErrorsTests
{
    private static RpcException Rpc(StatusCode code, string detail = "")
        => new(new Status(code, detail));

    [Fact]
    public void Handler_exceptions_are_not_connectivity()
    {
        ServiceErrors.IsConnectivity(Rpc(StatusCode.Unknown, "Exception was thrown by handler.")).Should().BeFalse();
        ServiceErrors.IsConnectivity(Rpc(StatusCode.InvalidArgument, "bad input")).Should().BeFalse();
    }

    [Fact]
    public void Transport_failures_are_connectivity()
    {
        ServiceErrors.IsConnectivity(Rpc(StatusCode.Unavailable)).Should().BeTrue();
        ServiceErrors.IsConnectivity(Rpc(StatusCode.DeadlineExceeded)).Should().BeTrue();
        ServiceErrors.IsConnectivity(new IOException("pipe broken")).Should().BeTrue();
        ServiceErrors.IsConnectivity(new TimeoutException()).Should().BeTrue();
        ServiceErrors.IsConnectivity(new InvalidOperationException("wrapped", new IOException())).Should().BeTrue();
    }

    [Fact]
    public void Describe_surfaces_the_service_detail_when_it_is_meaningful()
    {
        ServiceErrors.Describe(Rpc(StatusCode.Unknown, "the hosts file is locked"))
            .Should().Contain("the hosts file is locked");

        // The generic gRPC placeholder gets replaced with actionable guidance.
        ServiceErrors.Describe(Rpc(StatusCode.Unknown, "Exception was thrown by handler."))
            .Should().Contain("still running").And.NotContain("thrown by handler");
    }

    [Fact]
    public void DescribeActionFailure_keeps_the_failed_action_in_the_status_line()
    {
        ServiceErrors.DescribeActionFailure("Block domain", Rpc(StatusCode.Unavailable))
            .Should().Be("Block domain failed — service unavailable; reconnect from the status bar");

        ServiceErrors.DescribeActionFailure("Import policy", Rpc(StatusCode.Unknown, "bad JSON"))
            .Should().Contain("Import policy failed").And.Contain("bad JSON");
    }

    [Fact]
    public async Task ServiceActionGuard_turns_service_failures_into_status_text()
    {
        var status = string.Empty;

        await ServiceActionGuard.RunAsync(
            "Refresh blocklists",
            value => status = value,
            () => Task.FromException(new IOException("pipe broken")));

        status.Should().Be("Refresh blocklists failed — service unavailable; reconnect from the status bar");
    }

    [Fact]
    public async Task ServiceActionGuard_does_not_hide_non_service_failures()
    {
        var act = () => ServiceActionGuard.RunAsync(
            "Refresh blocklists",
            _ => { },
            () => Task.FromException(new InvalidOperationException("bad view state")));

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("bad view state");
    }
}
