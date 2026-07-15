using FluentAssertions;
using HostsGuard.App.Services;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class ShellHydrationCoordinatorTests
{
    [Fact]
    public async Task Independent_reads_start_in_parallel_up_to_the_shared_bound()
    {
        var coordinator = new ShellHydrationCoordinator(2);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = 0;
        var maximumRunning = 0;
        var started = 0;
        var work = Enumerable.Range(0, 4)
            .Select(index => new ShellHydrationWork($"work-{index}", async _ =>
            {
                var current = Interlocked.Increment(ref running);
                Interlocked.Increment(ref started);
                InterlockedExtensions.Max(ref maximumRunning, current);
                await release.Task;
                Interlocked.Decrement(ref running);
            }))
            .ToArray();

        var run = coordinator.RunAsync(work, CancellationToken.None);

        Volatile.Read(ref started).Should().Be(2, "two reads should start without waiting for either to finish");
        run.IsCompleted.Should().BeFalse();
        release.SetResult();

        (await run).Should().BeEmpty();
        maximumRunning.Should().Be(2);
        started.Should().Be(4);
    }

    [Fact]
    public async Task One_failed_read_does_not_cancel_independent_reads()
    {
        var coordinator = new ShellHydrationCoordinator(2);
        var completed = false;
        ShellHydrationWork[] work =
        [
            new("failed", _ => Task.FromException(new InvalidOperationException("optional RPC failed"))),
            new("healthy", _ =>
            {
                completed = true;
                return Task.CompletedTask;
            }),
        ];

        var failures = await coordinator.RunAsync(work, CancellationToken.None);

        completed.Should().BeTrue();
        failures.Should().ContainSingle().Which.Name.Should().Be("failed");
    }

    [Fact]
    public async Task Cancellation_prevents_queued_reads_from_starting()
    {
        var coordinator = new ShellHydrationCoordinator(1);
        using var cancellation = new CancellationTokenSource();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondStarted = false;
        ShellHydrationWork[] work =
        [
            new("active", async _ =>
            {
                firstStarted.SetResult();
                await release.Task;
            }),
            new("queued", _ =>
            {
                secondStarted = true;
                return Task.CompletedTask;
            }),
        ];

        var run = coordinator.RunAsync(work, cancellation.Token);
        await firstStarted.Task;
        cancellation.Cancel();
        release.SetResult();

        await FluentActions.Awaiting(() => run).Should().ThrowAsync<OperationCanceledException>();
        secondStarted.Should().BeFalse();
    }

    private static class InterlockedExtensions
    {
        public static void Max(ref int target, int value)
        {
            var current = Volatile.Read(ref target);
            while (current < value)
            {
                var observed = Interlocked.CompareExchange(ref target, value, current);
                if (observed == current)
                {
                    return;
                }

                current = observed;
            }
        }
    }
}
