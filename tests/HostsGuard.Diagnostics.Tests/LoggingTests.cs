using System.Diagnostics;
using FluentAssertions;
using Xunit;

namespace HostsGuard.Diagnostics.Tests;

/// <summary>NET-180: the shared file logger renders the ambient W3C trace id.</summary>
public class LoggingTests
{
    [Fact]
    public void File_logger_renders_the_ambient_trace_id()
    {
        var dir = Path.Combine(Path.GetTempPath(), "hg_logtests_" + Guid.NewGuid().ToString("N"));
        try
        {
            var activity = new Activity("test-op");
            activity.SetIdFormat(ActivityIdFormat.W3C);
            activity.Start();
            var traceId = activity.TraceId.ToHexString();

            using (var logger = Logging.CreateFileLogger(dir))
            {
                logger.Information("correlated event for {Target}", "example.com");
            }

            activity.Stop();

            var content = string.Join('\n', Directory.GetFiles(dir, "*.log").Select(File.ReadAllText));
            content.Should().Contain("correlated event");
            content.Should().Contain(traceId, "the output template must render the ambient activity's TraceId");
        }
        finally
        {
            try
            {
                Directory.Delete(dir, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}
