using System.Windows.Controls;
using FluentAssertions;
using HostsGuard.App.Services;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class PasswordBoxHelperTests
{
    private static void RunSta(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally
            {
                System.Windows.Threading.Dispatcher.CurrentDispatcher.InvokeShutdown();
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join(TimeSpan.FromSeconds(30)).Should().BeTrue("the STA password helper test must not hang");
        failure.Should().BeNull();
    }

    [Fact]
    public void IsEmpty_tracks_password_changes_for_watermarked_boxes()
    {
        RunSta(() =>
        {
            var box = new PasswordBox();
            PasswordBoxHelper.SetWatermark(box, "Enter lock password");

            PasswordBoxHelper.GetWatermark(box).Should().Be("Enter lock password");
            PasswordBoxHelper.GetIsEmpty(box).Should().BeTrue();

            box.Password = "secret";
            PasswordBoxHelper.GetIsEmpty(box).Should().BeFalse();

            box.Clear();
            PasswordBoxHelper.GetIsEmpty(box).Should().BeTrue();
        });
    }
}
