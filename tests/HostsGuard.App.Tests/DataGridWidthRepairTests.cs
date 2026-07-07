using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using FluentAssertions;
using HostsGuard.App.Services;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class DataGridWidthRepairTests
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
        thread.Join(TimeSpan.FromSeconds(30)).Should().BeTrue("the STA repair test must not hang");
        failure.Should().BeNull();
    }

    [Fact]
    public void Public_fallback_forces_usable_widths_when_private_hook_is_unavailable()
    {
        RunSta(() =>
        {
            var grid = new DataGrid
            {
                AutoGenerateColumns = false,
                Width = 720,
                Height = 240,
                ItemsSource = new[]
                {
                    new Row("example.test", "Observed", "chrome.exe", 12),
                },
            };
            grid.Columns.Add(new DataGridTextColumn
            {
                Header = "Domain",
                Binding = new Binding(nameof(Row.Domain)),
                Width = new DataGridLength(2, DataGridLengthUnitType.Star),
                MinWidth = 20,
            });
            grid.Columns.Add(new DataGridTextColumn
            {
                Header = "Status",
                Binding = new Binding(nameof(Row.Status)),
                Width = new DataGridLength(90),
                MinWidth = 20,
            });
            grid.Columns.Add(new DataGridTextColumn
            {
                Header = "Process",
                Binding = new Binding(nameof(Row.Process)),
                Width = new DataGridLength(1, DataGridLengthUnitType.Star),
                MinWidth = 20,
            });
            grid.Columns.Add(new DataGridTextColumn
            {
                Header = "Hits",
                Binding = new Binding(nameof(Row.Hits)),
                Width = new DataGridLength(60),
                MinWidth = 20,
            });

            var window = new Window
            {
                Width = 720,
                Height = 240,
                Content = grid,
                Left = -32000,
                Top = -32000,
                ShowActivated = false,
                ShowInTaskbar = false,
                WindowStartupLocation = WindowStartupLocation.Manual,
            };

            try
            {
                window.Show();
                window.UpdateLayout();

                var result = DataGridWidthRepair.RepairOnce(
                    grid,
                    usePrivateInvalidation: false,
                    forceFallback: true);

                _ = DataGridWidthRepair.PrivateInvalidationHookAvailable;
                result.UsedPrivateInvalidation.Should().BeFalse();
                result.UsedPublicFallback.Should().BeTrue();
                result.CollapsedColumnsRemain.Should().BeFalse();
                grid.Columns.Should().OnlyContain(c =>
                    c.Width.UnitType == DataGridLengthUnitType.Pixel
                    && c.Width.DisplayValue > c.MinWidth + 1);
            }
            finally
            {
                window.Close();
            }
        });
    }

    private sealed record Row(string Domain, string Status, string Process, int Hits);
}
