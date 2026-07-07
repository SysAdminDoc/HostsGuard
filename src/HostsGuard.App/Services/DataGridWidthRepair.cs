using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace HostsGuard.App.Services;

/// <summary>
/// Repairs WPF DataGrid columns that were first measured against a zero-width
/// scroll viewport and collapsed to MinWidth.
/// </summary>
public static class DataGridWidthRepair
{
    private static readonly MethodInfo? InvalidateColumnWidthsMethod =
        typeof(DataGrid).Assembly
            .GetType("System.Windows.Controls.DataGridColumnCollection")
            ?.GetMethod(
                "InvalidateColumnWidthsComputation",
                BindingFlags.Instance | BindingFlags.NonPublic);

    public static bool PrivateInvalidationHookAvailable => InvalidateColumnWidthsMethod is not null;

    public static async Task<DataGridWidthRepairResult> RepairAsync(DataGrid grid)
    {
        ArgumentNullException.ThrowIfNull(grid);
        var latest = DataGridWidthRepairResult.NotNeeded;

        for (var attempt = 0; attempt < 8; attempt++)
        {
            await Task.Delay(150).ConfigureAwait(true);
            if (!grid.IsVisible)
            {
                return latest;
            }

            try
            {
                latest = RepairOnce(grid);
                if (!latest.CollapsedColumnsRemain)
                {
                    return latest;
                }
            }
            catch (Exception ex) when (ex is TargetInvocationException or InvalidOperationException)
            {
                // Best-effort repair: a failed attempt must never take down the
                // shell; the next attempt or a manual resize can still recover.
            }
        }

        return latest;
    }

    public static DataGridWidthRepairResult RepairOnce(
        DataGrid grid,
        bool usePrivateInvalidation = true,
        bool forceFallback = false)
    {
        ArgumentNullException.ThrowIfNull(grid);

        var collapsedBefore = HasCollapsedColumns(grid);
        if (!forceFallback && !collapsedBefore)
        {
            return DataGridWidthRepairResult.NotNeeded;
        }

        FindScrollViewer(grid)?.InvalidateScrollInfo();
        InvalidateSubtree(grid);
        grid.UpdateLayout();

        var usedPrivateInvalidation = false;
        if (usePrivateInvalidation)
        {
            usedPrivateInvalidation = TryInvalidateColumnWidths(grid);
            grid.UpdateLayout();
        }

        var usedPublicFallback = false;
        if (forceFallback || HasCollapsedColumns(grid))
        {
            usedPublicFallback = ApplyPublicWidthFallback(grid);
            grid.UpdateLayout();
        }

        return new DataGridWidthRepairResult(
            usedPrivateInvalidation,
            usedPublicFallback,
            HasCollapsedColumns(grid));
    }

    private static bool TryInvalidateColumnWidths(DataGrid grid)
    {
        var declaringType = InvalidateColumnWidthsMethod?.DeclaringType;
        if (InvalidateColumnWidthsMethod is null
            || declaringType is null
            || !declaringType.IsInstanceOfType(grid.Columns))
        {
            return false;
        }

        InvalidateColumnWidthsMethod.Invoke(grid.Columns, null);
        return true;
    }

    private static bool ApplyPublicWidthFallback(DataGrid grid)
    {
        var columns = grid.Columns
            .Where(c => c.Visibility == Visibility.Visible)
            .ToArray();
        if (columns.Length == 0)
        {
            return false;
        }

        var available = ResolveAvailableWidth(grid, columns);
        var desired = columns.Select(DesiredFallbackWidth).ToArray();
        var desiredTotal = desired.Sum();
        if (available > desiredTotal)
        {
            var extra = (available - desiredTotal) / columns.Length;
            for (var i = 0; i < desired.Length; i++)
            {
                desired[i] += extra;
            }
        }
        else if (available > 0 && desiredTotal > available)
        {
            var scale = available / desiredTotal;
            for (var i = 0; i < desired.Length; i++)
            {
                desired[i] = Math.Max(columns[i].MinWidth + 24, desired[i] * scale);
            }
        }

        for (var i = 0; i < columns.Length; i++)
        {
            columns[i].Width = new DataGridLength(desired[i], DataGridLengthUnitType.Pixel);
        }

        return true;
    }

    private static double ResolveAvailableWidth(DataGrid grid, IReadOnlyList<DataGridColumn> columns)
    {
        var scrollViewer = FindScrollViewer(grid);
        var available = scrollViewer?.ViewportWidth ?? grid.ActualWidth;
        if (double.IsNaN(available) || double.IsInfinity(available) || available <= 0)
        {
            available = grid.ActualWidth;
        }

        var minimum = columns.Sum(c => Math.Max(c.MinWidth + 24, 72));
        if (double.IsNaN(available) || double.IsInfinity(available) || available <= 0)
        {
            return minimum;
        }

        return Math.Max(minimum, available - grid.RowHeaderActualWidth - SystemParameters.VerticalScrollBarWidth - 24);
    }

    private static double DesiredFallbackWidth(DataGridColumn column)
    {
        var minimum = Math.Max(column.MinWidth + 24, 72);
        if (column.Width.IsAbsolute && column.Width.DisplayValue > minimum)
        {
            return column.Width.DisplayValue;
        }

        return column.Width.UnitType switch
        {
            DataGridLengthUnitType.Star => Math.Max(minimum, 96 * Math.Max(1, column.Width.Value)),
            DataGridLengthUnitType.Auto or DataGridLengthUnitType.SizeToCells or DataGridLengthUnitType.SizeToHeader => Math.Max(minimum, 108),
            _ => minimum,
        };
    }

    private static bool HasCollapsedColumns(DataGrid grid)
    {
        return grid.Columns
            .Where(c => c.Visibility == Visibility.Visible)
            .Any(c => c.ActualWidth <= c.MinWidth + 0.5);
    }

    private static ScrollViewer? FindScrollViewer(DependencyObject node)
    {
        return FindDescendant<ScrollViewer>(node);
    }

    private static T? FindDescendant<T>(DependencyObject node)
        where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(node); i++)
        {
            var child = VisualTreeHelper.GetChild(node, i);
            if (child is T match)
            {
                return match;
            }

            var nested = FindDescendant<T>(child);
            if (nested is not null)
            {
                return nested;
            }
        }

        return null;
    }

    private static void InvalidateSubtree(DependencyObject node)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(node); i++)
        {
            var child = VisualTreeHelper.GetChild(node, i);
            if (child is UIElement el)
            {
                el.InvalidateMeasure();
                el.InvalidateArrange();
            }

            InvalidateSubtree(child);
        }
    }
}

public sealed record DataGridWidthRepairResult(
    bool UsedPrivateInvalidation,
    bool UsedPublicFallback,
    bool CollapsedColumnsRemain)
{
    public static DataGridWidthRepairResult NotNeeded { get; } = new(false, false, false);
}
