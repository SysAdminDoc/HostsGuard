using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace HostsGuard.App.Services;

/// <summary>
/// "x1,y1 x2,y2 …" → PointCollection, so ViewModels expose plain strings
/// (headless-testable) and only the view materializes geometry.
/// </summary>
public sealed class PointsTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var text = value as string;
        if (string.IsNullOrWhiteSpace(text))
        {
            return new PointCollection();
        }

        try
        {
            return PointCollection.Parse(text);
        }
        catch (FormatException)
        {
            return new PointCollection();
        }
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Series index → theme accent brush (Hg.Series0..4, theme-managed).</summary>
public sealed class SeriesBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var index = value is int i ? Math.Abs(i) % 5 : 0;
        return Application.Current?.TryFindResource($"Hg.Series{index}") as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
