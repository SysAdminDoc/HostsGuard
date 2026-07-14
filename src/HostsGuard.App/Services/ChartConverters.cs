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
        return Application.Current?.TryFindResource($"Hg.Series{index}") as Brush
            ?? Application.Current?.TryFindResource("Hg.Text") as Brush
            ?? SystemColors.ControlTextBrush;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Series index -> a stable line pattern. Charts therefore remain distinguishable
/// when a Windows contrast theme intentionally maps every series to one color.
/// </summary>
public sealed class SeriesDashConverter : IValueConverter
{
    private static readonly DoubleCollection[] Patterns =
    [
        Create(),
        Create(6, 3),
        Create(2, 2),
        Create(8, 2, 2, 2),
        Create(1, 2),
    ];

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var index = value is int i ? Math.Abs(i) % Patterns.Length : 0;
        return Patterns[index];
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();

    private static DoubleCollection Create(params double[] values)
    {
        var collection = new DoubleCollection(values);
        collection.Freeze();
        return collection;
    }
}
