using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace HostsGuard.App.Services;

/// <summary>Shows content when a bound count or collection is empty.</summary>
public sealed class EmptyStateVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var empty = value switch
        {
            null => true,
            _ when ReferenceEquals(value, DependencyProperty.UnsetValue) => true,
            int count => count == 0,
            long count => count == 0,
            ICollection collection => collection.Count == 0,
            _ => false,
        };
        return empty ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Inverse bool-to-visibility converter for recovery affordances.</summary>
public sealed class InverseBooleanToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is bool b && b ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
