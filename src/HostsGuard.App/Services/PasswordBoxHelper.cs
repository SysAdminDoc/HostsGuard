using System.Windows;
using System.Windows.Controls;

namespace HostsGuard.App.Services;

public static class PasswordBoxHelper
{
    public static readonly DependencyProperty WatermarkProperty =
        DependencyProperty.RegisterAttached(
            "Watermark",
            typeof(string),
            typeof(PasswordBoxHelper),
            new PropertyMetadata(string.Empty, OnWatermarkChanged));

    public static readonly DependencyProperty IsEmptyProperty =
        DependencyProperty.RegisterAttached(
            "IsEmpty",
            typeof(bool),
            typeof(PasswordBoxHelper),
            new PropertyMetadata(true));

    public static string GetWatermark(DependencyObject obj)
    {
        return (string)obj.GetValue(WatermarkProperty);
    }

    public static void SetWatermark(DependencyObject obj, string value)
    {
        obj.SetValue(WatermarkProperty, value);
    }

    public static bool GetIsEmpty(DependencyObject obj)
    {
        return (bool)obj.GetValue(IsEmptyProperty);
    }

    private static void SetIsEmpty(DependencyObject obj, bool value)
    {
        obj.SetValue(IsEmptyProperty, value);
    }

    private static void OnWatermarkChanged(DependencyObject obj, DependencyPropertyChangedEventArgs e)
    {
        if (obj is not PasswordBox box)
        {
            return;
        }

        box.PasswordChanged -= OnPasswordChanged;
        box.PasswordChanged += OnPasswordChanged;
        box.Loaded -= OnLoaded;
        box.Loaded += OnLoaded;
        box.Unloaded -= OnUnloaded;
        box.Unloaded += OnUnloaded;
        UpdateIsEmpty(box);
    }

    private static void OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox box)
        {
            UpdateIsEmpty(box);
        }
    }

    private static void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox box)
        {
            UpdateIsEmpty(box);
        }
    }

    private static void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox box)
        {
            box.PasswordChanged -= OnPasswordChanged;
            box.Loaded -= OnLoaded;
            box.Unloaded -= OnUnloaded;
        }
    }

    private static void UpdateIsEmpty(PasswordBox box)
    {
        SetIsEmpty(box, string.IsNullOrEmpty(box.Password));
    }
}
