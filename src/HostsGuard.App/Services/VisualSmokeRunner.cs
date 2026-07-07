using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace HostsGuard.App.Services;

/// <summary>
/// Test-only rendered WPF smoke gate. It is invoked only by command-line flags.
/// </summary>
internal static class VisualSmokeRunner
{
    private static readonly string[] TabNames =
    [
        "Hosts Activity",
        "Hosts File",
        "Firewall Activity",
        "Firewall Rules",
        "Tools",
    ];

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static async Task<int> RunAsync(
        Window window,
        string outputDir,
        string theme,
        int expectedWidth,
        int expectedHeight,
        int settleMs,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(window);
        Directory.CreateDirectory(outputDir);

        var result = new VisualSmokeResult
        {
            Theme = theme,
            ExpectedSize = $"{expectedWidth}x{expectedHeight}",
            ActualSize = $"{Math.Round(window.ActualWidth)}x{Math.Round(window.ActualHeight)}",
            OutputDir = Path.GetFullPath(outputDir),
        };

        await WaitForLayoutAsync(window, settleMs, cancellationToken).ConfigureAwait(true);
        result.ActualSize = $"{Math.Round(window.ActualWidth)}x{Math.Round(window.ActualHeight)}";
        if (!SizeMatches(window, expectedWidth, expectedHeight))
        {
            result.Failures.Add(
                $"Window rendered at {result.ActualSize}; expected {expectedWidth}x{expectedHeight}.");
        }

        var tabs = FindDescendant<TabControl>(window);
        if (tabs is null)
        {
            result.Failures.Add("Main tab control was not found.");
            WriteResult(outputDir, result);
            return 2;
        }

        for (var i = 0; i < Math.Min(TabNames.Length, tabs.Items.Count); i++)
        {
            tabs.SelectedIndex = i;
            tabs.UpdateLayout();
            window.UpdateLayout();
            await WaitForLayoutAsync(window, settleMs, cancellationToken).ConfigureAwait(true);

            foreach (var failure in FindUnexpectedHorizontalScrollbars(window, TabNames[i]))
            {
                result.Failures.Add(failure);
            }

            var fileName = $"{theme}-{Slug(TabNames[i])}.png";
            var path = Path.Combine(outputDir, fileName);
            var luma = Capture(window, path, 0, 90);
            result.Captures.Add(new VisualSmokeCapture
            {
                Tab = TabNames[i],
                Path = path,
                ChromeLuminance = Math.Round(luma, 1),
            });

            if (i == 0)
            {
                ValidateChromeLuminance(theme, luma, result.Failures);
            }
        }

        if (tabs.Items.Count < TabNames.Length)
        {
            result.Failures.Add($"Only {tabs.Items.Count} tabs rendered; expected {TabNames.Length}.");
        }

        WriteResult(outputDir, result);
        return result.Failures.Count == 0 ? 0 : 2;
    }

    public static void WriteFailure(string outputDir, Exception exception)
    {
        Directory.CreateDirectory(outputDir);
        WriteResult(outputDir, new VisualSmokeResult
        {
            OutputDir = Path.GetFullPath(outputDir),
            Failures = { exception.Message },
        });
    }

    private static async Task WaitForLayoutAsync(Window window, int settleMs, CancellationToken cancellationToken)
    {
        await window.Dispatcher.InvokeAsync(window.UpdateLayout).Task.ConfigureAwait(true);
        await Task.Delay(Math.Max(50, settleMs), cancellationToken).ConfigureAwait(true);
        await window.Dispatcher.InvokeAsync(window.UpdateLayout).Task.ConfigureAwait(true);
    }

    private static bool SizeMatches(Window window, int expectedWidth, int expectedHeight)
    {
        return (int)Math.Round(window.ActualWidth) == expectedWidth
            && (int)Math.Round(window.ActualHeight) == expectedHeight;
    }

    private static IEnumerable<string> FindUnexpectedHorizontalScrollbars(Window window, string tabName)
    {
        foreach (var grid in FindDescendants<DataGrid>(window).Where(g => g.IsVisible && g.ActualWidth > 0))
        {
            var gridName = AutomationProperties.GetName(grid);
            foreach (var bar in FindDescendants<ScrollBar>(grid))
            {
                if (!bar.IsVisible
                    || bar.Orientation != Orientation.Horizontal
                    || bar.ActualWidth <= 40
                    || bar.ActualHeight <= 4)
                {
                    continue;
                }

                yield return $"Unexpected horizontal scrollbar in grid '{gridName}' on '{tabName}'.";
            }
        }
    }

    private static double Capture(Window window, string path, int yStart, int sampleHeight)
    {
        var width = Math.Max(1, (int)Math.Round(window.ActualWidth));
        var height = Math.Max(1, (int)Math.Round(window.ActualHeight));
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(window);

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using (var stream = File.Create(path))
        {
            encoder.Save(stream);
        }

        return AverageLuma(bitmap, yStart, sampleHeight);
    }

    private static double AverageLuma(BitmapSource bitmap, int yStart, int sampleHeight)
    {
        var yEnd = Math.Min(bitmap.PixelHeight, yStart + sampleHeight);
        var stride = ((bitmap.PixelWidth * bitmap.Format.BitsPerPixel) + 7) / 8;
        var pixels = new byte[stride * bitmap.PixelHeight];
        bitmap.CopyPixels(pixels, stride, 0);

        var stepX = Math.Max(1, bitmap.PixelWidth / 80);
        var stepY = Math.Max(1, Math.Max(1, yEnd - yStart) / 12);
        double total = 0;
        var count = 0;

        for (var y = yStart; y < yEnd; y += stepY)
        {
            var row = y * stride;
            for (var x = 0; x < bitmap.PixelWidth; x += stepX)
            {
                var offset = row + (x * 4);
                var blue = pixels[offset];
                var green = pixels[offset + 1];
                var red = pixels[offset + 2];
                total += (0.2126 * red) + (0.7152 * green) + (0.0722 * blue);
                count++;
            }
        }

        return count == 0 ? 0 : total / count;
    }

    private static void ValidateChromeLuminance(string theme, double luma, IList<string> failures)
    {
        if (string.Equals(theme, "dark", StringComparison.OrdinalIgnoreCase) && luma > 95)
        {
            failures.Add($"Dark chrome luminance was {Math.Round(luma, 1)}; expected <= 95.");
        }

        if (string.Equals(theme, "light", StringComparison.OrdinalIgnoreCase) && luma < 115)
        {
            failures.Add($"Light chrome luminance was {Math.Round(luma, 1)}; expected >= 115.");
        }
    }

    private static T? FindDescendant<T>(DependencyObject root)
        where T : DependencyObject
    {
        return FindDescendants<T>(root).FirstOrDefault();
    }

    private static IEnumerable<T> FindDescendants<T>(DependencyObject root)
        where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T match)
            {
                yield return match;
            }

            foreach (var descendant in FindDescendants<T>(child))
            {
                yield return descendant;
            }
        }
    }

    private static string Slug(string value)
    {
        var chars = value
            .ToLowerInvariant()
            .Select(c => char.IsAsciiLetterOrDigit(c) ? c : '-')
            .ToArray();
        return string.Join('-', new string(chars).Split('-', StringSplitOptions.RemoveEmptyEntries));
    }

    private static void WriteResult(string outputDir, VisualSmokeResult result)
    {
        File.WriteAllText(
            Path.Combine(outputDir, "visual-smoke-run.json"),
            JsonSerializer.Serialize(result, JsonOptions));
    }

    private sealed class VisualSmokeResult
    {
        public string Theme { get; set; } = "";

        public string ExpectedSize { get; set; } = "";

        public string ActualSize { get; set; } = "";

        public string OutputDir { get; set; } = "";

        public List<VisualSmokeCapture> Captures { get; } = [];

        public List<string> Failures { get; init; } = [];
    }

    private sealed class VisualSmokeCapture
    {
        public string Tab { get; init; } = "";

        public string Path { get; init; } = "";

        public double ChromeLuminance { get; init; }
    }
}
