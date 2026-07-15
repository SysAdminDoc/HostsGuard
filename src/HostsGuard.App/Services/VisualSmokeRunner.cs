using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;

namespace HostsGuard.App.Services;

/// <summary>
/// Test-only rendered WPF smoke gate. It is invoked only by command-line flags.
/// </summary>
internal static class VisualSmokeRunner
{
    private static readonly (string Tab, string Landmark)[] PrimaryPages =
    [
        ("Hosts Activity", "ActivityGrid"),
        ("Alerts", "AlertsGrid"),
        ("Hosts File", "DomainsGrid"),
        ("Firewall Activity", "ConnectionsGrid"),
        ("Firewall Rules", "FwRulesGrid"),
        ("Tools", "ToolsSurface"),
    ];

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static async Task<int> RunAsync(
        Window window,
        string outputDir,
        string theme,
        string locale,
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
            Locale = locale,
            ExpectedSize = $"{expectedWidth}x{expectedHeight}",
            ActualSize = $"{Math.Round(window.ActualWidth)}x{Math.Round(window.ActualHeight)}",
            OutputDir = Path.GetFullPath(outputDir),
        };

        await WaitForLayoutAsync(window, settleMs, cancellationToken).ConfigureAwait(true);
        await SizeCaptureSurfaceAsync(window, expectedWidth, expectedHeight, cancellationToken).ConfigureAwait(true);
        var captureSurface = CaptureSurface(window);
        result.ActualSize = $"{Math.Round(captureSurface.ActualWidth)}x{Math.Round(captureSurface.ActualHeight)}";
        if (!SizeMatches(captureSurface, expectedWidth, expectedHeight))
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

        if (window.DataContext is not MainViewModel fixture || !fixture.IsConnected)
        {
            result.Failures.Add("Primary-page capture requires the deterministic connected fixture.");
        }

        for (var i = 0; i < Math.Min(PrimaryPages.Length, tabs.Items.Count); i++)
        {
            var page = PrimaryPages[i];
            tabs.SelectedIndex = i;
            tabs.UpdateLayout();
            window.UpdateLayout();
            await WaitForLayoutAsync(window, settleMs, cancellationToken).ConfigureAwait(true);

            if (i == 4
                && FindNamedElement(window, "FwRulesGrid") is DataGrid { Items.Count: > 0 } rulesGrid)
            {
                rulesGrid.SelectedIndex = 0;
                rulesGrid.UpdateLayout();
                window.UpdateLayout();
                await WaitForLayoutAsync(window, settleMs, cancellationToken).ConfigureAwait(true);
            }

            foreach (var failure in FindUnexpectedHorizontalScrollbars(window, page.Tab))
            {
                result.Failures.Add(failure);
            }

            if (IsPseudoLocale(locale))
            {
                foreach (var failure in FindPseudoLocaleLayoutFailures(window, page.Tab))
                {
                    result.Failures.Add(failure);
                }
            }

            ValidateSelectedPage(window, tabs, i, page.Tab, page.Landmark, result.Failures);
            var fileName = $"{theme}-{Slug(page.Tab)}.png";
            var path = Path.Combine(outputDir, fileName);
            var metrics = Capture(captureSurface, path);
            result.Captures.Add(new VisualSmokeCapture
            {
                Tab = page.Tab,
                Landmark = page.Landmark,
                Path = path,
                Sha256 = GetSha256(path),
                ChromeLuminance = Math.Round(AverageLuma(captureSurface, 0, 90), 1),
                AverageLuminance = Math.Round(metrics.AverageLuminance, 1),
                LuminanceRange = Math.Round(metrics.LuminanceRange, 1),
                OpaqueRatio = Math.Round(metrics.OpaqueRatio, 4),
                BottomOpaqueRatio = Math.Round(metrics.BottomOpaqueRatio, 4),
                ContentTileRatio = Math.Round(metrics.ContentTileRatio, 4),
            });

            ValidateCapture(theme, page.Tab, metrics, result.Failures);

            if (i == 0)
            {
                ValidateChromeLuminance(theme, AverageLuma(captureSurface, 0, 90), result.Failures);
            }
        }

        if (tabs.Items.Count < PrimaryPages.Length)
        {
            result.Failures.Add($"Only {tabs.Items.Count} tabs rendered; expected {PrimaryPages.Length}.");
        }

        foreach (var duplicate in result.Captures.GroupBy(capture => capture.Sha256)
                     .Where(group => group.Count() > 1))
        {
            result.Failures.Add(
                $"Primary pages rendered identical pixels: {string.Join(", ", duplicate.Select(capture => capture.Tab))}.");
        }

        await CaptureDisconnectedRecoveryAsync(window, captureSurface, outputDir, theme, settleMs, result,
            cancellationToken).ConfigureAwait(true);

        await CaptureDialogsAsync(window, outputDir, theme, settleMs, result, cancellationToken)
            .ConfigureAwait(true);

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

    private static async Task SizeCaptureSurfaceAsync(
        Window window,
        int expectedWidth,
        int expectedHeight,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var surface = CaptureSurface(window);
            var widthDelta = expectedWidth - surface.ActualWidth;
            var heightDelta = expectedHeight - surface.ActualHeight;
            if (Math.Abs(widthDelta) < 0.5 && Math.Abs(heightDelta) < 0.5)
            {
                return;
            }

            window.Width = Math.Max(window.MinWidth, window.ActualWidth + widthDelta);
            window.Height = Math.Max(window.MinHeight, window.ActualHeight + heightDelta);
            await WaitForLayoutAsync(window, 50, cancellationToken).ConfigureAwait(true);
        }
    }

    private static FrameworkElement CaptureSurface(Window window) =>
        window.Content as FrameworkElement ?? window;

    private static bool SizeMatches(FrameworkElement surface, int expectedWidth, int expectedHeight)
    {
        return (int)Math.Round(surface.ActualWidth) == expectedWidth
            && (int)Math.Round(surface.ActualHeight) == expectedHeight;
    }

    private static async Task CaptureDialogsAsync(
        Window owner,
        string outputDir,
        string theme,
        int settleMs,
        VisualSmokeResult result,
        CancellationToken cancellationToken)
    {
        var dialogs = new (string Name, Window Window)[]
        {
            ("About", new AboutDialog()),
            ("Confirmation", new ConfirmDialog(
                "Block all outbound traffic?",
                "New outbound connections will be blocked until you restore the safe network posture.")),
            ("Warning", new ConfirmDialog(
                "Decision not applied",
                "The service did not accept this decision. The connection stays blocked.",
                ThemedDialogKind.Warning)),
            ("Input", new InputDialog(
                "Assign rule group",
                "Enter a group name for the selected firewall rules.",
                "Browsers")),
            ("Connection consent", new ConsentWindow(new ConnectionDecisionRequest
            {
                Id = "visual-smoke",
                Application = @"C:\Program Files\Browser\browser.exe",
                Direction = "Out",
                RemoteAddress = "203.0.113.9",
                RemotePort = 443,
                Protocol = "TCP",
                ProcessId = 4711,
                Signer = "Verified Software Publisher",
                Country = "United States",
            })),
        };

        foreach (var (name, dialog) in dialogs)
        {
            try
            {
                dialog.Owner = owner;
                dialog.WindowStartupLocation = WindowStartupLocation.Manual;
                dialog.Left = -32000;
                dialog.Top = -32000;
                dialog.ShowActivated = false;
                dialog.ShowInTaskbar = false;
                dialog.Topmost = false;
                dialog.Show();
                await WaitForLayoutAsync(dialog, Math.Min(settleMs, 250), cancellationToken)
                    .ConfigureAwait(true);

                var fileName = $"{theme}-dialog-{Slug(name)}.png";
                var path = Path.Combine(outputDir, fileName);
                var dialogSurface = CaptureSurface(dialog);
                _ = Capture(dialogSurface, path);
                result.DialogCaptures.Add(new VisualSmokeDialogCapture
                {
                    Dialog = name,
                    Path = path,
                    ActualSize = $"{Math.Round(dialogSurface.ActualWidth)}x{Math.Round(dialogSurface.ActualHeight)}",
                });
                if (IsPseudoLocale(result.Locale))
                {
                    foreach (var failure in FindPseudoLocaleLayoutFailures(dialog, $"{name} dialog"))
                    {
                        result.Failures.Add(failure);
                    }

                    if (dialogSurface.ActualWidth > owner.ActualWidth || dialogSurface.ActualHeight > owner.ActualHeight)
                    {
                        result.Failures.Add($"Pseudo-locale {name} dialog exceeded the main capture surface.");
                    }
                }
            }
            catch (Exception ex)
            {
                result.Failures.Add($"Could not render the {name} dialog: {ex.Message}");
            }
            finally
            {
                dialog.Close();
            }
        }
    }

    private static async Task CaptureDisconnectedRecoveryAsync(
        Window window,
        FrameworkElement captureSurface,
        string outputDir,
        string theme,
        int settleMs,
        VisualSmokeResult result,
        CancellationToken cancellationToken)
    {
        if (window.DataContext is not MainViewModel viewModel)
        {
            result.Failures.Add("Disconnected recovery capture could not access the shell view model.");
            return;
        }

        viewModel.IsConnected = false;
        viewModel.ConnectionText = "Service unavailable — deterministic recovery fixture";
        await WaitForLayoutAsync(window, Math.Min(settleMs, 250), cancellationToken).ConfigureAwait(true);
        ValidateLandmark(window, "Disconnected recovery", "DisconnectedOverlay", result.Failures);

        var path = Path.Combine(outputDir, $"{theme}-disconnected-recovery.png");
        var metrics = Capture(captureSurface, path);
        result.StateCaptures.Add(new VisualSmokeStateCapture
        {
            State = "disconnected",
            Landmark = "DisconnectedOverlay",
            Path = path,
            Sha256 = GetSha256(path),
        });
        ValidateCapture(theme, "Disconnected recovery", metrics, result.Failures);
        viewModel.IsConnected = true;
        await WaitForLayoutAsync(window, 50, cancellationToken).ConfigureAwait(true);
    }

    private static void ValidateSelectedPage(
        Window window,
        TabControl tabs,
        int expectedIndex,
        string tab,
        string landmark,
        IList<string> failures)
    {
        if (tabs.SelectedIndex != expectedIndex)
        {
            failures.Add($"{tab} was not the selected primary page at capture time.");
        }

        if (window.DataContext is not MainViewModel { IsConnected: true })
        {
            failures.Add($"{tab} was captured without the connected fixture.");
        }

        if (FindNamedElement(window, "DisconnectedOverlay") is { IsVisible: true })
        {
            failures.Add($"{tab} was obscured by the disconnected recovery overlay.");
        }

        ValidateLandmark(window, tab, landmark, failures);
    }

    private static void ValidateLandmark(
        Window window,
        string surface,
        string landmark,
        IList<string> failures)
    {
        if (FindNamedElement(window, landmark) is not { } element)
        {
            failures.Add($"{surface} landmark '{landmark}' was not found.");
        }
        else if (!element.IsVisible || element.ActualWidth < 20 || element.ActualHeight < 20)
        {
            failures.Add(
                $"{surface} landmark '{landmark}' was not visibly rendered " +
                $"({element.ActualWidth:F0}x{element.ActualHeight:F0}).");
        }
    }

    private static FrameworkElement? FindNamedElement(DependencyObject root, string name)
    {
        if (root is FrameworkElement element && element.Name == name)
        {
            return element;
        }

        return FindDescendants<FrameworkElement>(root).FirstOrDefault(element => element.Name == name);
    }

    private static string GetSha256(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

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

    internal static IEnumerable<string> FindPseudoLocaleLayoutFailures(DependencyObject root, string surfaceName)
    {
        var textBlocks = root is TextBlock rootText
            ? FindDescendants<TextBlock>(root).Prepend(rootText)
            : FindDescendants<TextBlock>(root);
        foreach (var text in textBlocks.Where(text =>
                     text.Visibility == Visibility.Visible &&
                     text.ActualWidth > 0 && text.Text.Length != 0 &&
                     text.TextWrapping == TextWrapping.NoWrap && text.TextTrimming == TextTrimming.None &&
                     !HasVisualAncestor<DataGrid>(text)))
        {
            var dpi = VisualTreeHelper.GetDpi(text);
            var formatted = new FormattedText(
                text.Text,
                System.Globalization.CultureInfo.CurrentUICulture,
                text.FlowDirection,
                new Typeface(text.FontFamily, text.FontStyle, text.FontWeight, text.FontStretch),
                text.FontSize,
                Brushes.Black,
                dpi.PixelsPerDip);
            var availableWidth = text.ActualWidth;
            if (!double.IsNaN(text.Width))
            {
                availableWidth = Math.Min(availableWidth, text.Width);
            }

            if (!double.IsInfinity(text.MaxWidth))
            {
                availableWidth = Math.Min(availableWidth, text.MaxWidth);
            }

            if (formatted.WidthIncludingTrailingWhitespace > availableWidth + 2)
            {
                var label = text.Text.Length <= 60 ? text.Text : text.Text[..57] + "...";
                yield return $"Pseudo-locale text clipped on {surfaceName}: '{label}'.";
            }
        }
    }

    private static bool HasVisualAncestor<T>(DependencyObject element)
        where T : DependencyObject
    {
        for (var current = VisualTreeHelper.GetParent(element); current is not null;
             current = VisualTreeHelper.GetParent(current))
        {
            if (current is T)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsPseudoLocale(string locale) =>
        locale.Equals("qps-ploc", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(Environment.GetEnvironmentVariable("HOSTSGUARD_PSEUDO_LOCALE"), "1", StringComparison.Ordinal);

    private static CaptureMetrics Capture(FrameworkElement surface, string path)
    {
        var width = Math.Max(1, (int)Math.Round(surface.ActualWidth));
        var height = Math.Max(1, (int)Math.Round(surface.ActualHeight));
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(surface);

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using (var stream = File.Create(path))
        {
            encoder.Save(stream);
        }

        return Analyze(bitmap);
    }

    private static double AverageLuma(FrameworkElement surface, int yStart, int sampleHeight)
    {
        var width = Math.Max(1, (int)Math.Round(surface.ActualWidth));
        var height = Math.Max(1, (int)Math.Round(surface.ActualHeight));
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(surface);
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

    private static CaptureMetrics Analyze(BitmapSource bitmap)
    {
        var stride = bitmap.PixelWidth * 4;
        var pixels = new byte[stride * bitmap.PixelHeight];
        bitmap.CopyPixels(pixels, stride, 0);
        var step = Math.Max(1, Math.Min(bitmap.PixelWidth, bitmap.PixelHeight) / 250);
        var bottomStart = (int)(bitmap.PixelHeight * 0.95);
        long samples = 0, opaque = 0, bottomSamples = 0, bottomOpaque = 0;
        double total = 0, minimum = 255, maximum = 0;
        const int tileColumns = 10;
        const int tileRows = 8;
        var tileMinimum = Enumerable.Repeat(255d, tileColumns * tileRows).ToArray();
        var tileMaximum = new double[tileColumns * tileRows];

        for (var y = 0; y < bitmap.PixelHeight; y += step)
        {
            var row = y * stride;
            for (var x = 0; x < bitmap.PixelWidth; x += step)
            {
                var offset = row + (x * 4);
                var alpha = pixels[offset + 3];
                var luma = (0.2126 * pixels[offset + 2]) + (0.7152 * pixels[offset + 1]) +
                           (0.0722 * pixels[offset]);
                samples++;
                total += luma;
                if (alpha >= 250)
                {
                    opaque++;
                    minimum = Math.Min(minimum, luma);
                    maximum = Math.Max(maximum, luma);
                }

                if (y >= bottomStart)
                {
                    bottomSamples++;
                    if (alpha >= 250)
                    {
                        bottomOpaque++;
                    }
                }

                var tileX = Math.Min(tileColumns - 1, x * tileColumns / bitmap.PixelWidth);
                var tileY = Math.Min(tileRows - 1, y * tileRows / bitmap.PixelHeight);
                var tile = (tileY * tileColumns) + tileX;
                tileMinimum[tile] = Math.Min(tileMinimum[tile], luma);
                tileMaximum[tile] = Math.Max(tileMaximum[tile], luma);
            }
        }

        var contentTiles = tileMaximum.Zip(tileMinimum).Count(pair => pair.First - pair.Second >= 12);
        return new CaptureMetrics(
            samples == 0 ? 0 : total / samples,
            maximum - minimum,
            samples == 0 ? 0 : opaque / (double)samples,
            bottomSamples == 0 ? 0 : bottomOpaque / (double)bottomSamples,
            contentTiles / (double)(tileColumns * tileRows));
    }

    private static void ValidateCapture(
        string theme,
        string tab,
        CaptureMetrics metrics,
        IList<string> failures)
    {
        if (metrics.OpaqueRatio < 0.995 || metrics.BottomOpaqueRatio < 0.995)
        {
            failures.Add($"{tab} {theme} capture contains transparent/blank pixels " +
                         $"(opaque {metrics.OpaqueRatio:P1}, bottom {metrics.BottomOpaqueRatio:P1}).");
        }

        if (metrics.LuminanceRange < 60 || metrics.ContentTileRatio < 0.10)
        {
            failures.Add($"{tab} {theme} capture lacks rendered UI detail " +
                         $"(range {metrics.LuminanceRange:F1}, detailed tiles {metrics.ContentTileRatio:P1}).");
        }

        var dark = IsDarkPalette(theme);
        var invalidAverage = dark
            ? metrics.AverageLuminance is < 5 or > 100
            : metrics.AverageLuminance is < 100 or > 250;
        if (invalidAverage)
        {
            failures.Add($"{tab} {theme} average luminance {metrics.AverageLuminance:F1} is outside the theme bounds.");
        }
    }

    private static bool IsDarkPalette(string theme) =>
        string.Equals(theme, "dark", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(theme, "contrast-aquatic", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(theme, "contrast-dusk", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(theme, "contrast-night-sky", StringComparison.OrdinalIgnoreCase);

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

        public string Locale { get; set; } = "";

        public string ExpectedSize { get; set; } = "";

        public string ActualSize { get; set; } = "";

        public string OutputDir { get; set; } = "";

        public List<VisualSmokeCapture> Captures { get; } = [];

        public List<VisualSmokeDialogCapture> DialogCaptures { get; } = [];

        public List<VisualSmokeStateCapture> StateCaptures { get; } = [];

        public List<string> Failures { get; init; } = [];
    }

    private sealed class VisualSmokeCapture
    {
        public string Tab { get; init; } = "";

        public string Path { get; init; } = "";

        public string Landmark { get; init; } = "";

        public string Sha256 { get; init; } = "";

        public double ChromeLuminance { get; init; }

        public double AverageLuminance { get; init; }

        public double LuminanceRange { get; init; }

        public double OpaqueRatio { get; init; }

        public double BottomOpaqueRatio { get; init; }

        public double ContentTileRatio { get; init; }
    }

    private sealed record CaptureMetrics(
        double AverageLuminance,
        double LuminanceRange,
        double OpaqueRatio,
        double BottomOpaqueRatio,
        double ContentTileRatio);

    private sealed class VisualSmokeDialogCapture
    {
        public string Dialog { get; init; } = "";

        public string Path { get; init; } = "";

        public string ActualSize { get; init; } = "";
    }

    private sealed class VisualSmokeStateCapture
    {
        public string State { get; init; } = "";

        public string Landmark { get; init; } = "";

        public string Path { get; init; } = "";

        public string Sha256 { get; init; } = "";
    }
}
