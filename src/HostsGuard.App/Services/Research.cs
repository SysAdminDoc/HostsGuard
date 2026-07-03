using System.Diagnostics;

namespace HostsGuard.App.Services;

/// <summary>
/// "Research Online" links (ported from the Python RESEARCH list). Opens the
/// user's default browser via shell execute.
/// </summary>
public static class Research
{
    public static readonly IReadOnlyList<(string Name, string UrlTemplate)> Sites = new[]
    {
        ("Google", "https://www.google.com/search?q={d}"),
        ("VirusTotal", "https://www.virustotal.com/gui/domain/{d}"),
        ("who.is", "https://who.is/whois/{d}"),
        ("URLScan", "https://urlscan.io/search/#{d}"),
        ("Shodan", "https://www.shodan.io/search?query={d}"),
        ("SecurityTrails", "https://securitytrails.com/domain/{d}"),
        ("MXToolbox", "https://mxtoolbox.com/SuperTool.aspx?action=mx:{d}"),
        ("AbuseIPDB", "https://www.abuseipdb.com/check/{d}"),
    };

    public static void Open(string urlTemplate, string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return; // context menus fire with null when no row is selected
        }

        var url = urlTemplate.Replace("{d}", Uri.EscapeDataString(domain), StringComparison.Ordinal);
        if (!url.StartsWith("https://", StringComparison.Ordinal))
        {
            return;
        }

        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }
}
