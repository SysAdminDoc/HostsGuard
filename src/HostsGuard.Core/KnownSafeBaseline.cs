namespace HostsGuard.Core;

/// <summary>One entry in the known-safe baseline: an essential OS binary.</summary>
public sealed record BaselineEntry(string FileName, string Description);

/// <summary>
/// The curated known-safe baseline (NET-068): essential Windows binaries whose
/// outbound traffic should never trigger an ask-to-connect prompt, so Notify
/// mode targets *interesting* traffic instead of burying the user under
/// prompts for Windows Update, Defender, and OS infrastructure. Deliberately
/// excludes <c>svchost.exe</c> — it hosts everything, so blanket-allowing it
/// would defeat the point; per-service attribution (a separate item) is needed
/// to carve out individual svchost services.
/// </summary>
public static class KnownSafeBaseline
{
    public static readonly IReadOnlyList<BaselineEntry> Entries = new BaselineEntry[]
    {
        new("System", "Windows kernel (SMB, NCSI, core networking)"),
        new("lsass.exe", "Local Security Authority (domain auth)"),
        new("MoUsoCoreWorker.exe", "Update Orchestrator worker"),
        new("UsoClient.exe", "Update Session Orchestrator client"),
        new("wuauclt.exe", "Windows Update client"),
        new("WaaSMedicAgent.exe", "Windows Update remediation"),
        new("SIHClient.exe", "Server-initiated healing"),
        new("MsMpEng.exe", "Microsoft Defender engine"),
        new("MpCmdRun.exe", "Microsoft Defender command-line"),
        new("NisSrv.exe", "Defender network inspection"),
        new("SecurityHealthService.exe", "Windows Security health"),
    };

    private static readonly HashSet<string> Names =
        new(Entries.Select(e => e.FileName), StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// True if <paramref name="applicationPath"/> is a baseline OS binary. Matches
    /// by file name, and (except the pathless "System") requires the path to live
    /// under a Windows directory so an impostor named after a system binary
    /// elsewhere on disk is never auto-trusted.
    /// </summary>
    public static bool IsBaseline(string? applicationPath)
    {
        var path = (applicationPath ?? string.Empty).Trim();
        if (path.Length == 0)
        {
            return false;
        }

        // 5157 reports the kernel as the pathless "System".
        if (path.Equals("System", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var name = System.IO.Path.GetFileName(path);
        if (name.Length == 0 || !Names.Contains(name))
        {
            return false;
        }

        return path.Contains(@"\windows\", StringComparison.OrdinalIgnoreCase);
    }
}
