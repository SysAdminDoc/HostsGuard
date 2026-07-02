using HostsGuard.Data;

// HostsGuard.Migrator — one-shot import of a Python-era HostsGuard profile
// (%APPDATA%\HostsGuard) into the .NET service data dir (%ProgramData%\HostsGuard).
// Usage: HostsGuard.Migrator [--source <dir>] [--target <dir>] [--dry-run]

var source = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HostsGuard");
var target = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "HostsGuard");
var dryRun = false;

for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--source" when i + 1 < args.Length:
            source = args[++i];
            break;
        case "--target" when i + 1 < args.Length:
            target = args[++i];
            break;
        case "--dry-run":
            dryRun = true;
            break;
        case "--help" or "-h":
            Console.WriteLine("Usage: HostsGuard.Migrator [--source <dir>] [--target <dir>] [--dry-run]");
            return 0;
        default:
            Console.Error.WriteLine($"Unknown argument: {args[i]}");
            return 2;
    }
}

Console.WriteLine($"HostsGuard Python-profile migration{(dryRun ? " (dry run)" : string.Empty)}");
Console.WriteLine($"  source: {source}");
Console.WriteLine($"  target: {target}");
Console.WriteLine();

try
{
    var report = PythonMigration.Run(source, target, dryRun);
    foreach (var action in report.Actions)
    {
        Console.WriteLine($"  - {action}");
    }

    Console.WriteLine();
    if (report.AlreadyMigrated)
    {
        Console.WriteLine("Already migrated; nothing changed.");
        return 0;
    }

    Console.WriteLine(dryRun ? "Dry run — nothing was changed. Summary of what WOULD import:" : "Imported:");
    Console.WriteLine($"  domains:                {report.Domains}");
    Console.WriteLine($"  schedules:              {report.Schedules}");
    Console.WriteLine($"  temp-allow windows:     {report.TempAllows}");
    Console.WriteLine($"  allowlist subscriptions:{report.AllowlistUrls,2}");
    Console.WriteLine($"  blocklist subscriptions:{report.BlocklistSubs,2}");
    Console.WriteLine($"  backups copied:         {report.BackupsCopied}");
    Console.WriteLine();
    Console.WriteLine("Firewall HG_ rules re-discover live via COM and need no migration.");
    return 0;
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
{
    Console.Error.WriteLine($"Migration failed: {ex.Message}");
    return 1;
}
