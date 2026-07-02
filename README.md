# HostsGuard

![Version](https://img.shields.io/badge/version-3.15.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)
![Status](https://img.shields.io/badge/status-active-success)

> Real-time network privacy manager for Windows. Monitor DNS activity, manage your hosts file, control Windows Firewall rules, and block unwanted connections.


![Screenshot](screenshot.png)

## Quick Start

```bash
git clone https://github.com/SysAdminDoc/HostsGuard.git
cd HostsGuard
python HostsGuard.py  # Auto-installs constrained dependencies, requests admin elevation
```

**Requirements:** Python 3.8+, Windows 10/11, Administrator privileges

Dependencies (`PySide6`, `psutil`, `maxminddb`) are installed from `constraints.txt` on first run when missing. For deterministic local setup, run `py -3.12 -m pip install -r requirements.txt`.

### Building

```powershell
py -3.12 -m pip install -r requirements.txt pyinstaller
py -3.12 HostsGuard.py release-smoke # Prints tested dependency versions
pyinstaller HostsGuard.spec          # Builds to dist/HostsGuard/
winget install --id JRSoftware.InnoSetup -e
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss
# Produces installer_output/HostsGuard-v3.15.0-Setup.exe
```

## Features

### Hosts Activity Tab

| Feature | Description |
|---------|-------------|
| DNS Cache Monitor | Polls Windows DNS client cache every 3 seconds, surfaces new domains in real-time |
| Domain Blocking | Block individual domains or entire root domains via hosts file (`0.0.0.0` entries) |
| Domain Allowing | Whitelist domains to exclude them from blocking |
| Hide / Hide Root | Permanently suppress domains from the activity feed — persists across restarts via `hidden_roots` table |
| Feed Tracking | Records first seen, last seen, hit count, and originating process for every domain |
| Status Filtering | Filter by All, Blocked, Allowed, Unmanaged, or Hidden |
| Advanced Search | Search tables with `field:value`, `!term`, and `field!=value` filters |
| Bulk Actions | Multi-select domains for batch block, allow, or hide operations |
| Research Links | Right-click any domain to open Google, VirusTotal, who.is, URLScan, Shodan, SecurityTrails, MXToolbox, or AbuseIPDB |

### Firewall Activity Tab

| Feature | Description |
|---------|-------------|
| Live Connections | Real-time view of all outbound TCP/UDP connections via `psutil` |
| Firewall Status Overlay | Each connection shows whether it's blocked by hosts file, firewall, or neither |
| Process Identification | Shows process name, PID, remote port, country code, and traffic category |
| Quick Firewall Blocking | Block any IP (outbound, inbound, or both) or program directly from the connection list |
| Custom Rules | Create fully customized Windows Firewall rules with direction, action, protocol, address, and program |
| Learning Mode | Prompts on first connection from unknown processes — trust, untrust, or investigate |
| GeoIP Lookup | Resolves remote IPs to country codes via ip-api.com with LRU caching |

### Hosts File Tab

| Feature | Description |
|---------|-------------|
| Managed Domains | Database-backed domain management with status, source, hit tracking, and notes |
| Raw Editor | Direct editing of `C:\Windows\System32\drivers\etc\hosts` with syntax awareness |
| Clean & Save | Deduplicates, validates, and normalizes hosts entries in one click |
| Backup / Restore | Timestamped backups in `%APPDATA%\HostsGuard\backups\` with one-click restore |
| Emergency Reset | Resets hosts file to Windows defaults if something goes wrong |
| Blocklist Import | Import from 12+ community blocklists across ads, tracking, malware, and privacy categories |
| Paste Import | Bulk-add domains from clipboard (one per line) to hosts file or database |

### Firewall Rules Tab

| Feature | Description |
|---------|-------------|
| Full Rule Viewer | Lists all Windows Firewall rules with name, direction, action, protocol, remote address, and program |
| HG Prefix Tracking | HostsGuard-created rules use `HG_` prefix for easy identification and management |
| Quick Block Buttons | Block IP Out, Block IP In+Out, Block Program - instant rule creation |
| Change Action | Right-click any rule to toggle between Block and Allow |
| Enable / Disable | Toggle rules on/off without deleting them |
| Profile Management | Enable all firewall profiles (Domain, Public, Private) with one click |
| Bulk Delete | Remove all HostsGuard-created rules at once |
| Persistent State | FW rules tracked in database for recovery after system changes |

### Tools Tab

| Feature | Description |
|---------|-------------|
| Connection History | SQLite-backed log of all observed connections with search and export |
| Event Log | Chronological log of block, allow, firewall, and policy actions with action and reason filters |
| Statistics Dashboard | Blocked count, allowed count, feed total, today's hits, top blocked domains |
| DNS Flush | One-click `ipconfig /flushdns` |
| DNS Resolver Switcher | One-click switch to Cloudflare, Google, Quad9, AdGuard DNS, or NextDNS |
| Encrypted DNS Intelligence | Refresh Windows known DoH servers plus an optional SHA-256-checked resolver list; shows source and last-updated status |
| Network Reset | Winsock reset, IP release/renew |
| Database Sync | Manual hosts-to-DB synchronization |
| Session Recording | Record DNS + connection events to JSONL for analysis |
| Export | Export connections as CSV/JSONL and config as JSON, including policy reasons |
| Support Bundle | Export a redacted diagnostic zip with version/build info, sanitized config, DB integrity, logs, event history, firewall summary, hosts stats, and dependency versions |
| Machine Policy Migration | Copy per-user policy DB/config into ProgramData for consistent hosts/firewall policy across Windows accounts |

### System Features

| Feature | Description |
|---------|-------------|
| System Tray | Minimize to tray with desktop notifications for blocked domains |
| Persistent PowerShell | Keeps a single `powershell.exe` session alive — eliminates ~200ms spawn overhead per command |
| Parallel Startup | Database, hosts file, and connection DB load in a background thread behind a splash screen |
| Bandwidth Monitor | Real-time upload/download rates in the title bar via `psutil.net_io_counters` |
| DPI Aware | Scales all UI elements for high-DPI displays, with persisted 90/100/110/125/150 percent UI scale |
| Auto-Elevation | Requests UAC admin privileges on launch (required for hosts file and firewall access) |
| File Logging | Errors logged to `%APPDATA%\HostsGuard\hostsguard.log` (500KB rotating) |
| Portable Mode | `--portable` stores all data next to the exe instead of `%APPDATA%` |
| Dark/Light Theme | Toggle between dark (Tokyo Night) and light (Catppuccin Latte) themes |
| Observe Mode | Allow all connections silently for onboarding — review and create rules later |
| Lockdown Mode | Block all outbound by default, whitelist programs individually |
| Threat Intel | URLhaus + Feodo tracker overlay — flags connections to known-bad IPs/domains |
| Signed Binary Badge | Authenticode verification badge on processes (✔ signed / ✘ unsigned) |
| Offline GeoIP + ASN | Country and ASN resolution via local DB-IP Lite MMDB — works offline |
| Temp Allow | Allow a domain for 5/15/30/60 minutes, automatically revert to blocked |
| Scheduled Blocklist Refresh | Auto-update subscribed blocklists on configurable interval |
| Rule Groups | Filter and bulk-manage domains by source (blocklist, manual, etc.) |
| Firewall Drift Detection | Save baseline, detect added/removed/changed rules |
| CLI Interface | `block/allow/unblock/status/export/release-smoke` commands without launching GUI |
| ETW DNS Monitoring | Real-time DNS events via ETW with PowerShell polling fallback |
| Per-App Bandwidth Chart | Stacked area chart showing connection activity per process over time |
| Network Profiles | Save/switch named rule sets — different blocking for home/work/public |
| Headless Service Mode | `--service` runs monitoring without GUI, exposes token-authed HTTP JSON-RPC (GET /status /domains /stats /log /openapi.json, POST /domains) on port 7847 + optional signed/retried event webhooks |
| DNS Inspection | Right-click any domain to see A/AAAA/CNAME chains, TTLs, resolver latency |
| SHA-512 Integrity | Hash-based hosts file tamper detection (catches time-preserved modifications) |
| Registry Monitor | Detects DataBasePath registry redirection by malware |
| Windows Event Log | Tamper events written to Application log as structured JSON for SIEM ingestion |
| Block Encrypted DNS | Firewall-block refreshed DoH resolver IPs + DoT/DoQ port 853 (your own resolver exempt) so apps can't tunnel DNS past hosts blocking |
| Blocked Services | One-click toggles to block YouTube, TikTok, Facebook, Discord, Netflix, and more via curated hosts entries |
| Windows Telemetry Preset | One-click block ~28 Microsoft telemetry endpoints (reversible as a unit) |
| Scheduled Blocking | Block a domain or service on a recurring weekly schedule (windows may cross midnight) |
| Allowlist Subscriptions | Subscribe to remote allowlists that whitelist domains and win over blocklists |
| Mini Monitor | Tray-toggled always-on-top thumbnail of live up/down rates and connection/blocked counts |
| Orphaned FW Rule Detection | Flags HostsGuard program rules whose executable moved, suggests signed identity matches by signer/product/original filename/hash history, and previews the replacement before re-bind |
| Auto-Restore | Optional automatic hosts file restoration from backup on tamper detection |

## Blocklist Sources

Importable directly from the Hosts File tab:

| Category | Lists |
|----------|-------|
| **Popular** | HaGezi Ultimate, StevenBlack Unified, OISD Full, HOSTShield Combined |
| **Ads & Tracking** | Disconnect Tracking, Disconnect Ads |
| **Malware** | URLhaus, abuse.ch, Phishing Army |
| **Privacy** | First-Party Trackers (HaGezi), NoTracking |
| **Social** | StevenBlack Facebook |

## How It Works

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  DNS Cache Poll   │────>│   Feed Database   │────>│  Hosts Activity   │
│  (3s interval)    │     │   (SQLite WAL)    │     │  Tab (real-time)  │
│  via PowerShell   │     │                  │     │                  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                │
                                │ sync
                                ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Hosts File       │<───│  Domain Manager   │────>│  Hosts File Tab   │
│  (0.0.0.0 entries)│     │  (block/allow/    │     │  (editor + lists) │
│                  │     │   hide/root)      │     │                  │
└──────────────────┘     └──────────────────┘     └──────────────────┘

┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  psutil           │────>│  Connection DB    │────>│ Firewall Activity │
│  net_connections  │     │  (SQLite WAL)     │     │  (live view)      │
│  (2s interval)    │     │                  │     │                  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                                          │
                                                          │ block
                                                          ▼
                                                  ┌──────────────────┐
                                                  │  Windows Firewall │
                                                  │  (NetFirewallRule)│
                                                  │  via PowerShell   │
                                                  └──────────────────┘
```

### Thread Architecture

| Thread | Type | Purpose | Interval |
|--------|------|---------|----------|
| DNSMonitor | QThread | Polls `Get-DnsClientCache` via persistent PS session | 3s |
| ConnWorker | QThread | Scans `psutil.net_connections()` | 2s |
| HostsWatcher | QThread | Watches hosts file mtime for external changes | 3s |
| DNSResolveWorker | QThread | Background reverse DNS lookups | On demand |
| GeoWorker | QThread | Background GeoIP lookups via ip-api.com | On demand |
| FWLoadWorker | QThread | Loads all firewall rules (dedicated subprocess) | On demand |
| PersistentPS | subprocess | Long-lived PowerShell session for fast command execution | Persistent |

## Configuration

All data is stored in `%APPDATA%\HostsGuard\`:

Non-portable installs can be migrated from the per-user folder to a machine-wide
policy folder in `%ProgramData%\HostsGuard\` from Tools > Backup + Recovery >
**Use Machine Policy**. Once a machine policy exists, future launches use
ProgramData so global hosts and firewall state do not drift between Windows
accounts. Portable mode continues to store data next to the executable.

| File | Purpose |
|------|---------|
| `hostsguard.db` | Domain management, feed, event log, canonical reasons, FW state (SQLite WAL) |
| `connections.db` | Connection history (SQLite WAL) |
| `config.json` | Learning mode, trusted/untrusted processes, notification settings, UI scale |
| `doh_resolvers.json` | Refreshed DoH resolver intelligence: source, last update, SHA-256, and validated IP list |
| `hostsguard.log` | Error log (500KB rotating, 1 backup) |
| `backups/` | Timestamped hosts file backups |
| `favicons/` | Cached site favicons for domain table display |

## FAQ / Troubleshooting

**Q: The app requests admin privileges. Why?**
Writing to `C:\Windows\System32\drivers\etc\hosts` and creating Windows Firewall rules both require administrator access. HostsGuard auto-elevates via UAC on launch.

**Q: DNS monitoring shows "Requires Windows"**
The DNS cache monitor uses `Get-DnsClientCache` which is Windows-only. Connection monitoring via `psutil` works on all platforms, but the hosts file path and firewall features are Windows-specific.

**Q: Managed Domains tab is empty**
Click the **Refresh** button or switch away and back — the first load runs an async sync from the hosts file to the database. If you have a large hosts file (100k+ entries), the initial sync may take a few seconds.

**Q: I blocked a domain but it still resolves**
Run `ipconfig /flushdns` (available in the Tools tab) or wait for the DNS cache to expire. Some applications maintain their own DNS cache separate from the OS.

**Q: How do I undo everything?**
Hosts File tab > **Restore** restores the most recent backup. **Emergency Reset** rewrites the hosts file to Windows defaults. Firewall Rules tab > **Delete HG Rules** removes all HostsGuard-created firewall rules.

**Q: Can I run this headless / via CLI?**
Yes. CLI commands work without the GUI: `python HostsGuard.py block example.com`, `status`, `export`, `release-smoke` (block/allow/unblock require an elevated terminal). For continuous monitoring without GUI, use `python HostsGuard.py --service` which starts DNS monitoring, connection tracking, hosts integrity checks, and exposes a JSON-RPC endpoint on `http://127.0.0.1:7847` (configurable via `HG_PORT` env var). Endpoints: `GET /status`, `GET /domains`, `GET /stats`, `GET /log`, `GET /openapi.json`, and `POST /domains` (with `{action, domain}` body). `/status` includes DoH resolver intelligence source, last update, and resolver counts; `/domains` and `/log` include canonical reason values; `/log` supports validated `limit`, `since`, `action`, and `reason` query params such as `/log?reason=firewall&limit=50`. Errors use a stable `hostsguard.error.v1` JSON shape, and POST bodies over 1 MB are rejected instead of truncated. Because the service runs elevated and the endpoint can modify your hosts file, every request must include `X-HG-Token`; set `HG_TOKEN` explicitly or use the auto-generated token stored in `%APPDATA%\HostsGuard\service_token`.

Optional service event webhooks use `config.json` keys `webhook_enabled`, `webhook_url`, `webhook_secret`, `webhook_retries`, `webhook_backoff_seconds`, and `webhook_timeout_seconds`. When `webhook_secret` is set, each POST includes `X-HG-Signature: sha256=<hmac>` over the JSON body plus `X-HG-Schema: hostsguard.webhook.v1`. Retries are bounded to 0-5 with capped backoff/timeout, delivery retry/exhaustion status is written to `hostsguard.log`, and support bundles redact both webhook URLs and secrets.

**Q: How do I keep encrypted-DNS blocking current?**
Use Tools > DNS + Network > **Refresh DoH List**. HostsGuard merges Windows known DoH servers with the built-in resolver list and, if configured, a remote resolver list from `config.json` keys `doh_resolver_url` and `doh_resolver_sha256`. Remote lists are rejected without a SHA-256 value, failed refreshes leave the previous `doh_resolvers.json` intact, and enabling **Block Encrypted DNS** always exempts your current DNS resolver.

**Q: Windows Defender flags HostsGuard as a threat**
Blocking Microsoft telemetry domains causes Defender to report `SettingsModifier:Win32/HostsFileHijack`. This is a false positive - HostsGuard is modifying the hosts file intentionally. To resolve: Settings > Virus & Threat Protection > Manage settings > Exclusions > Add an exclusion > File > `C:\Windows\System32\drivers\etc\hosts`. HostsGuard shows a warning before importing lists that trigger this.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contributing

Issues and PRs welcome. If reporting a bug, use Tools > Config + Data > **Export Support Bundle** and attach the redacted zip.
