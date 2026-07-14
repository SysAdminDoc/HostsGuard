# HostsGuard

![Version](https://img.shields.io/badge/version-0.12.121-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4)
![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet&logoColor=white)
![Status](https://img.shields.io/badge/status-active-success)

> Real-time network privacy manager for Windows. Monitor DNS activity, manage your hosts file, control Windows Firewall rules, consent-prompt on new outbound connections, and block unwanted traffic — all local, zero telemetry.

## Screenshots

Live DNS activity feed with the premium operator-console status rail, native themed window chrome, icon-led navigation, dense activity table, selected-row inspector, per-root 24h sparklines, and the `field:value` search DSL - dark, light, and live Windows contrast themes. The local visual-smoke gate renders deterministic connected/populated fixtures in dark, light, Aquatic, Desert, Dusk, and Night Sky palettes; asserts a visible landmark and unique pixel hash for every primary page; captures disconnected recovery separately; and pins matching app/service versions plus evidence in `docs/img/visual-smoke-manifest.json`.

![Hosts Activity — dark theme](docs/img/hosts-activity-dark.png)

![Hosts Activity — light theme](docs/img/hosts-activity-light.png)

## Architecture

HostsGuard is a **split-trust, two-process** application built on .NET 10 (LTS):

```
┌───────────────────────────────┐      gRPC over Named Pipe        ┌────────────────────────────────────┐
│  HostsGuard.App (WPF)         │  (ACL'd pipe, per-session        │  HostsGuard.Service (LocalSystem)  │
│  UNELEVATED desktop UI        │◄────token authentication)───────►│  Windows Service — owns ALL        │
│  tray · dashboards · prompts  │   unary + server-streaming       │  privileged mutation               │
└───────────────────────────────┘                                  │  · hosts file (transactional)      │
                                                                   │  · Windows Firewall COM rules      │
┌───────────────────────────────┐      same contract               │  · ETW DNS / IPHLPAPI connections  │
│  HostsGuard.Cli               │─────────────────────────────────►│  · tamper watch · scheduler        │
│  block/allow/status/export…   │                                  │  · SQLite (ProgramData)            │
└───────────────────────────────┘                                  └────────────────────────────────────┘
```

The elevated logic lives in a LocalSystem service that starts with the OS, so the UI **never needs UAC**, mutation is centralized and auditable, tamper self-heal runs even when nobody is logged in, and every OS call is a typed Windows API (Firewall COM, ETW, IPHLPAPI) instead of a parsed subprocess.

## Install

1. Download the `win-x64` or `win-arm64` `HostsGuard-vX.Y.Z-<rid>-dotnet-Setup.exe` from [Releases](https://github.com/SysAdminDoc/HostsGuard/releases).
2. Run it (the installer elevates once to register the `HostsGuardSvc` service; the app itself runs unelevated).
3. Launch **HostsGuard** from the Start menu or tray.

**Requirements:** Windows 10/11, x64 or ARM64. The service depends on the Windows Firewall service (MpsSvc). Uninstall stops the service, restores your default firewall posture, and removes all `HG_` rules.

### Migrating from the Python build (v3.x)

The installer includes `%ProgramFiles%\HostsGuard\migrator\HostsGuard.Migrator.exe`, a one-shot import of a Python-era profile — `hostsguard.db` (domains, feed, event log, profiles, firewall state), `config.json` (schedules, allowlists, DoH state, learning trust sets), and `doh_resolvers.json` — into the new schema. `HG_` firewall rules are re-discovered live via COM and carry over automatically. Preview first with `HostsGuard.Migrator.exe --dry-run`; the migration is idempotent.

The final Python build (v3.17.0) is preserved at the [`python-eol`](https://github.com/SysAdminDoc/HostsGuard/releases/tag/python-eol) tag.

## Features

### Consent prompts (ask-to-connect)

| Feature | Description |
|---------|-------------|
| Filtering modes | **Normal** (enforce silently), **Notify** (prompt on new outbound connections), **Learning** (auto-allow and record) — switchable from the tray |
| Consent window | Top-most prompt on blocked outbound attempts with process path or interpreter command line, signer, resolved hostname, GeoIP country, threat-intel verdict, and domain purpose |
| Scope + duration | Allow/block by program, remote IP, or port — permanently or for a limited time window |
| Interpreter script binding | Prompts for `python`, `node`, `pwsh`, `java`, `wscript`, and `cscript` show the extracted script/module and can bind the decision to exe+script without broadly allowing every script under that interpreter |
| Known-safe baseline | OS-essential binaries (Windows Update, Defender, kernel, LSA) are auto-allowed so prompts target interesting traffic |
| Identity-bound rules | Rules record the binary's SHA-256 and signer; a renamed impostor at a whitelisted path is re-prompted, while an auto-updater moving to a new versioned directory is recognized as the same app |
| Trust publisher / folder | Auto-allow future software signed by a trusted Authenticode publisher, or any binary under a trusted install folder — opted in from the prompt |
| Inbound consent | Opt-in prompting on unruled **inbound** connections too, producing scoped inbound rules (off by default to avoid unsolicited-inbound noise) |
| Decision history | Every consent decision is recorded and reviewable, with WFP filter origin/runtime and interface attribution when Windows emits it |
| Posture rails | Arming Notify/Learning sets default-outbound Block per profile; the prior posture is restored on switch back to Normal and on service stop |
| Accessibility | Full AutomationProperties coverage, explicit tab order, live-region threat banner, keyboard/screen-reader focus management |

### Hosts Activity

| Feature | Description |
|---------|-------------|
| Real-time DNS feed | ETW `Microsoft-Windows-DNS-Client` events surface domains as they resolve — no polling |
| Observation integrity | DNS ETW, kernel-network ETW, and Security-log sources report healthy/degraded/unavailable state plus loss, gap, restart, transition, and incomplete-interval evidence in the UI, CLI, and support bundle; failed pumps/watchers recover in-process, audit-policy drift is repaired, and Security-log rollover raises one deduplicated remediation alert |
| Domain blocking | Block individual domains or entire root domains via hosts file (`0.0.0.0` entries) |
| Domain purpose | Curated offline domain→purpose annotations ("Microsoft telemetry", "Akamai CDN", "Google Analytics") inline in the feed and on prompts |
| 24h sparkline | Per-root hourly hit rollup rendered as an inline activity sparkline |
| Temp allow | Allow a domain for 15 minutes / 1 hour / 8 hours, automatically reverted to blocked |
| Hide / hide root | Suppress domains from the activity feed, persistent across restarts |
| Advanced search | `field:value`, `!term`, and `field!=value` filters across all tables |
| Research links | Right-click any domain to open Google, VirusTotal, who.is, and more |

### FW Activity

| Feature | Description |
|---------|-------------|
| Live connections | PID-attributed TCP state/listeners via IPHLPAPI plus ETW packet endpoints that retain UDP and sub-two-second TCP flows |
| Group by app + search | Collapsible per-process grouping with a `field:value` search DSL (`port:443 country!=US`, `fw:threat`) |
| Service attribution | svchost-hosted connections show the responsible Windows service (SCM enumeration) |
| Blocked-connection watch | Security event log 5157/5152 detection feeds the consent broker |
| Listener exposure audit | Sort/filter TCP and UDP IPv4/IPv6 local binds with exact process path, service/package identity, active firewall profiles, and blanket/restricted/default inbound coverage; public/wildcard findings describe local policy only and never claim external reachability |
| Status overlay | Each connection shows blocked-by-hosts/firewall/threat, plus **DIRECT-IP** for raw-IP dials with no preceding DNS lookup |
| Quick blocking | Block any remote IP or program, block a resolved site through the hosts file, create a per-app DNS-following `HG_Domain_` firewall rule, or scope-block a program to Internet / LAN / localhost / inbound |
| Immediate flow close | Right-click an established IPv4 TCP row to close it now; opt in to **Close TCP on block** to close matching IPv4 TCP flows after IP, app, consent, or kill-switch blocks. IPv6 teardown is reported unsupported. |
| GeoIP + threat intel | Offline MMDB country/ASN resolution plus URLhaus/Feodo known-bad overlay |
| Connection history | Retention-bounded local traffic explorer with app, domain/host, IP, status, protocol, and time filters, CSV export, redacted traffic-profile export, clear-history, and 30-day default retention |
| History privacy | Per-app and domain-suffix exclusions keep live visibility, enforcement, and security alerts active while purging and suppressing passive DNS, connection, bandwidth, and usage history; configurable in the UI, CLI, and portable policy |
| First network activity | Optional, default-off alert for the first destination contacted by a new binary SHA-256 identity; stable first-seen persistence deduplicates repeats and treats a changed binary hash as a new version |
| Per-app bandwidth | Top-5 per-process bandwidth timeline via ETW kernel byte counters |
| Data usage rollups | Retention-bounded daily app x domain byte table with sent/received/total filters |
| Usage budget alerts | Optional local app/domain quota rules warn through the alert inbox when retained usage crosses a byte threshold; reset/export quota history without blocking or shaping traffic |
| Explain / look up connection | Right-click a connection to show the ordered hosts/firewall/trust/profile/kill-switch decision chain, or look it up on VirusTotal, who.is, Google, and AbuseIPDB |
| Learning review | Batch-promote, reverse, or discard Learning-mode auto-decisions |

### Hosts File

| Feature | Description |
|---------|-------------|
| Managed domains | Database-backed domain management with status, source, hit tracking, and canonical reasons |
| Raw editor | Direct editing of `drivers\etc\hosts` with clean-and-save (dedupe, validate, normalize) |
| Backup / restore | Timestamped hosts backups plus verified full-state recovery points covering SQLite, exact hosts content, and an explicit non-secret settings allowlist; restore is preview/SHA-bound, creates a pre-restore snapshot, and rolls back failed or interrupted startup application |
| Blocklist import | 12+ curated community blocklists (HaGezi, StevenBlack, OISD, URLhaus, ...) plus local-content import up to exactly 25,000,000 bytes; preview, enable/disable, source-scoped rollback, hosts/adblock-format diagnostics, source-health/churn guard checkpoints, allowlist-wins merge, per-source hits/30d stats, and exact NCSI probe warnings with list-only recovery that never overrides manual blocks |
| Allowlist subscriptions | Remote allowlists that whitelist domains and win over blocklists |
| Blocked services | One-click toggles to block YouTube, TikTok, Facebook, Discord, Netflix, and more |
| Telemetry preset | One-click block of ~28 Microsoft telemetry endpoints, reversible as a unit |
| Tamper watch | SHA-512 integrity tracking distinguishes HostsGuard's writes from external ones; optional auto-restore |

### FW Rules

| Feature | Description |
|---------|-------------|
| Full rule viewer | All Windows Firewall rules with name, direction, action, protocol, address, target kind, executable/package target, interface aliases, and report-only drift status |
| `HG_` prefix tracking | HostsGuard-created rules are identifiable and bulk-manageable, including DNS-following `HG_Domain_` per-app rules, `HG_LAN_*` attack-surface hardening rules, and `HG_VPNBind_*` interface-scoped app rules |
| UWP/MSIX package rules | Lists installed app-container packages and creates package-scoped allow/block rules by package family name or package SID, without changing hosts-file blocking defaults |
| Full-firewall drift baseline | Snapshots every Windows Firewall rule and ledgers when foreign rules appear, change, or vanish without auto-reverting non-HostsGuard rules |
| Rule effectiveness analysis | Read-only grouping of exact/semantic duplicates, allow/block overlaps, shadowed allows, inactive/disabled rules, and local-policy overrides; only selected exact-duplicate `HG_` rules can be removed after an unchanged analysis plus preview-hash guard, while foreign/policy rules remain review-only |
| Secure Rules guard | Opt-in tamper-guard: the service recreates or re-enables any `HG_` rule deleted or disabled behind its back; after three restores in ten minutes, only that rule is durably quarantined with live/tracked evidence until the operator accepts the foreign state or re-arms recovery (non-HostsGuard rules are never touched) |
| Orphan detection + rebind | Flags program rules whose executable moved and suggests signed identity matches with a preview before re-bind |
| Rule groups | Assign `HG_` rules to a named group and toggle the whole group on/off atomically; groups round-trip through the portable policy |
| Rule authoring | Create and edit `HG_` rules with direction, action, TCP/UDP local and remote port ranges, remote addresses, program/package target, enabled state, and live-validated interface aliases; the form previews the effective scope and portable policy preserves it |

### Tools

| Feature | Description |
|---------|-------------|
| DNS-bypass defenses | Block QUIC/UDP-443, block known DoH bootstrap resolvers, and DoT/DoQ port 853 (your own resolver exempt) so apps can't tunnel DNS past hosts blocking |
| LAN attack-surface hardening | One-click reversible cards block LLMNR, mDNS, NetBIOS-NS, SSDP/UPnP discovery, WPAD, and inbound SMB using registry-backed posture where Windows exposes it plus auditable `HG_LAN_*` firewall rules. Each card shows what may break before you turn it on. |
| CNAME-cloak guard | Opt-in reactive block of first-party hosts that resolve via CNAME to a blocked tracker |
| DNS resolver switcher | Select physical or explicit VPN/tunnel adapters, preview DHCP/static state, then apply Cloudflare/Google/Quad9 or DHCP transactionally; a bounded A+AAAA probe reports RTT or restores every adapter exactly |
| Resolver health matrix | Run read-only A+AAAA probes against every active adapter/resolver endpoint with UDP or configured DoH attribution, RTT, TLS/certificate state, and explicit unavailable/failure details; optional 15–1,440 minute schedules are off by default, non-overlapping, and never change DNS settings |
| DNS and HTTPS/SVCB inspector | Inspect Windows DNS Client cache entries or directly query a selected name through cancellable `DnsQueryEx`; decode priority, alias target, mandatory keys, ALPN, port, IPv4/IPv6 hints, ECH, DoH path, and bounded unknown parameters, while distinguishing DNS-advertised ECH from global, unattributable on-wire observations |
| Proxy/PAC tamper baseline | Compare every loaded user's WinINET proxy/PAC settings and the machine WinHTTP state with an explicitly accepted baseline; changes raise one redacted alert, credentials and PAC tokens never persist, and HostsGuard never rewrites the setting |
| IDN homograph alerts | Opt-in, alert-only comparison of observed IDNs against allowlisted, trusted, and recent domains using embedded Unicode 17.0.0 UTS #39 confusable data; Alerts shows decoded Unicode, punycode, scripts, restriction evidence, and the matching domain without auto-blocking |
| Algorithmic-domain alerts | Opt-in, alert-only scoring of suspicious registrable labels with exact entropy, vowel, digit, consonant-run, contribution, and threshold evidence; a versioned 57-case corpus gates precision at 95% and recall at 75%, while IDNs, CDN subdomains, and short labels are protected against false positives |
| DNS-tunneling burst alerts | Opt-in, alert-only rolling detection scores per-root/process/PID subdomain length and entropy, unique-query ratio, rate, and DNS record-type mix; 60-second state, five-minute cooldowns, 2,048 aggregate/256 observation caps, and CDN/telemetry regression fixtures keep it bounded and conservative |
| DoH intelligence | Refreshable, SHA-256-verified DoH resolver list merged with Windows known servers, plus ECH visibility posture that explains when SNI is hidden or not observable |
| Scheduled blocking | Block a domain, service, or **firewall rule** (`fw:` target) on a recurring weekly schedule (windows may cross midnight) |
| Network profiles | Save/switch named rule sets and auto-activate them with conjunctive gateway MAC, Wi-Fi SSID, interface, DNS suffix, VPN-presence, or legacy fingerprint rules; deterministic specificity precedence and portable-policy round trips preserve existing mappings |
| Captive portal recovery | Run a bounded read-only Windows NCSI check with redirects disabled and sanitized evidence; a suspected portal explicitly enables the existing 5/15/60-minute enforcement pause, which auto-resumes and is never activated by detection alone |
| Settings lock | Password-lock mode/posture/rule changes with an optional timed unlock; an armed password cannot be replaced without first proving it to disarm; 600,000-iteration PBKDF2-SHA256 verification uses a bounded, non-blocking retry throttle with one deduplicated security alert; unreadable state fails closed with an explicit administrator recovery path |
| Global outbound | Tray Block-all / Allow-all outbound posture selector plus timed 5/15/60 minute enforcement pause with auto-resume (no restart) |
| VPN kill-switch | Watch a chosen VPN adapter; force default-outbound Block on every profile whenever it drops so nothing leaks outside the tunnel, restored on reconnect (opt-in) |
| Per-app VPN binding | Bind a program to one adapter by blocking it on other active interfaces; default outbound posture and hosts-file blocks are unchanged, and bindings round-trip through portable policy |
| Loopback API | Opt-in (`HG_LOOPBACK_API=1`) token-authed `127.0.0.1` JSON-RPC/OpenAPI surface |
| Event webhooks | Opt-in signed HTTPS POST of engine events (`X-HG-Signature` HMAC-SHA256, bounded retries), configured via the loopback API with public-endpoint SSRF validation |
| Portable policy | Export/import a strictly validated, versioned JSON policy carrying domains, firewall posture, DNS-following domain-firewall intents, LAN attack-surface posture, per-app VPN bindings, usage-budget alert rules, schedules, profiles, consent trust sets, DNS privacy toggles, DoH intelligence, kill-switch intent, AI knowledge, user overrides, and webhook endpoint intent. Lock intent is reported but its password verifier stays machine-local, like AI API keys and webhook secrets. Duplicate/unknown fields and duplicate keyed rows are rejected before preview or mutation; optional HTTPS subscriptions preview diffs, pin the fetched SHA-256, keep auto-apply off by default, and roll back the latest subscription apply. |
| Defender exclusion helper | Handles the `HostsFileHijack` false positive when blocking Microsoft telemetry |
| Support bundle | Redacted diagnostic zip — config, DB integrity, logs, event history, firewall summary, and metadata-only traffic-profile JSON/CSV with Wireshark filter hints (no tokens, webhooks, packet payloads, private domains, or remote IPs) |
| Event taxonomy | Structured, filterable event ledger of every block, allow, firewall, consent, DNS, list, support, and policy action; browsable in WPF and CLI with redacted CSV export |
| Alert inbox | Stateful, low-volume security alerts with unread/read acknowledgement and per-type surface/log-only settings for identity drift, threat hits, hosts tamper, settings-lock failures, kill-switch, firewall drift, unknown networks, algorithmic domains, DNS-tunneling bursts, and blocked inbound scans across distinct local ports |
| Localization | System default, English, Spanish, German, and French are selectable from one canonical menu. Menus, dialogs, critical recovery flows, and all runtime ViewModel text use resources; the 1,755-key surface currently has 505 Spanish, 502 German, and 499 French translations, with honest English fallback and a non-regression ratchet rather than a false completeness claim |
| Rendered accessibility QA | Deterministic background WPF tests render 67 pairwise captures spanning empty/populated/loading/disconnected/error states, dark/light/simulated High Contrast, 90/100/125/150% scale, compact/default sizes, all primary tabs, nested Hosts tabs, and every Tools card; gates cover clipping, focus, live regions, names, grid headers, contrast, pixel detail, and capture completeness |

### CLI

```
HostsGuard.Cli status
HostsGuard.Cli block <domain> [reason]
HostsGuard.Cli allow <domain> [reason]
HostsGuard.Cli unblock <domain>
HostsGuard.Cli firewall-packages [--search text]
HostsGuard.Cli firewall-rule interfaces
HostsGuard.Cli firewall-rule create|edit --name Rule [--protocol tcp|udp] [--local-ports ports] [--remote-ports ports] [--interfaces alias,alias]
HostsGuard.Cli block-package <package-family-name|sid> [out|in]
HostsGuard.Cli allow-package <package-family-name|sid> [out|in]
HostsGuard.Cli unblock-package <package-family-name|sid> [out|in]
HostsGuard.Cli explain <domain|ip|process|exe> [--program path] [--port N] [--proto tcp|udp]
HostsGuard.Cli export [path.json]
HostsGuard.Cli export-policy [path.json]
HostsGuard.Cli import-policy [--preview] <path.json>
HostsGuard.Cli import-policy --restore-checkpoint
HostsGuard.Cli snapshot create
HostsGuard.Cli snapshot list
HostsGuard.Cli snapshot preview <snapshot-id>
HostsGuard.Cli snapshot restore <snapshot-id> --sha256 <previewed-sha256>
HostsGuard.Cli proxy status
HostsGuard.Cli proxy accept-baseline
HostsGuard.Cli idn-homograph [status|enable|disable]
HostsGuard.Cli dga-check <domain> [--json]
HostsGuard.Cli dns-inspect <domain> [--json]
HostsGuard.Cli resolver-health [--run] [--host name] [--schedule off|minutes] [--json]
HostsGuard.Cli profile-match [current|list|set|delete] [options] [--json]
HostsGuard.Cli captive-portal [--json] [--pause 5|15|60]
HostsGuard.Cli mode [normal|notify|learning]
HostsGuard.Cli secure-rules [status|enable|disable]
HostsGuard.Cli secure-rules accept|rearm <HG_rule_name>
HostsGuard.Cli events [--limit N] [--search text] [--category name] [--export events.csv]
HostsGuard.Cli listeners [--protocol tcp|udp] [--port N] [--process text] [--risk low|medium|high] [--export path.csv|path.json]
HostsGuard.Cli firewall-analyze [--kind name] [--remediation name] [--search text] [--export path.csv|path.json]
HostsGuard.Cli firewall-cleanup preview|apply --analysis-hash SHA256 [--preview-hash SHA256] --name HG_Rule
HostsGuard.Cli traffic-profile [profile.json|profile.csv] [--since ISO] [--until ISO] [--process app] [--action name] [--protocol tcp|udp]
HostsGuard.Cli support-bundle [--since ISO] [--until ISO] [--process app] [--action name] [--protocol tcp|udp]
HostsGuard.Cli usage [--days N] [--limit N] [--search text] [--app process] [--domain domain]
HostsGuard.Cli usage-quota [list|set|delete|reset|export]
HostsGuard.Cli dns-cache [--limit N] [--search text]
HostsGuard.Cli dns-flush-entry <cached-name>
HostsGuard.Cli blocklists [list|stats|refresh|preview|import|disable|enable|remove|rollback]
HostsGuard.Cli blocklists recover-connectivity [exact-ncsi-domain ...]
HostsGuard.Cli update check
HostsGuard.Cli update stage
HostsGuard.Cli update stage --path <feed-matching-installer.exe> [--sha256 <hash>]
HostsGuard.Cli update health --expected <version> [--timeout <seconds>]
HostsGuard.Cli safe-posture
HostsGuard.Cli safe-posture-smoke
HostsGuard.Cli release-smoke
```

The CLI talks to the service over the same authenticated pipe contract as the app, so it works unelevated too. Local update staging is an online-assisted path: the supplied file name, architecture, newer version, and streamed SHA-256 must match the current GitHub release metadata; `--sha256` is only an additional assertion and cannot authorize another executable. Before an upgrade replaces files, the installer must stop the service and create a versioned binary/SCM snapshot. It then requires the expected service version, matching database schema, and readable firewall/filtering posture without changing that posture. A failed check restores the previous version once; a healthy start removes the recovery state.

## Data locations

| Path | Purpose |
|------|---------|
| `%ProgramData%\HostsGuard\` | Policy state: `hostsguard.db` (SQLite WAL), consent state, DoH intelligence — DACL-locked to SYSTEM+Admins |
| `%APPDATA%\HostsGuard\` | Per-user UI settings (`config.json`: theme, UI scale) and logs |

## Building from source

```powershell
git clone https://github.com/SysAdminDoc/HostsGuard.git
cd HostsGuard
dotnet build HostsGuard.sln          # requires .NET 10 SDK
dotnet test HostsGuard.sln           # 1645 tests, no elevation needed
powershell -NoProfile -ExecutionPolicy Bypass -File tools\package-hygiene.ps1
                                      # fails on vulnerable or undeferred stale NuGet packages
powershell -NoProfile -ExecutionPolicy Bypass -File tools\release-version-gate.ps1
                                      # verifies source versions, rendered evidence, and published winget consistency
powershell -NoProfile -ExecutionPolicy Bypass -File tools\release-version-gate.ps1 -RequireArtifacts
                                      # release cut only: also requires current installers + winget hashes
powershell -NoProfile -ExecutionPolicy Bypass -File tools\visual-smoke.ps1
                                      # offscreen rendered WPF dark/light smoke
build\publish.ps1 -AllRuntimes       # app/service/CLI/migrator, including packaged dry-run smoke
                                      # single-file self-contained win-x64/win-arm64 -> dist\dotnet\<rid>\
winget install --id JRSoftware.InnoSetup -e
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer-dotnet.iss
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /DTargetRid=win-arm64 /DTargetArchitecturesAllowed=arm64 /DTargetInstallIn64BitMode=arm64 installer-dotnet.iss
# Produces installer_output/HostsGuard-v<version>-win-x64-dotnet-Setup.exe
#          installer_output/HostsGuard-v<version>-win-arm64-dotnet-Setup.exe
```

Solution layout: `HostsGuard.Core` (pure domain, no OS deps), `HostsGuard.Contracts` (gRPC protos), `HostsGuard.Windows` (Firewall COM / ETW / IPHLPAPI / ACL interop), `HostsGuard.Service` (elevated engine), `HostsGuard.App` (WPF UI), `HostsGuard.Cli`, `HostsGuard.Migrator`, plus per-project test suites under `tests/`.

## Security

The .NET engine pins its runtime and dependency posture:

- **Runtime servicing floor:** the solution targets **.NET 10 (LTS, supported to
  November 2028)** and builds resolve the latest servicing patch
  (`TargetLatestRuntimePatch`), so self-contained artifacts bundle a current
  runtime.
- **Dependency CVEs:** `dotnet list package --vulnerable --include-transitive`
  is kept clean. `tools\package-hygiene.ps1` is the local release ratchet: it
  fails on vulnerable packages, outdated direct packages, or new undeferred
  transitive drift while printing the current TraceEvent, SQLitePCLRaw,
  xUnit-runner, and UI-support deferral reasons with owner/version, observed
  version drift, rationale, and revisit trigger. The native SQLite bundle is pinned to `SQLitePCLRaw.bundle_e_sqlite3`
  3.0.3 to clear GHSA-2m69-gcr7-jv3q (CVE-2025-6965); Google.Protobuf ≥ 3.35
  carries the recursion-depth fix; the .NET 10 SDK prunes framework-provided
  transitives, retiring the old test-only 4.3.0 floors.
- **Elevated surface:** the LocalSystem service's data directory
  (`%ProgramData%\HostsGuard`) is DACL-locked to SYSTEM+Admins before any state
  file is written; client blocklist and webhook URLs pass an SSRF guard
  (non-HTTPS, loopback/RFC1918/link-local/CGNAT/ULA/metadata rejected) before
  the service dials them; the gRPC control pipe is ACL'd and per-session-token
  authenticated.
- **Portable policy boundaries:** exported policies intentionally omit AI API
  keys and webhook signing secrets while preserving non-secret policy intent,
  including endpoints, enabled state, learned knowledge, and override rows; an
  import reports the omitted secrets so they can be re-entered on the target
  machine.

Report vulnerabilities via a GitHub issue with the redacted support bundle
(Tools → **Export Support Bundle**).

## FAQ / Troubleshooting

**Q: Does the app need admin privileges?**
No. The UI and CLI run unelevated; all privileged work happens in the `HostsGuardSvc` LocalSystem service that the installer registers (installation itself elevates once).

**Q: I blocked a domain but it still resolves**
Use Tools -> DNS -> **Inspect domain** (or `HostsGuard.Cli dns-inspect <domain> [--json]`) to query and decode live HTTPS/SVCB service bindings. The result labels ECH advertised by that name separately from service-wide on-wire ECH observations, which cannot be attributed to a hidden domain. The **Windows resolver cache** panel loads cached names and can flush only the selected entry. Some applications maintain their own DNS cache separate from the OS; for those, use FW Activity -> **Block this site for this app (firewall)** after the site resolves to create a per-app `HG_Domain_` rule whose IP list follows later DNS answers. The DNS-bypass defenses (QUIC block, DoH blocklist) close the common tunnels, but remain opt-in.

**Q: How do I undo everything?**
Hosts File tab → **Restore** restores the most recent backup; **Emergency Reset** rewrites the hosts file to Windows defaults; FW Rules tab → **Delete HG Rules** removes all HostsGuard-created firewall rules. Uninstalling does all of this automatically and restores your prior firewall posture.

**Q: Windows Defender flags the hosts file as a threat**
Blocking Microsoft telemetry domains causes Defender to report `SettingsModifier:Win32/HostsFileHijack`. This is a false positive — HostsGuard is modifying the hosts file intentionally. Add an exclusion for `C:\Windows\System32\drivers\etc\hosts`; HostsGuard warns before importing lists that trigger this.

**Q: What happened to the Python version?**
HostsGuard v3.x was a Python/PySide6 application. It was retired in favor of this .NET 10 rewrite, which removes PowerShell subprocess shelling (typed Windows APIs instead), runtime-only error surfacing (compiled core), and the 127 MB PyInstaller bundle (small self-contained binaries + a real Windows Service). The final Python build is preserved at the `python-eol` tag, and `HostsGuard.Migrator` imports v3.x profiles.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contributing

Issues and PRs welcome. If reporting a bug, attach the redacted support bundle (Tools → **Export Support Bundle**).
