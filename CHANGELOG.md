# Changelog

All notable changes to HostsGuard are documented in this file.

## [Unreleased]

### Added — "decide later" review for Learning mode (NET-074)
- **Learning review** — Learning mode auto-allows and records; a new review
  panel (FW Activity) lists those auto-decisions (`HG_Learn_` rules) so prompt
  fatigue doesn't turn into silent permanent allows. Per row or in bulk:
  **Keep** promotes to a permanent consent allow, **Reverse** flips it to a
  permanent block, **Discard** removes it so the app prompts again next time.
  Little Snitch "Silent Mode" pattern; new Consent RPCs GetLearned /
  ReviewLearned (schema-lock updated deliberately).

### Added — svchost per-service attribution + per-service rules (NET-073)
- **Service attribution** — connections and consent prompts from service-hosted
  processes (svchost, dllhost) now show the responsible Windows service
  (SCM enumeration, no elevation needed; cached). New Service column in FW
  Activity (searchable via `service:`) and a Service row on the consent prompt.
- **Per-service rules** — when exactly one service owns the connection's PID,
  the consent prompt offers "Only the '<service>' service": the resulting HG_
  rule is scoped via the firewall COM serviceName, so blocking Dnscache no
  longer blocks everything else svchost hosts. The covering-rule check is
  service-aware (a Dnscache-scoped allow doesn't silence prompts for other
  services in the same process), rules list shows the service scope, and
  CreateRule accepts a service name. No Windows competitor does this cleanly.

### Added — group-by-app connections view + live search (NET-071)
- **FW Activity grouped view** — live connections now group under their owning
  process (collapsible per-app sections with connection counts; toggleable
  back to the flat list), the expected tree view requested across
  WFN/TinyWall/Fort. GeoIP country and THREAT status stay inline per row.
- **Live search** — the shared search DSL (`field:value`, `!term`,
  `field!=value`) now filters the live view as you type, with aliases
  (`app:`→process, `ip:`/`addr:`→remote, `proto:`→protocol, `status:`→fw),
  e.g. `port:443 country!=US` or `fw:threat`.

### Added — connection history + per-app bandwidth (NET-070)
- **Persistent connection history** — first sightings from the connection feed
  land in a new retention-bounded `conn_history` table (schema v6) with
  process, PID, protocol, remote endpoint, GeoIP country, and threat status.
  Queryable from FW Activity → History & bandwidth (substring search across
  process/remote/country), with a configurable retention policy (default 30
  days, clamped 1–365, pruned opportunistically). Nothing leaves the machine.
- **Per-app bandwidth timeline** — real byte counters via the ETW kernel
  NetworkTCPIP provider (TCP+UDP, IPv4+IPv6 send/recv, per PID — the
  GlassWire-style source, no packet capture), aggregated into per-process
  per-minute buckets and rendered as a top-5 polyline timeline with ↑sent/↓recv
  legend totals. Elevation-gated like the DNS monitor; the view says so when
  counters are inactive. New Monitoring RPCs: GetConnectionHistory,
  GetAppBandwidth, Get/SetHistorySettings (schema-lock updated deliberately).

### Changed — .NET 10 LTS migration (NET-081)
- **Solution retargeted from .NET 8 to .NET 10 (LTS)** ahead of the .NET 8
  end-of-support date (2026-11-10); .NET 10 is supported to November 2028. All
  19 projects now target `net10.0(-windows)`, C# 14, SDK pinned to 10.0.301
  (`rollForward: latestFeature`). The SDK's framework-provided package pruning
  retires the test-only System.Net.Http/System.Text.RegularExpressions CVE
  floors and the `System.IO.Pipes.AccessControl` reference (all in-box now).
  `X509Certificate.CreateFromSignedFile` is obsolete (SYSLIB0057) with no
  managed replacement for signed-PE signer extraction — suppressed locally at
  its two best-effort call sites. Full suite green, publish + release-smoke
  verified on runtime 10.0.9, vulnerable-package scan clean.

### Removed — Python implementation retired (v0.5.1)
- **Python codebase removed (NET-055, cutover part 1)** — the v3.17.0
  Python/PySide6 implementation (`hostsguard/`, `HostsGuard.py`,
  `test_hostsguard.py`, `HostsGuard.spec`, `installer.iss`, `requirements.txt`,
  `constraints.txt`, `runtime_hook_mp.py`, `version_info.txt`) is deleted from
  the tree. .NET 8 is the sole implementation going forward. The final Python
  build is preserved at the `python-eol` git tag for reference (it remains the
  NET-070 history/bandwidth reference and the parity oracle of record).
  `HostsGuard.Migrator` still imports Python-era profiles. README rewritten for
  the .NET build; no engine code changes.

### Added — .NET 8 engine v0.5.0 (DNS-bypass defenses + consent-prompt quality)
- **Accessibility pass on the consent prompt (NET-080)** — the focus-stealing,
  time-boxed consent window now carries AutomationProperties names on every
  control, explicit tab order, an assertive live-region on the threat banner,
  and lands keyboard/screen-reader focus on the Allow button; the UI-scale combo
  gained a name too. The headless WPF smoke asserts the accessible names.
- **Domain-purpose annotations (NET-078)** — a curated, offline domain→purpose
  map (Little Snitch Research Assistant style) labels known domains ("Microsoft
  telemetry", "Akamai CDN", "Google Analytics") in a new Purpose column on the
  Hosts Activity feed and inline on the consent prompt's resolved hostname.
  Longest-suffix match; unknown domains stay blank; no cloud lookup.
- **CNAME-cloak reactive blocking (NET-075)** — an opt-in guard blocks a
  first-party host that resolves via CNAME to a blocked tracker, defeating
  CNAME-cloaking without a DNS forwarder. The ETW DNS monitor now parses the
  resolution-completion event (3008) for the CNAME chain and is wired into the
  service — which also finally feeds the DNS activity feed and 24h sparkline
  with real data. New SetCnameCloak RPC + a Tools toggle; setting persists.
- **Secure Rules tamper-guard (NET-072)** — an opt-in guard (Tools tab) has the
  LocalSystem service recreate or re-enable any HostsGuard HG_ rule that gets
  deleted or disabled behind its back, restoring it from the tracked state and
  logging the revert. It only ever touches HostsGuard's own rules — the user's
  other firewall configuration is left alone. Modelled on Malwarebytes WFC's
  Secure Rules; the setting persists across restarts and reconciles on a timer.
- **Identity-bound rules + versioned-path handling (NET-069)** — the consent
  broker's covering-rule check now verifies the on-disk binary still matches the
  SHA-256/signer recorded when the rule was created, so a renamed impostor
  dropped at a whitelisted path is re-prompted instead of silently allowed. The
  rebind scanner gains a "same versioned app path" signal (via
  `AppPaths.NormalizeVersionedPath`) so an auto-updater that moves its binary to
  a new version directory is recognized as the same app.
- **Known-safe baseline (NET-068)** — essential Windows binaries (Update, Defender,
  kernel, LSA) are auto-allowed silently so Notify mode targets interesting
  traffic instead of burying the user in prompts for OS infrastructure.
  Deliberately excludes svchost.exe (needs per-service attribution). The baseline
  is inspectable and re-appliable over the pipe (GetBaseline/ApplyBaseline) and
  from a Tools-tab "Apply known-safe baseline" button.
- **Consent scope + duration selectors (NET-067)** — the prompt now offers scope
  checkboxes (this IP / this port / this protocol; whole-app by default) and a
  duration dropdown (Once 15 min / 1 hour / This session / Always). Rules are
  shaped and TTL-reaped accordingly: "always" writes a permanent rule, "session"
  survives until the service restarts, timed durations reap on the sweep. The
  legacy Allow/Block once/always buttons collapse into Allow/Block + duration.
- **Enriched consent prompt (NET-066)** — the ask-to-connect window now shows the
  remote's reverse-DNS hostname (resolved async, off-thread), GeoIP country, and
  the process's Authenticode signer, and raises a threat banner when the remote
  IP is on the threat-intelligence overlay. All best-effort; degrades gracefully
  when data is unavailable.
- **DoH-resolver bootstrap blocklist (NET-065)** — the curated blocklist catalog
  gains an "Encrypted DNS" category (HaGeZi DoH Servers + DoH/VPN/Proxy Bypass).
  Subscribing blocks the bootstrap domains that apps/browsers with hardcoded DoH
  resolvers use to skip the OS resolver and the hosts file. Auto-updates with the
  existing scheduled blocklist refresh; complements the DoH resolver-IP firewall
  intelligence.
- **Block QUIC / HTTP3 (NET-064)** — a Tools-tab toggle blocks outbound UDP/443
  via a `HG_QUIC_UDP443` firewall rule, forcing clients to fall back to TCP so
  DoH3 and general QUIC can't bypass hosts/SNI-based blocking. Opt-in, off by
  default, clean TCP fallback (no user-visible breakage). `GetDohStatus` now
  reports `quic_blocked`.

### Added — .NET 8 engine v0.4.0 (WFC parity, packaging, hardening)
- **WFC notification parity (WFCP-000..022)** — the reactive allow/block prompt
  on unruled connections, reaching feature parity with Malwarebytes Windows
  Firewall Control. Detection is the Security event **5157/5152** stream
  (`BlockedConnectionWatch` + `EventLogWatcher`, audit enabled via
  `AuditSetSystemPolicy` with an `auditpol` fallback) — the only user-mode
  signal for *blocked* connections, which the TCP-table poller structurally
  cannot see. NT device paths resolve to DOS paths via a cached
  `QueryDosDevice` mapper. The `ConsentBroker` dedups app+dir+remote+proto
  bursts, skips apps a live HG rule already covers, and per filtering **mode**
  either drops (Normal), auto-allows + records (Learning), or pushes a
  `ConnectionDecisionRequest` to the UI (Notify) with a 60 s pending TTL
  (timeout = stays blocked, recorded, no rule). Decisions write `HG_Consent_`
  permanent or `HG_Once_` reaped-after-15-min COM rules with identity
  remembered. A top-most themed **consent window** (Allow/Block × once/always,
  remote scoping, countdown) surfaces the prompt — a LocalSystem service cannot
  toast into a user session. Posture safety rails: arming Notify/Learning saves
  per-profile default-outbound and sets Block; returning to Normal *or stopping
  the service* restores the exact prior posture (mode persists to re-arm on
  restart). Tray mode switch, status-bar mode indicator, and a recent-decisions
  view with re-decide.
- **Phase 2 residuals** — hosts **backup restore** (guarded list + restore,
  traversal-safe), FW Activity per-app **connections-per-minute timeline**,
  orphan-rule **rebind** (identity-scored candidate scan + manual file-pick
  fallback), lockdown/learning/observe toggles (lockdown = per-profile
  default-outbound posture via `INetFwPolicy2`).
- **Packaging (NET-050/051/054)** — `build/publish.ps1` produces single-file
  self-contained win-x64 builds of service/app/cli gated by `release-smoke`;
  `installer-dotnet.iss` registers `HostsGuardSvc` (LocalSystem, auto-start,
  `depends= MpsSvc`, restart-on-failure) and unwinds it on uninstall
  (posture restore + HG_ rule removal). New `HostsGuard.Cli`:
  status/block/allow/unblock/export/mode over the pipe + `release-smoke`
  (runtime, deps, signing, service reachability) + `uninstall-cleanup`.
  Cross-session pipe/handshake ACLs (SYSTEM+Admins own, Authenticated Users
  connect, token authorizes) let the unelevated UI reach the LocalSystem
  service.
- **Hardening (NET-061/062/062b/063)** — seeded property/fuzz suite over the
  parsing + gRPC-boundary surface (which caught a missing RFC-1035 domain
  length cap). Security review remediation: the `%ProgramData%\HostsGuard`
  data dir is now DACL-locked to SYSTEM+Admins before any state file is
  created (was world-readable/plantable); client list URLs pass an **SSRF
  guard** (reject loopback/RFC1918/link-local/CGNAT/ULA/metadata, redirects
  refused) before the LocalSystem service fetches them; consent posture is
  restored on service stop. Per-profile posture restore, `HardenAcl`
  short-circuit, and single-reconcile allowlist reapply. Dependency CVE scan
  clean (native SQLite bundle 3.0.3 past GHSA-2m69-gcr7-jv3q; test-only 4.3.0
  transitives pinned). Observability: canonical `EventTaxonomy` + a redacted
  `diagnostics.json` (event counts by category, consent mode/posture) in the
  support bundle.
- **Per-domain 24h sparkline (NET-042)** — schema v5 `feed_hourly` rollup, a
  `GetSparkline` RPC, and an inline mini-polyline per Hosts Activity row.
- **367 .NET tests**; headless WPF smoke constructs every window in both
  themes; zero build warnings under warnings-as-errors.

### Added — .NET 8 restructure (engine v0.3.0)
- Began the C#/.NET 8 rewrite (`src/` + `tests/`, `HostsGuard.sln`) on a
  split-trust architecture: an elevated LocalSystem service owns all privileged
  mutation; the unelevated UI/CLI talk to it over gRPC on an ACL'd named pipe.
  The Python v3.x build (`hostsguard/`) is frozen as the parity reference.
- HostsGuard.Core: pure domain logic ported from Python (domains/TLD, hosts
  parse + idempotent clean, firewall-address + rule mapping, reason taxonomy,
  scheduling, search DSL, DNS normalization, redaction) — 124 tests.
- HostsGuard.Contracts: versioned gRPC contract (hostsguard.v1) with a schema-lock.
- HostsGuard.Ipc: gRPC over an ACL'd named pipe + per-session token auth
  (constant-time), verified end-to-end.
- HostsGuard.Windows: transactional hosts engine (atomic write + SHA-512
  self-write hash), native ACL hardening, INetFwPolicy2 COM firewall engine +
  shape-tolerant rule mapper, real-time FileSystemWatcher tamper watch + registry
  DataBasePath check, IPHLPAPI PID-attributed connection monitor, ETW DNS monitor
  (TraceEvent), firewall program-identity cache + orphan detection.
- HostsGuard.Data: SQLite (Microsoft.Data.Sqlite + Dapper) with schema v1 mapped
  from Python v7, legacy column-rename migration, data-preserving/allowlist-wins
  UPSERT.
- HostsGuard.Diagnostics: Serilog redacting sink (secrets never reach a sink).
- HostsGuard.Service: LocalSystem host wiring the engines to Diagnostics +
  HostsControl gRPC impls; end-to-end Block round-trip verified.
- HostsGuard.App: WPF service-client + MVVM Hosts ViewModel foundation (UI drives
  the service through the pipe).
- HostsGuard.App shell (NET-020): DI composition root, five-tab MainWindow
  (Hosts Activity / FW Activity / Hosts File / FW Rules / Tools), dark+light
  theme token dictionaries ported from the Python v3.14 palette with runtime
  switching, UI scale (90–150%) via LayoutTransform, tray icon with
  hide-to-tray, non-fatal service connection with status-bar health, and a
  config store that shares %APPDATA%\HostsGuard\config.json with the Python
  build while preserving Python-owned keys. Verified interactively: launches
  unelevated, renders all tabs, live theme toggle, correct "service
  unavailable" degradation.
- Hosts views (NET-021): contract grew TempAllow/ListTempAllows,
  GetHostsText/SetHostsText, HideRoot/UnhideRoot, and GetActivity (schema-lock
  updated deliberately). The service now hosts Monitoring streams over an
  in-process EventBus, records DNS sightings into the persistent feed, and runs
  a TempAllowScheduler: temp-allow windows persist in the DB (schema v2), the
  earliest expiry is timer-armed, expired windows revert on service restart,
  and a manual allow/block since the window opened wins over the auto-revert.
  The UI gained the live Hosts Activity tab (WatchDns stream + snapshot,
  status/search filters, hide-root, temp-allow 15m/1h/8h, research links,
  reason tooltips) and the Hosts File tab split into Managed Domains
  (status filter, bulk block/allow/remove, block-root) + Raw Editor
  (transactional save through the engine).
- Firewall views (NET-022): FirewallControl service impl on the COM engine
  behind a new IFirewallEngine seam — quick-block IP/program, custom rule
  creation with enforced HG_ prefix, HG_-only mutation guard (system rules can
  never be deleted/disabled through HostsGuard), fw_state drift tracking
  (deleted-behind-our-back rules surface flagged), orphan detection, and
  program-identity remembering on rule creation. A ConnectionFeed poller
  publishes IPHLPAPI connection sightings to WatchConnections streams. The UI
  gained FW Activity (live connection grid, quick-block remote IP / program,
  research links) and FW Rules (viewer with HostsGuard-only + text filters,
  enable/disable, delete, bulk delete, inline custom-rule form, ⚠ orphan/drift
  flags).
- Tools tab (NET-023): DnsControl impl (native DnsFlushResolverCache flush,
  per-adapter registry resolver switching with preset list, domain inspector
  with block-state), Policy schedules editor (validated HH:mm + day set,
  DB-persisted schema v3) enforced by a ScheduleEnforcer with overnight-window
  support and self-owned revert (manual blocks/whitelists always win), hosts
  backup + ACL re-hardening RPCs, and a redacted support-bundle export
  (status/events/rules/schedules zip; public IPs and secrets pass through the
  redaction pipeline). Contract grew ExportSupportBundle, BackupHosts, and
  HardenAcl.
- Destructive-action guardrails (NET-024): a shared IConfirm flow (port of the
  Python `_confirm`) now gates domain remove, bulk remove, firewall rule
  delete, bulk delete, and the new Emergency Reset button; view-model tests
  prove a declined confirm leaves state untouched on every path.
- Blocklist + allowlist engine (NET-030/031): new ListControl service with the
  25-source curated catalog (large-list ⚠ flags), https-only source validation,
  streaming byte-capped fetch (25 MB block / 5 MB allow), shared parse/dedupe,
  single-transaction bulk upsert (allowlist wins), subscription records with
  daily scheduled refresh, unsubscribe-keeps-domains, oversized-hosts
  DNS-Client CPU warning above 100k entries, import diff counts, and allowlist
  subscriptions that whitelist + unblock and re-apply after every import. UI
  gained a Blocklists view (catalog grid, import with large-list confirm,
  refresh-all, allowlist URL editor).
- Blocked services + telemetry preset (NET-032): one-click toggles for the 14
  curated service sets and the 28-endpoint Windows telemetry preset (Defender
  HostsFileHijack guidance surfaced before applying and in the ack). Toggles
  are self-owned: reverting only removes rows the toggle created, manual
  blocks keep their identity, and manual whitelists always win. Tools tab
  gained the service toggle grid. (Scheduled blocking itself shipped with the
  NET-023 enforcement engine.)
- DoH/DoT blocking (NET-033): BlockEncryptedDns now creates HG_DoH_IPs
  (resolver-IP block from the built-in + learned set) and HG_DoT_TCP/UDP
  (port 853) rules with the user's and the machine's own resolvers exempt;
  FwRule/COM engine grew remote-port support (protocol set before ports).
  DoH intelligence persists in doh_resolvers.json (schema parity with Python):
  refresh merges the Windows known-DoH-server registry list with an optional
  remote list gated on a required SHA-256 — any failure leaves prior state
  intact. Connections to known DoH resolvers on 443/853 are categorized
  "DoH/DoT" in the live feed (browser-DoH detection). Tools tab gained the
  encrypted-DNS toggle + intelligence refresh.
- Network profiles (NET-034): SaveProfile snapshots the managed-domain set,
  SwitchProfile replaces it and reconciles the hosts file to the profile's
  blocked set (an automatic "(previous)" snapshot is taken before every
  switch), DeleteProfile guarded by confirm in the UI. The machine-policy half
  of the old item is resolved by architecture: the service already owns all
  state in %ProgramData%\HostsGuard.
- i18n scaffolding (NET-037): I18n.T(key, english, args) backed by
  Resources/Strings.resx with safe missing-key fallback to the English default;
  shell connection strings route through it as the pattern. Future locales are
  satellite-assembly drops, no code changes.
- Defender integration (NET-036): one-click hosts-file exclusion through the
  WMI MSFT_MpPreference "Add" method (PowerShell-free), idempotent with typed
  unavailability errors, plus a revert-detection heuristic (hosts file empty of
  blocks while the DB expects them = the classic post-remediation signature)
  surfaced with HostsFileHijack guidance in the Tools tab.
- Threat intel + offline GeoIP (NET-035): Feodo Tracker IP overlay (persisted
  across restarts, empty-list refreshes rejected keeping the prior set) flags
  live connections as THREAT; DB-IP Lite country MMDB via MaxMind.Db feeds the
  FW Activity country column, memory-mapped, with a streaming download cap AND
  a gzip-expansion cap (Core GzipLimited, the `_gzip_decompress_limited` port),
  and corrupt downloads are probe-validated so they never replace a working
  database. Tools tab gained refresh buttons for both.
- Migrator (NET-053): HostsGuard.Migrator imports a Python-era profile
  (%APPDATA%\HostsGuard → %ProgramData%\HostsGuard) — hostsguard.db (legacy
  columns upgrade in place), config.json schedules / temp_allows / allowlist +
  blocklist subscriptions, doh_resolvers.json, and backups — with a --dry-run
  report, one-shot marker, and a never-overwrite guard on an existing target
  database. Verified against a real v3.x-shaped profile with zero data loss.
- 260 .NET tests; zero build warnings under warnings-as-errors.

## [v3.17.0] - 2026-07-02

### Fixed
- Hardened config persistence, remote feed ingestion, and local service request
  parsing: config now saves atomically with UTF-8 and per-thread temp files,
  remote hosts/threat/allowlist/GeoIP/favicons reads enforce size limits, and
  service requests reject negative `Content-Length` plus invalid `HG_PORT`
  values before starting elevated mutation work.
- Added confirmations for managed-domain removals and single firewall-rule
  deletion so context-menu destructive actions match the guarded bulk/reset
  flows.
- Aligned headless-service discovery metadata: `/openapi.json` now advertises
  the active `HG_PORT`, service startup copy lists the contract endpoint, and
  release metadata version strings are guarded by tests.
- Bounded GeoIP MMDB gzip decompression so compressed download size limits also
  cap expanded payloads before database files are written.

## [v3.16.0] - 2026-07-02

### Fixed
- Hardened packaged startup by running `multiprocessing.freeze_support()` before
  bootstrap/Qt imports, skipping runtime dependency installation inside frozen
  builds, and wiring a PyInstaller runtime hook for worker-process diversion.
- Added a pre-migration SQLite backup guard so existing policy databases are
  copied with SQLite's backup API before schema upgrades or legacy column-shape
  repairs; failed migrations now log the preserved backup path.
- Added a reviewed config import path that validates schema/domain/firewall/
  learning rows, previews counts and skipped entries before apply, creates a DB
  backup, and restores DB plus learning state on import failure.
- Replaced static-only DoH/DoT resolver blocking with refreshable resolver
  intelligence that merges Windows known DoH servers, requires SHA-256 for
  remote resolver lists, preserves the user's current DNS resolver exemption,
  reports source/last-updated status in Tools and `/status`, rolls back failed
  refreshes by leaving the previous state file intact, and recreates DoH/DoT
  firewall rules to avoid duplicates.
- Added canonical policy reasons for domain, feed, and event-log rows; Managed
  Domains and Event Log now expose reason filters, config/CLI/service exports
  include reason values, `/log?reason=<value>` filters service logs, and legacy
  rows are backfilled or rendered with inferred reasons.
- Hardened the localhost service contract with `/openapi.json`, validated
  `limit/since/action/reason` query parameters for `/log`, stable structured
  error bodies, explicit 1 MB POST body rejection instead of truncation, and
  schema-bearing mutation responses.
- Added identity-aware firewall program rebind suggestions for orphaned
  HostsGuard rules, using cached signer/product/original filename/SHA-256
  evidence plus bounded replacement-path scanning and a preview step before
  applying the new executable path.
- Added a redacted support bundle export in Tools that packages version/build
  diagnostics, sanitized config, SQLite integrity status, recent redacted logs,
  event history, firewall summary, hosts stats, dependency versions, and
  Windows Event Log entries when available.
- Added machine-wide policy drift handling: HostsGuard now detects user versus
  ProgramData policy files, reports active policy scope/owner/drift in Tools and
  support diagnostics, and can copy per-user policy DB/config/DoH intelligence
  into ProgramData with rollback protection while leaving portable mode unchanged.
- Added shared advanced search grammar across DNS activity, live connections,
  managed domains, firewall rules, and event log tables with `field:value`,
  `!term`, and `field!=value` filters plus inline placeholder examples.
- Added a persisted UI scale setting in Tools with 90/100/110/125/150 percent
  choices, wired through the shared `_dp()` sizing helper so fonts, tables,
  dialogs, and fixed-format controls scale consistently after restart.
- Added a checked `constraints.txt` release dependency set, constrained runtime
  bootstrap installs, bundled the constraints file into PyInstaller output, and
  exposed `release-smoke` to print the tested PySide6/psutil/maxminddb/
  PyInstaller versions before shipping.
- Hardened service event webhooks with optional `webhook_secret` HMAC signing,
  bounded retry/backoff/timeout controls, explicit disabled/invalid states, and
  retry/exhaustion delivery status in `hostsguard.log`; support bundles redact
  webhook secrets alongside URLs.
- Split the monolithic runtime into a `hostsguard/` package with a thin
  `HostsGuard.py` launcher, responsibility facade modules for core/firewall/
  network/service/UI code, and direct package-import tests instead of AST
  extraction.
- Added a localization-ready English string registry in `hostsguard/i18n.py`
  with safe missing-key/language fallback and routed the main app tabs plus
  primary Hosts, Firewall, and Tools labels/actions through `T(...)`.

### Verified
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 76 tests.
- Passed `py -3.12 -m py_compile HostsGuard.py test_hostsguard.py runtime_hook_mp.py`.
- Rebuilt the PyInstaller onedir artifact with `runtime_hook_mp.py` included.
- Passed `py -3.12 HostsGuard.py status` CLI smoke.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 78 tests after the
  migration-backup coverage was added.
- Rebuilt the PyInstaller onedir artifact after the migration-backup change.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 82 tests after import
  validation and rollback coverage was added.
- Passed `py -3.12 -m py_compile HostsGuard.py test_hostsguard.py runtime_hook_mp.py`
  and rebuilt the PyInstaller onedir artifact after the import change.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 90 tests after adding
  DoH resolver intelligence coverage.
- Passed `py -3.12 -m py_compile HostsGuard.py test_hostsguard.py runtime_hook_mp.py`,
  rebuilt the PyInstaller onedir artifact, and passed `py -3.12 HostsGuard.py status`
  after the DoH intelligence change.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 94 tests after adding
  canonical policy reason coverage.
- Passed `py -3.12 -m py_compile HostsGuard.py test_hostsguard.py runtime_hook_mp.py`,
  passed `py -3.12 HostsGuard.py status`, and rebuilt the PyInstaller onedir
  artifact after the reason-tracking change.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 99 tests after adding
  service contract coverage.
- Passed `py -3.12 -m py_compile HostsGuard.py test_hostsguard.py runtime_hook_mp.py`,
  passed `py -3.12 HostsGuard.py status`, and rebuilt the PyInstaller onedir
  artifact after the service-contract change.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 102 tests after adding
  firewall rebind scoring coverage.
- Passed `py -3.12 -m py_compile HostsGuard.py test_hostsguard.py runtime_hook_mp.py`
  after the firewall rebind change.
- Passed `py -3.12 HostsGuard.py status` and rebuilt the PyInstaller onedir
  artifact after the firewall rebind change.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 104 tests after adding
  support bundle redaction and zip payload coverage.
- Passed `py -3.12 -m py_compile HostsGuard.py test_hostsguard.py runtime_hook_mp.py`
  after the support bundle change.
- Passed `py -3.12 HostsGuard.py status` and rebuilt the PyInstaller onedir
  artifact after the support bundle change.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 107 tests after adding
  policy drift detection and ProgramData migration rollback coverage.
- Passed `py -3.12 -m py_compile HostsGuard.py test_hostsguard.py runtime_hook_mp.py`
  after the policy migration change.
- Passed `py -3.12 HostsGuard.py status` and rebuilt the PyInstaller onedir
  artifact after the policy migration change.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 110 tests after adding
  advanced search grammar parser/matcher coverage.
- Passed `py -3.12 -m py_compile HostsGuard.py test_hostsguard.py runtime_hook_mp.py`
  after the advanced search change.
- Passed `py -3.12 HostsGuard.py status` and rebuilt the PyInstaller onedir
  artifact after the advanced search change.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 112 tests after adding
  UI scale coercion coverage.
- Passed `py -3.12 -m py_compile HostsGuard.py test_hostsguard.py runtime_hook_mp.py`
  after the UI scale change.
- Passed `py -3.12 HostsGuard.py status` and rebuilt the PyInstaller onedir
  artifact after the UI scale change.
- Passed `py -3.12 -m pip install -r requirements.txt pyinstaller` using
  `constraints.txt`.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 114 tests after adding
  release constraint coverage.
- Passed `py -3.12 -m py_compile HostsGuard.py test_hostsguard.py runtime_hook_mp.py`,
  `py -3.12 HostsGuard.py status`, and `py -3.12 HostsGuard.py release-smoke`.
- Rebuilt the PyInstaller onedir artifact with `constraints.txt` bundled and
  passed the frozen `release-smoke` process exit check.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 118 tests after adding
  webhook delivery semantics coverage.
- Passed `py -3.12 -m py_compile HostsGuard.py test_hostsguard.py runtime_hook_mp.py`,
  `py -3.12 HostsGuard.py status`, and `py -3.12 HostsGuard.py release-smoke`
  after the webhook hardening change.
- Rebuilt the PyInstaller onedir artifact and passed the frozen `release-smoke`
  process exit check after the webhook hardening change.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 119 tests after the
  package split and direct-import test migration.
- Passed `py -3.12 -m py_compile HostsGuard.py hostsguard\__init__.py
  hostsguard\app.py hostsguard\core.py hostsguard\firewall.py
  hostsguard\network.py hostsguard\service.py hostsguard\ui.py
  test_hostsguard.py runtime_hook_mp.py`.
- Passed `py -3.12 HostsGuard.py status`, `py -3.12 HostsGuard.py release-smoke`,
  rebuilt the PyInstaller onedir artifact from the thin launcher, and passed the
  frozen `release-smoke` process exit check after the package split.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 122 tests after adding
  localization registry coverage.
- Passed `py -3.12 -m py_compile HostsGuard.py hostsguard\__init__.py
  hostsguard\app.py hostsguard\core.py hostsguard\firewall.py
  hostsguard\i18n.py hostsguard\network.py hostsguard\service.py
  hostsguard\ui.py test_hostsguard.py runtime_hook_mp.py`.
- Passed `py -3.12 HostsGuard.py status` and `py -3.12 HostsGuard.py release-smoke`
  after wiring the localization registry.
- Rebuilt the PyInstaller onedir artifact and passed the frozen `release-smoke`
  process exit check after the localization registry change.
- Bumped release metadata to v3.16.0 and re-verified 122 tests, py_compile,
  source CLI status/release-smoke, a clean PyInstaller onedir build, and the
  frozen `release-smoke` process exit check.

## [v3.15.0] - 2026-07-02

### Changed
- Elevated the PySide6 interface polish across the full app shell: branded header,
  clearer tab names, stronger dark/light focus states, consistent button/checkbox
  behavior, and deterministic no-pill radius treatment.
- Reworked prompts, confirmations, firewall-rule creation, empty states, loading
  overlays, toasts, and status labels so default, empty, error, disabled, and
  destructive flows read clearly and recoverably.
- Replaced fragile decorative glyph labels with readable text/status treatments,
  refreshed microcopy across hosts, firewall, blocklist, learning, backup, and
  DNS tools, and recaptured the README screenshot from rendered UI QA.
- Added Windows version metadata to the packaged executable so binary properties,
  installer metadata, and in-app version text report v3.15.0 consistently.

### Verified
- Rendered dark and light screenshots for Hosts Activity, Firewall Activity,
  Hosts File subtabs, Firewall Rules, Tools, domain prompts, and firewall-rule
  dialogs.
- Passed `py -3.12 -m pytest test_hostsguard.py -q` with 71 tests.

## [v3.14.1] - 2026-07-02

### Changed
- Hardened the Windows installer pipeline: the Inno Setup script now emits a
  versioned setup executable with explicit version metadata, setup logging, and
  close-application handling for upgrades.
- Documented the direct Inno Setup compiler path used on Windows systems where
  `iscc` is installed but not present on `PATH`.

## [v3.14.0] - 2026-07-02

### Changed
- Refined the shared PySide6 theme system with higher-contrast dark/light
  palettes, consistent focus states, normalized radii, stronger table/header
  styling, and flatter status badges.
- Added theme-aware table empty states and a clearer loading overlay so filtered,
  first-run, and background-loading states feel intentional instead of blank.
- Tightened workflow microcopy and accessibility metadata across search/filter
  controls, compact header controls, destructive confirmations, scheduled blocking,
  and the custom firewall-rule dialog.
- Fixed rendered Qt polish defects found during dark/light QA: compact button
  variants now receive deterministic theme styling, Tools tab section labels no
  longer expose accelerator underscores, the event-log action no longer clips,
  and connection-detail firewall actions use a readable two-row layout.

## [v3.13.0] - 2026-07-01

Feature release from the roadmap drain: encrypted-DNS blocking, one-click service
and telemetry presets, scheduled blocking, allowlist subscriptions, an expanded
service API, a mini monitor, and the PyQt5→PySide6 (LGPL) migration.

### Tests
- Added integration tests exercising the real `DB._migrate`/`_rename_legacy` against
  an on-disk legacy-schema database (recovers domains/log queries, idempotent, fresh
  DB) and the real `_parse_fw_rules` across single-object/list/list-valued-RA/missing-
  field/garbage JSON. Harness now AST-extracts the `DB` class and `FWR` too. 64 → 71.

### Changed
- Migrated the GUI from PyQt5 to PySide6 (LGPL). PyQt5 is GPLv3, which made
  the PyInstaller binary of this MIT-licensed app GPL-encumbered; PySide6 (LGPL)
  resolves the conflict, and PyQt5 has been maintenance-only since 2024-07.
  All tabs, dialogs, workers, and signals verified under PySide6; requirements,
  PyInstaller spec excludes, and docs updated accordingly.

### Security
- Headless service (`--service`) now requires auth by default. It runs elevated
  and mutates the hosts file, so the endpoint is no longer open when `HG_TOKEN`
  is unset — a 64-hex token is auto-generated and persisted to
  `%APPDATA%\HostsGuard\service_token` (0600), and every request must carry a
  matching `X-HG-Token` header (constant-time compare). Startup prints where to
  read the token.

### Fixed
- DNS Inspect now resolves CNAME targets that use DNS name-compression pointers
  instead of showing "(ptr)"; the parser threads the full packet + rdata offset
  through `_read_name` (which already handled pointers). Removed the dead
  `_parse_name_from`.

### Added
- Mini Monitor: a tray-toggled, draggable, always-on-top thumbnail showing live
  up/down rates and connection / blocked-today counts, fed by the existing
  bandwidth and connection workers. Double-click or re-toggle to dismiss.
- Service API expanded + webhooks: the JSON-RPC service adds authenticated
  `GET /stats` (blocked/allowed/feed/today + top-blocked + connection count) and
  `GET /log` (recent events). When `webhook_url` is set in config, blocked-domain
  and hosts-tamper events fire a best-effort JSON POST (service and GUI).
- Windows Telemetry one-click preset: Tools → DNS & Network has a "Block Windows
  Telemetry" toggle that blocks ~28 curated Microsoft telemetry endpoints via the
  hosts file (reversible as a unit, reflects state on open). Warns about Defender's
  HostsFileHijack alert before applying.
- Allowlist subscriptions: Hosts File → Blocklists has an "Allowlist Subscriptions"
  box — domains from the listed URLs are whitelisted (unblocked and kept out of the
  hosts file), and win over blocklists (the bulk UPSERT no longer downgrades a
  whitelisted domain to blocked; blocklist imports re-apply the DB allowlist). URLs
  persist in config and re-fetch on launch.
- Firewall orphaned-rule detection: HostsGuard program-block rules whose target
  executable no longer exists (silently stop enforcing after an app update moves
  the binary) are now flagged with a ⚠ in the FW Rules tab and counted in the
  status bar, with a right-click "Re-bind program…" action to point the rule at
  the new path. (Windows FW matches by path, so true hash-based identity isn't
  possible without WDAC/AppLocker; detect-and-rebind is the driver-free fix.)
- Scheduled blocking: Tools → "Scheduled Blocking…" opens an editor to block a
  domain or service on a recurring weekly schedule (weekday selection + start/end,
  windows may cross midnight). A minute-tick scheduler applies and reverts windows;
  it only reverts blocks it applied itself (source `schedule`), never a manual or
  blocklist block on the same domain. Schedules persist and re-arm on restart.
- Blocked Services: a Hosts File → Services tab with one-click toggles that block
  14 popular services (YouTube, TikTok, Facebook, Instagram, X, Reddit, Discord,
  Snapchat, Netflix, Twitch, WhatsApp, Telegram, LinkedIn, Pinterest) via curated
  hosts entries. Toggles apply/remove the domain set atomically, reflect actual
  hosts state on open, and are tagged `service:<name>` in the DB. Best-effort
  (exact hostnames, no wildcards); pairs with Block Encrypted DNS to prevent DoH
  bypass.
- Block Encrypted DNS (DoH/DoT): a Tools → DNS & Network toggle firewall-blocks
  known DoH resolver IPs and DoT/DoQ port 853 outbound so apps and browsers
  can't tunnel DNS past hosts-file blocking. The machine's own configured DNS
  resolver is exempted so the user's chosen DNS keeps working. The browser-DoH
  detector now offers to enable this in one click. Honest UI note: per-app DoH
  can't be fully closed without a driver/proxy.
- Large-hosts-file guard: importing a very large blocklist (HaGezi Ultimate,
  OISD, StevenBlack, HOSTShield Combined) or importing while the hosts file
  already exceeds 100k entries now warns about the Windows DNS Client CPU
  cost and offers the firewall-IP alternative before proceeding; a post-import
  note fires when the file crosses the threshold.

## [v3.12.0] - 2026-07-01

Deep engineering + correctness audit. HostsGuard could not start on any fresh
launch since v3.7.0; this release fixes that plus ~35 correctness, security,
data-integrity, theming, and performance issues.

### Fixed — startup / crashes
- App crashed at import on every launch (GUI, CLI, service) since v3.7.0:
  `C=_load_theme()` ran at module load but `load_cfg()` was defined further
  down the file (`NameError`). Config helpers moved above the theme block.
- Hide / Hide-root crashed the app: `DNSMonitor._seen` became an `OrderedDict`
  in v3.7.0 but two UI paths still called `.add()`.
- `QTimer.singleShot(0, …)` fired from plain worker threads never ran (no event
  dispatcher in those threads), so ~15 pieces of async feedback silently never
  happened: the Managed Domains first-load / Refresh overlay (stuck forever),
  DNS-inspect results, lockdown / DoH-check / DNS-switch / winsock / renew /
  ACL / upstream-restore toasts, Delete-All-HG completion, and the firewall
  profiles label. Added a queued-signal `ui_call()` GUI-thread bridge.

### Fixed — hosts file / persistence
- Legacy databases (pre schema-versioning: `date_added`/`hit_count`/`timestamp`
  columns) had every domains/log query fail silently → empty Managed Domains,
  empty CLI export, dead event log. Added an in-place `RENAME COLUMN` migration.
- `block`/`unblock`/`block_bulk` returned `None` when `flush=False`, so every
  blocklist import raised `TypeError` and Restore-from-DB always reported 0.
- The tamper watcher treated the app's own writes as external tampering (the
  suppress flag cleared microseconds after a write while the watcher polls every
  5 s); with auto-restore on this reverted the user's own edits. Replaced with
  SHA-512 self-write hash tracking.
- `clean_hosts` was not idempotent — every Clean & Save duplicated the Windows
  header and managed-by marker and doubled blank lines.
- `add_domain` used `INSERT OR REPLACE`, resetting the added-date and wiping
  notes/category on every re-block. Rewritten as a data-preserving UPSERT.
- Temp-allow entries persist with expiry and are re-armed (or reverted) on
  startup instead of leaking a permanent whitelist entry on exit.
- Emergency Reset now backs up the hosts file first.

### Fixed — firewall / connections
- Block-IP dialogs advertised ranges but rejected everything but a bare IP;
  now accept single IP / CIDR / dash range with proper validation.
- Lockdown toggle claimed success even when the firewall policy change failed.
- DHCP Renew used `&&` (a parse error in Windows PowerShell 5.1) and did nothing.
- New/Duplicate rule dialogs accepted empty names and unvalidated addresses.
- Connection history used time-of-day-only timestamps (broke pruning and
  cross-day ordering) and re-inserted open connections every 2 s (unbounded
  growth). Now full ISO timestamps, recorded once per connection.

### Fixed — service / CLI
- JSON-RPC service hardened: optional `HG_TOKEN` bearer auth (the endpoint
  mutates the hosts file from an elevated process), `ThreadingHTTPServer`,
  POST restricted to `/domains`, malformed bodies return 400, JSON errors.
- UAC elevation relaunch dropped all argv (`--portable`/`--service`/CLI verbs
  were lost); the console-hide hid the user's own terminal. Both fixed.
- CLI no longer auto-elevates (which lost output) or kills a running GUI;
  reports write failures and admin requirements clearly.

### Fixed — theming / UX (light theme had baked-in dark values)
- Alternating rows, gridlines, header hairlines, selected-tab tint, selection
  text color, stat cards, loading scrim, blocked-row tint, and the bandwidth
  chart palette were all hardcoded dark values — now theme-token derived.
- Hits columns sorted lexicographically (`9` after `100`) — now numeric.
- Search boxes debounced with clear buttons; table keyboard focus is visible.
- Theme toggle offers an immediate restart.

### Fixed — performance / thread safety / data integrity
- Blocklist imports committed one transaction per domain (100k+ WAL fsyncs on
  large lists); added a single-transaction `add_domains_bulk`.
- GeoIP and favicon lookups negative-cache misses (unknown IPs / unreachable
  domains were re-queued on every scan).
- `DNSMonitor._seen` (shared GUI/monitor thread) now fully locked.
- Switching network profiles auto-saves the outgoing profile and reconciles the
  hosts file to the new profile exactly (previously accumulated every profile's
  entries and could lose unsaved edits).
- Connection history / event log auto-pruned on startup; threat intel refreshes
  every 6 h; Windows event source is registered on first use.

### Tests
- Test harness now extracts the real functions from source via `ast` instead of
  hand-copying them (no more drift). 44 → 64 tests with regression coverage.

## [v3.11.0]
- Trust-chain restore from StevenBlack upstream; headless service JSON-RPC;
  network profiles; per-app bandwidth chart; hosts ACL hardening.

## [v3.10.0]
- Auto-restore on tamper; Windows Event Log integration; SHA-512 integrity +
  registry DataBasePath tamper detection; DNS response inspection.
