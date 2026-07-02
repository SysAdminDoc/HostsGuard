# Changelog

All notable changes to HostsGuard are documented in this file.

## [Unreleased]

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
