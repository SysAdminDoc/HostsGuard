# Changelog

All notable changes to HostsGuard are documented in this file.

## [0.12.140] - 2026-07-14

### Added
- Tools health now lists read-only Hyper-V firewall coverage by Windows VM
  creator ID, including effective VM/profile defaults, host-rule merge,
  local-rule merge, and loopback state.

### Changed
- Hyper-V diagnostics explicitly report unsupported cmdlets and the Windows
  guest-attribution boundary; HostsGuard does not claim inner-WSL process
  identity and never changes Hyper-V firewall policy from this surface.

## [0.12.139] - 2026-07-14

### Added
- Remote blocklist subscriptions can keep up to five ordered HTTPS fallback
  mirrors through the desktop editor, CLI, RPC contract, and portable policy.
- Source health now records the endpoint selected by the latest successful
  fetch and its latency; the Blocklists table and CLI expose both.

### Changed
- Mirrors receive the same DNS-rebinding-resistant SSRF checks as primary list
  fetches. Refresh stops at the first successful endpoint, never merges
  divergent mirror payloads, and preserves the last applied domains when every
  endpoint fails.
- The database advances to schema 39 with additive mirror and fetch-provenance
  fields on blocklist subscriptions.

## [0.12.138] - 2026-07-14

### Added
- Every newly persisted block decision now carries a deciding source identity,
  such as its managed-domain source, blocklist, firewall/WFP rule, schedule,
  command rule, or quota.
- The event ledger can search and filter deciding sources and shows them in the
  desktop table, CLI output, and redacted CSV exports.

### Changed
- The event database advances to schema 38 with an additive
  `log.matched_source` column; existing event rows remain readable.

## [0.12.137] - 2026-07-14

### Added
- The Hosts Activity inspector now shows the latest observed DNS resolution
  path from the original query through ordered CNAME aliases to A/AAAA answers.
- Each domain hop shows its current managed verdict and reference-blocklist
  memberships, making CNAME-cloak decisions directly explainable.

### Changed
- Resolution chains persist through the existing bounded asynchronous activity
  writer, so ETW callbacks stay non-blocking and the latest chain survives a
  service restart.

## [0.12.136] - 2026-07-14

### Added
- The Hosts File workspace now has a Local redirects page for pinning a domain
  to a unicast IPv4/IPv6 address, reviewing managed pins, and removing them.
- Intentional pins persist in their own schema, round-trip through portable
  policy, and carry an exact HostsGuard marker in the Windows hosts file.

### Changed
- Hosts-file adoption exempts only the persisted domain/address pair from
  redirect-tamper alerts, restores a drifted managed pin, and continues to flag
  untracked or address-changed redirects. Blocking a pinned domain removes the
  pin so block and redirect intent cannot conflict.

## [0.12.135] - 2026-07-14

### Added
- The Blocklists page can now select a bounded UTF-8 hosts/adblock file, preview
  parsed/new/invalid counts without mutation, and import the exact confirmed
  bytes as a durable, non-refreshable `local:` source through the existing RPC.

### Changed
- Local-content RPCs now reject malformed UTF-8 explicitly instead of replacing
  invalid bytes; the app reports empty, unreadable, over-25-MB, and encoding
  failures before any hosts-file mutation.

## [0.12.134] - 2026-07-14

### Changed
- The write-only DeepSeek API-key field now shows a localized watermark and a
  service-backed stored/not-stored indicator, including clear guidance that a
  blank field preserves an existing key while a new value replaces it.
- Corrupt-database recovery and staged startup restore now operate only on their
  own disposed non-pooled handle instead of clearing process-wide SQLite pools
  and interrupting unrelated live databases.

## [0.12.133] - 2026-07-14

### Added
- The tray now has a localized Profiles submenu that refreshes saved profiles
  whenever it opens, checks the active profile, and switches through the same
  guarded workflow used by the Tools page.
- Profile items stay open while switching; pending clicks are disabled and
  settings-lock, service, cancellation, and success outcomes remain visible in
  the submenu. External profile changes appear on the next tray open.

## [0.12.132] - 2026-07-14

### Changed
- Service/RPC failures, release-update outcomes, dates, asset plurals and sizes,
  default file-dialog filters, RDP fallback evidence, and firewall-rule counts
  now resolve through localized resources in English, Spanish, German, and French.
- Localization gates now scan every app service and view model, recognize
  multiline resource calls, and exercise interpolation, plural, date, fallback,
  and pseudo-locale behavior.

## [0.12.131] - 2026-07-14

### Changed
- The connected shell now exposes core posture and live feeds before loading
  inactive tabs; each major tab hydrates on first activation.
- Independent service reads share a four-request concurrency bound, optional
  surface failures remain local, and reconnect cancels stale generations
  without letting their cleanup blank the current session.

## [0.12.130] - 2026-07-14

### Changed
- CLI root dispatch now uses one exhaustive command catalog with canonical
  alias handling and startup validation that every public verb has a handler.
- Pipe/RPC failures, portable-policy file access, request construction, and
  retry timing now have injectable contracts and a dedicated headless CLI test
  lane covering exit codes, help/invalid forms, file failures, and RPC mapping.

## [0.12.129] - 2026-07-14

### Added
- Connection-consent prompts now show the local endpoint and, when Windows
  supplies them, the network interface, active firewall profiles, and WFP
  filter owner/origin alongside the remote endpoint and protocol.
- Optional evidence rows collapse when unavailable and expose localized
  screen-reader names; IPv6 endpoints use unambiguous bracketed formatting.

## [0.12.128] - 2026-07-14

### Fixed
- Address columns in live firewall activity, consent decisions, listener
  exposure, connection history, and firewall rules now sort IPv4 numerically
  and IPv6 by normalized bytes and numeric scope ID.
- Ascending address order consistently places `Any`, then `LocalSubnet`, then
  IPv4/IPv6; non-address rule specifications remain visible and sort last.

## [0.12.127] - 2026-07-14

### Changed
- A shared injectable service clock now drives consent cache and rule expiry,
  temporary allow/block windows, enforcement pause, scheduled rules, resolver
  and DoH caches, intelligence staleness, usage windows, and status uptime.
- Production behavior still defaults to the system clock; focused tests now
  advance an in-memory clock across exact TTL boundaries without wall-clock
  sleeps.

## [0.12.126] - 2026-07-14

### Added
- Successful threat-intelligence refreshes now re-scan up to 10,000 retained
  connections from the last 30 days and raise one alert-only finding for each
  newly matching IP.

### Security
- Retrospective scans reapply current app/domain privacy exclusions at query
  time, honor the shorter configured retention period, and never create a
  firewall rule.
- Indicator findings deduplicate durably across repeated refreshes and alert
  acknowledgement, preventing reviewed history from returning as inbox noise.

## [0.12.125] - 2026-07-14

### Added
- Read-only Windows Terminal Services inventory now exposes active and
  24-hour recently disconnected Remote Desktop sessions, sanitized client/IP
  evidence, observation health, and timestamps through service and CLI status.
- Newly observed active RDP sessions create one coalesced local alert; quick
  reconnects do not produce duplicate inbox noise and no posture changes occur.

### Changed
- Connection-filtering, block-all, VPN kill-switch, and saved-profile changes
  now include an explicit RDP lockout warning while a remote session is active.
  Operators can still confirm the change; unavailable WTS observation is shown
  as unknown instead of being misreported as no remote session.

### Fixed
- Parallel test teardown no longer clears every process-wide SQLite pool after
  disposing a non-pooled fixture connection, eliminating an intermittent
  cross-fixture `SqliteConnection.Dispose` null-reference race.

## [0.12.124] - 2026-07-14

### Changed
- Direct Microsoft runtime, data, dependency-injection, and Windows packages
  now share the 10.0.10 servicing baseline.
- All eight test projects now use `Microsoft.NET.Test.Sdk` 18.8.1; dependency
  hygiene reports no vulnerable or outdated direct packages.

## [0.12.123] - 2026-07-14

### Added
- Uninstall now defaults to retaining local state for reinstall and offers an
  explicit purge of both `%ProgramData%\HostsGuard` and `%APPDATA%\HostsGuard`;
  silent runs use deterministic `/RETAINLOCALDATA` and `/PURGELOCALDATA`
  switches.

### Security
- Purge accepts no caller-selected paths, validates the exact canonical data
  roots, and removes directory reparse points without traversing their targets.
- Locked files are scheduled for deletion at the next Windows restart, with a
  distinct CLI result, uninstall-log entry, and restart notification.

## [0.12.122] - 2026-07-14

### Security
- Control-pipe reverse authentication now fails closed when the connected
  object's owner is missing, invalid, inaccessible, untrusted, or cannot be
  probed, instead of treating indeterminate ownership as trusted.
- Owner probes return typed outcomes for current-user development and approved
  Windows service identities; rejected connections use stable token-free error
  codes and dispose the stream before it can carry a gRPC request.

## [0.12.121] - 2026-07-14

### Security
- Portable-policy exports retain settings-lock intent but never include or
  transfer its PBKDF2 verifier. Legacy v1 verifier fields are validated,
  scrubbed, and reported as omitted while the destination lock stays local.
- Policy parsing now rejects duplicate JSON properties, unknown fields,
  unsupported or nonpositive versions, null keyed rows, and duplicate domain,
  firewall-rule, profile, source, and other persisted identities before preview
  or mutation.

### Changed
- Import previews and results put the credential-omission notice first so both
  the CLI and bounded WPF summaries tell operators to configure a local lock.

## [0.12.120] - 2026-07-14

### Fixed
- Every published service RPC now has an explicit read-only, protective, or
  lock-protected classification, and every lock-protected handler enforces the
  same service-side gate before validation or mutation.
- Settings lock now covers previously bypassable firewall, DNS, consent,
  recovery, monitoring, list, hosts, and policy changes, including direct rule
  toggles, encrypted-DNS/QUIC unblocks, flow teardown, and Secure Rules state.

### Changed
- Posture-strengthening emergency actions such as IP/QUIC blocks and hosts-file
  ACL hardening remain available while locked; a contract-completeness test now
  fails when any future RPC lacks a classification or required gate.

## [0.12.119] - 2026-07-14

### Fixed
- An armed settings-lock password can no longer be replaced through a second
  `enable` request; changing it now requires disarming with the current password
  before a new verifier can be set.
- Corrupt, unreadable, or unsupported lock state now fails closed and surfaces a
  critical recovery alert instead of silently becoming unlocked.

### Added
- Wrong unlock/disable attempts share a memory-only exponential retry budget
  capped at 30 seconds. Verification returns immediately while throttled, raises
  one deduplicated security alert after three failures, and resets on success or
  after a quiet recovery window without creating a permanent lockout.
- Lock status exposes degraded state, failure count, and safe retry timing so the
  Tools surface can explain recovery without exposing verifier material.

## [0.12.118] - 2026-07-14

### Added
- Secure Rules now quarantines only the conflicting `HG_` rule after three
  successful restores in a rolling ten-minute window, persists live/tracked
  evidence, and raises one surfaced critical alert while unrelated rules keep
  reconciling.
- Tools and the `secure-rules` CLI expose quarantined conflicts with confirmed
  actions to accept foreign state or re-arm immediate tracked-state recovery.

### Changed
- Expiring per-rule restore counters are capped in memory, and quarantine state
  survives service restarts until an operator resolves it.

## [0.12.117] - 2026-07-14

### Changed
- Blocklist and IP-list removal/rollback, full-state restore staging, and app
  VPN unbind now share one themed confirmation contract that names the exact
  target and consequence and defaults to cancel.
- Full-state restore confirmation retains the verified preview/hash,
  pre-restore recovery point, and automatic validation rollback safeguards.

### Added
- Decline/accept integration coverage proves that every newly guarded mutation
  performs no RPC when cancelled and proceeds only after confirmation.

## [0.12.116] - 2026-07-14

### Changed
- The status rail and bottom status bar now distinguish disconnected, loading,
  and live service state instead of displaying default or stale posture values.
- Service-backed filtering, global-posture, pause, diagnostics, DNS, and alert
  actions are disabled while offline and expose a reconnect explanation to
  tooltips and assistive technology.

### Fixed
- Reconnect now clears stale alert and posture presentation before hydrating
  the replacement client; live values and command availability return after
  the service connection succeeds.

## [0.12.115] - 2026-07-14

### Added
- The running WPF app now follows Windows contrast mode and live palette
  changes through system-color resources, including native title-bar behavior.
- Charts use stable dash patterns in addition to color, and validation errors
  retain a visible border plus glyph.

### Changed
- Disabled controls use the system disabled-text color instead of reduced
  opacity. Data-grid selection remains distinguishable by weight and focus
  borders without obscuring semantic status text.
- The release visual gate now renders every primary page in deterministic
  Aquatic, Desert, Dusk, and Night Sky fixtures as well as dark and light.

### Fixed
- Hovered menus, buttons, combo boxes, check boxes, tab content, and selected
  data-grid text no longer lose contrast when system colors collapse semantic
  accent colors.
- The singleton state database no longer joins SQLite's process-wide connection
  pool, preventing unrelated pool cleanup from racing its shutdown.

## [0.12.114] - 2026-07-14

### Added
- DNS ETW, kernel-network ETW, and Security-log observation sources now expose
  healthy/degraded/unavailable state with cumulative loss, gap, and restart
  counters plus the current incomplete interval in service diagnostics, CLI
  status, support bundles, and the Tools health table.
- DNS and firewall activity feeds now retain a live evidence-incomplete warning
  instead of presenting partial intervals as complete.

### Fixed
- Failed ETW pumps and Security-log subscriptions restart inside the running
  service. WFP audit-policy drift is detected and repaired, while Security-log
  rollover and audit loss create deduplicated alerts with remediation.

## [0.12.113] - 2026-07-14

### Fixed
- In-place updates now stop-and-wait before file replacement and preserve a
  versioned snapshot of the previous binaries plus SCM path, account,
  dependencies, description, start/error modes, and recovery actions.
- Installer service commands now check their exit codes. The new service must
  start at the exact expected version with a matching database schema and
  readable firewall/filtering posture; this health probe is read-only, so an
  upgrade no longer resets the user's network posture.
- A failed registration, start, or health check invokes the out-of-tree helper
  once to restore the previous files and service configuration, restart that
  version, and log the rollback result. Healthy startup logs success and clears
  the attempt, launched manifest, helper, and backup.

## [0.12.112] - 2026-07-14

### Security
- New settings-lock passwords now use 600,000 PBKDF2-HMAC-SHA256 iterations.
  A successful unlock transparently replaces legacy 210,000-iteration hashes.
- Persisted and portable-policy lock hashes now require the known encoding,
  210,000–600,000 iterations, a 16-byte salt, and a 32-byte output. Oversized
  or attacker-selected work/output parameters are rejected before policy
  checkpoints or machine-state mutation.

## [0.12.111] - 2026-07-14

### Fixed
- Local blocklist content now has a service-specific gRPC receive ceiling with
  bounded protobuf-envelope headroom, so the documented 25,000,000-byte handler
  limit is reachable over the named pipe. Real transport tests accept 4 MiB + 1
  and exactly 25,000,000 content bytes, return `content_too_large` for
  25,000,001, and prove other services retain gRPC's 4 MiB default.

## [0.12.110] - 2026-07-14

### Fixed
- Release visual smoke no longer captures a disconnected overlay six times while
  claiming page coverage. It now uses a deterministic connected/populated shell,
  asserts the selected page's named landmark, records a SHA-256 for each capture,
  fails duplicate primary-page pixels, and captures disconnected recovery as a
  separate state.
- Visual smoke refuses stale app or service binaries before launching, and the
  release gate requires matching binary metadata plus the complete landmark/hash
  evidence for dark and light themes.

### Changed
- Refreshed the dark/light Hosts Activity screenshots from the connected fixture
  and advanced the visual evidence manifest to schema 3.

## [0.12.109] - 2026-07-14

### Fixed
- The documented Python-profile migrator now ships as a matching-version,
  self-contained x64/ARM64 artifact and is included under the installer's
  `migrator` directory. Publishing runs the actual packaged executable against a
  legacy SQLite/config fixture and proves `--dry-run` reports two domains and
  expected config state without creating the target directory.
- Migration previews now count legacy database domains through a read-only
  connection instead of incorrectly reporting zero.

### Changed
- The release gate now rejects missing or stale-version migrator artifacts and
  rejects an installer definition that omits the runtime-specific migrator.

## [0.12.108] - 2026-07-14

### Security
- Local update staging now fails closed unless the caller-supplied installer's
  exact release name, architecture, newer version, and streamed SHA-256 match the
  GitHub release feed. An optional caller hash is only an additional assertion;
  it can no longer act as the trust anchor for an arbitrary executable later
  launched by the LocalSystem service. Oversized, stale, renamed, mismatched, and
  feed-unavailable inputs leave no new pending update.

## [0.12.107] - 2026-07-14

### Fixed
- The header no longer reassures with a green "Safe posture" when it isn't true:
  the shield/label now reflect real posture — green "Safe posture" only when
  connected and enforcement is active, muted "Paused"/"Suspended" when paused, and
  "Service offline" when disconnected. The rail service-health value renders red
  "Disconnected" instead of a misleading green.
- Localized the always-on status-bar counters (Hosts file / Blocked / Allowed /
  service version), the FW Activity Site-column tooltip, and the settings-lock
  password watermark — previously hardcoded English that satellites couldn't
  translate.

### Changed
- Consent-prompt scope/trust checkbox labels ("This IP", "This port", "Trust all
  software signed by…") now render in full-contrast body text instead of muted
  secondary text, strengthening the most security-critical modal.
- The disconnected-state Reconnect button — the only recovery path when the
  workbench is disabled — is now the accented primary action.

## [0.12.106] - 2026-07-14

### Fixed
- The hosts-file writer now registers its own-write hash before the atomic rename,
  closing a race where the tamper watcher could fire a spurious critical
  `hosts_tamper` alert (or an unnecessary adopt/organize rewrite) for the service's
  own block/import writes.
- IP-blocklist import no longer reports full enforcement when some firewall rule
  chunks fail to apply: it counts what actually applied, surfaces a warning, marks
  the source health `degraded`, and logs it as `ip_blocklist_partial`.
- Extending a temp-block window now preserves the original prior state instead of
  capturing the transient "blocked" state (which could leave a domain permanently
  blocked after revert). Both temp-block and temp-allow now perform their whole
  read-mutate-persist sequence under the scheduler gate, fixing a race with the
  revert sweep.
- `HostsEngine.Backup` copies under the write gate so a backup can't capture a
  torn in-flight rename or silently fail on a sharing violation.

### Changed
- `ServiceState.ShutdownToken` is captured at construction, so background work that
  reads it after disposal gets the already-cancelled token instead of an
  `ObjectDisposedException`. Removed a dead public-suffix branch in `Domains.GetRoot`.

## [0.12.105] - 2026-07-14

### Security
- The AI categorization endpoint is now SSRF-guarded end to end: the completer
  dials only public addresses at connect time (blocking loopback/metadata/private
  even via DNS rebind), `SetAiConfig` rejects non-public-https endpoints, and an
  imported (untrusted) portable policy can no longer silently repoint the
  Bearer-authenticated endpoint at a private/metadata host to exfiltrate the
  stored API key — it keeps the current endpoint and warns.
- The IP-blocklist parser now folds IPv4-mapped IPv6 addresses (e.g.
  `::ffff:192.168.1.1`) before its safety checks, so a hostile list can no longer
  smuggle a LAN/loopback target into an outbound firewall block rule; it also
  refuses CGNAT (`100.64/10`) and `0.0.0.0/8`, and masks CIDR host bits to the
  network address (`1.2.3.4/24` → `1.2.3.0/24`) so equivalent networks dedupe.
- Log/diagnostics redaction now scrubs provider API keys (`sk-…`, `gh*_`, `xox*`)
  and JWTs from free-form text, not just long hex.
- The loopback API compares fixed-size SHA-256 digests of the token so neither the
  auth outcome nor the token length is observable through timing.

### Fixed
- Renamed 38 resource keys whose names carried double-encoded UTF-8 mojibake
  (e.g. `Xaml_Normal_â_enforce_silently_…`) to clean ASCII across `Strings.resx`
  and `MainWindow.xaml`, and added an I18n guard test that fails if any resx key
  name contains a non-ASCII character. Displayed values were already correct.

## [0.12.103] - 2026-07-14

### Added
- Portable-policy JSON Schema and offline validator: a Draft 2020-12 schema is
  generated from the `PortablePolicy` model (so it can never drift), and a new
  `HostsGuard.Cli validate-policy <path>` command validates a document without a
  running service, reporting each error at its exact JSON Pointer path
  (e.g. `/Domains/0`). `validate-policy --emit-schema [path]` publishes the schema.

## [0.12.102] - 2026-07-14

### Added
- Import a blocklist from a local hosts/adblock file offline: new
  `PreviewBlocklistContent`/`ImportBlocklistContent` RPCs take client-supplied
  UTF-8 bytes (bounded to the 25 MB list cap, never a LocalSystem path) and reuse
  the existing parse/checkpoint/apply/allowlist machinery. Locally-imported
  sources use a non-fetchable `local:` URL so scheduled refresh skips them, while
  remove/rollback still target only that source. New CLI
  `blocklists preview-file|import-file <name> <path>`.

## [0.12.101] - 2026-07-14

### Changed
- Added direct in-proc RPC test coverage for `PolicyServiceImpl` and
  `ListControlServiceImpl` — schedule/profile/lock/network/portable-policy and
  blocklist/allowlist/IP-blocklist request validation, error-code mapping, and
  lock-gating — the handler layer that the coordinator-level tests did not reach.

## [0.12.100] - 2026-07-14

### Security
- The IPC client now verifies the control pipe's object owner before handshaking
  and refuses a pipe owned by an untrusted principal (a different-user squatter),
  closing the reverse gap where a process pre-creates the pipe name to impersonate
  the service. Trusts SYSTEM/Administrators (the LocalSystem service) and the
  current user (dev/console runs); fails open on an indeterminate owner so
  legitimate connections are never blocked.

## [0.12.99] - 2026-07-14

### Added
- Outbound webhooks now forward surfaced alerts (hosts tamper, firewall drift,
  DGA/DNS-tunnel/port-scan/IDN detectors, kill-switch, etc.), not just DNS/
  connection activity. Each new alert delivers once as a signed `event: "alert"`
  payload; deduped repeats and log-only (unsurfaced) alert types are not sent.

## [0.12.98] - 2026-07-14

### Security
- Broadened the SSRF guard's non-routable classification to reject IPv6 NAT64
  (`64:ff9b::/96`) targets by their embedded IPv4, the IPv6 unspecified address,
  and the IPv4 TEST-NET-1/2/3, benchmarking (`198.18.0.0/15`), and IETF-protocol
  (`192.0.0.0/24`) ranges so a client-supplied list/webhook URL cannot reach them.
- The loopback API now rate-limits failed token attempts with a token bucket
  (short burst, ~1/sec refill); valid callers are never throttled.

### Changed
- Added a reflection-based disposal guard test that pins every IDisposable member
  of `ServiceState` to a declared owner (disposed by `ServiceState.Dispose` or by a
  `Program.cs` `using var`), failing the build if a collaborator's lifecycle is
  added or changed without recording who disposes it.

## [0.12.97] - 2026-07-14

### Fixed
- Bounded the in-memory alert-dedup sets (`suspicious_domain`, `newly_observed_domain`,
  `dns_bypass`) behind a shared TTL'd, capacity-capped `BoundedDedupSet` so the
  always-on service no longer retains one entry per distinct domain for its whole
  lifetime; the binary-identity cache is now capped as well.
- Closed the last un-redacted logging egress: the redaction sink now scrubs the
  logged exception's message and full `ToString()` (type, stack, inner) before it
  reaches the file/EventLog sink, and every service `Console` diagnostic runs
  `ex.Message` through the redactor.
- The scheduled IP-blocklist refresh now runs under the coordinator's shutdown
  token, so Dispose interrupts an in-flight multi-source HTTPS fetch instead of
  waiting out the full drain window.

## [0.12.96] - 2026-07-13

### Changed
- Reduced idle service memory by streaming blocklist analysis instead of
  buffering and splitting multi-megabyte feeds, caching a lightweight app
  package inventory without executable-path expansion, and limiting SNI
  capture to relevant adapters with a smaller receive buffer.
- `status` and support diagnostics now expose process/GC memory, active SNI
  adapter count, and cached package count for live resource verification.
- Firewall drift ignores optional package-binary enrichment, preventing the
  lightweight inventory from producing false rule-change alerts.

## [0.12.95] - 2026-07-13

### Added
- A default-off First Network Activity alert records each binary identity's
  first destination and purpose without blocking. SHA-256 is the primary stable
  identity; repeat sightings deduplicate, while a changed binary hash is a new
  version and can alert once. Schema 35 persists the first-seen ledger.

## [0.12.94] - 2026-07-12

### Added
- Per-app and domain-suffix history privacy exclusions keep matching traffic
  visible live and fully enforced while suppressing connection, DNS, resolved
  host, bandwidth, and usage-rollup persistence. Adding or importing a rule
  purges already-retained matches; security alerts retain decision evidence.
- The History UI, `history-privacy` CLI, and portable-policy export/import now
  list and manage exclusions. Database schema 34 persists the rules locally.

## [0.12.93] - 2026-07-12

### Added
- Automatic profile rules can now match gateway MAC, Wi-Fi SSID, interface,
  DNS suffix, VPN presence/absence, and legacy fingerprints. Populated criteria
  are conjunctive; precedence is deterministic by specificity, then gateway,
  SSID, DNS suffix, interface, VPN, and stable profile/label order.
- Tools and `profile-match` show the current identity and manage additive rules.
  Native WLAN SSID discovery, full-signal debounce, stale/malformed-rule
  fallback, and portable-policy export/import preserve legacy mappings without
  a database migration.
- A bounded read-only Windows NCSI captive-portal check exposes redirect/status
  evidence through Tools and `captive-portal`. Detection never changes policy;
  only an explicit suspected-portal action enables the existing 5/15/60-minute
  pause with automatic enforcement resume.

## [0.12.92] - 2026-07-12

### Added
- A read-only resolver health matrix probes every eligible adapter/resolver
  endpoint with bounded UDP or configured DoH A+AAAA requests and reports RTT,
  protocol, record counts, TLS state, certificate failure, and explicit
  unavailable/error details without changing adapter or DNS configuration.
- Tools and `resolver-health [--run] [--host name] [--schedule off|minutes]
  [--json]` expose cached/manual results and an opt-in 15–1,440 minute schedule.
  Schedules persist, default off, suppress overlap, recover after cancellation,
  and enforce three-second endpoint and 30-second whole-run limits.
- Service status and support diagnostics include health aggregates and redacted
  matrix evidence. DNS parsing rejects mismatched IDs, error responses,
  truncation, oversized names/payloads, and malformed compression safely.

## [0.12.91] - 2026-07-12

### Added
- Domain inspection now directly queries HTTPS and SVCB records through a
  cancellable, three-second Windows `DnsQueryEx` boundary and decodes priority,
  alias target, mandatory keys, ALPN, no-default-ALPN, port, IPv4/IPv6 hints,
  ECH, DoH path, and bounded unknown parameters.
- The Tools inspector and `dns-inspect <domain> [--json]` show structured
  owner/TTL/parameter data, partial query outcomes, malformed-RDATA diagnostics,
  and explicit API-unavailable degradation. ECH advertised by the selected name
  is kept separate from global on-wire observations that cannot be attributed
  to an encrypted domain.

### Changed
- The shared RFC 9460/9461 parser now rejects duplicate, unordered, truncated,
  compressed, invalid AliasMode, and unsupported mandatory parameter layouts
  without throwing; valid unknown extensions remain visible as bounded hex.

## [0.12.90] - 2026-07-12

### Added
- A separate opt-in DNS-tunneling detector evaluates 60-second per-root,
  process, and PID query bursts using subdomain length and entropy,
  unique-query ratio, query rate, and A/AAAA/TXT/NULL/SVCB/HTTPS record-type
  mix. Alerts expose every observed metric and threshold and never block.
- Rolling state is capped at 2,048 aggregates and 256 observations per key,
  expires after its window/cooldown, and can alert again after five minutes.
  Deterministic tests cover malicious A/TXT/NULL bursts, benign CDN and
  telemetry traffic, expiry, cooldown, isolation, stale events, and eviction.
- Support diagnostics report only aggregate, buffer, and detection counters;
  query names and domains are excluded.

## [0.12.89] - 2026-07-12

### Added
- Algorithmic-domain scoring now exposes a versioned breakdown of entropy,
  vowel and digit ratios, consonant runs, signal contributions, thresholds,
  decision reason, and total score through structured alert data, the Alerts
  inspector, and `dga-check <domain> [--json]` diagnostics.
- A 57-case deterministic corpus covers random, wordlist, and numeric DGA
  labels plus brands, CDN subdomains, IDNs, short names, and adversarial
  mutations. Its current 100% precision and 81.5% recall are protected by
  95%/75% regression ratchets.

### Changed
- Algorithmic-domain detection is now genuinely off by default and records no
  alert until explicitly enabled. Enabled alerts remain deduplicated per
  registrable root and never block or rewrite a domain.

## [0.12.88] - 2026-07-12

### Changed
- The language menu now binds one canonical system/en/es/de/fr source, so all
  four shipped locales are selectable. Menus, dialogs, critical recovery
  surfaces, and runtime Hosts/Alerts/Blocklists/Firewall/Tools status, prompt,
  row, and error text now route through neutral resources instead of bypassing
  localization.
- Translation coverage is measured against the used surface: each es/de/fr
  satellite currently translates 408 of 1,633 keys (25.0%), while critical
  shell/menu/dialog/recovery keys are complete and untranslated keys fall back
  explicitly to English. Tests reject coverage regression, missing keys,
  hard-coded runtime status/action text, and UTF-8 mojibake.
- Offscreen visual smoke adds a pseudo-locale run and fails untrimmed clipped
  text across tabs and dialogs without activating the desktop.
- A deterministic pairwise render matrix now writes 67 background PNGs across
  empty, populated, loading, disconnected, and error states; dark, light, and
  simulated High Contrast; 90/100/125/150% scale; compact/default sizes; every
  primary tab, nested Hosts tab, and top-level Tools card. It gates logical
  focus, live regions, accessible names, grid headers, WCAG primary contrast,
  clipping, nonblank pixel detail, and capture completeness.

## [0.12.87] - 2026-07-12

### Added
- Blocklist preview, import, and refresh now emit structured warnings when a
  list contains one of the five exact current or legacy Windows NCSI DNS/web
  probe hosts documented by Microsoft. Apexes, nested subdomains, unrelated
  Microsoft domains, and CDN implementation hosts do not match, and deliberate
  imports remain available.
- Blocklists offers one-click recovery, also available through
  `blocklists recover-connectivity`, which persistently allows only exact NCSI
  domains currently blocked by a list. Mixed requests recover eligible rows
  while leaving manual blocks, existing allows, and unrelated domains unchanged;
  settings lock and the event ledger cover the mutation.

## [0.12.86] - 2026-07-12

### Added
- FW Rules can now create and edit HostsGuard-managed rules with normalized
  local/remote TCP or UDP ports, live-selected Windows interface aliases,
  enabled state, and a complete effective-scope preview. Existing disabled
  rules retain their state during edits, while Windows and policy rules remain
  read-only.
- `HostsGuard.Cli firewall-rule interfaces|create|edit` provides the same
  authoring surface; edits overlay only explicitly supplied options.

### Changed
- Shared validation rejects malformed, reversed, out-of-range, protocol-
  incompatible, or unknown-interface scopes before COM mutation. Updates
  restore the prior live rule if replacement fails, and scoped rules continue
  to round-trip through list, database state, and portable policy export/import.

## [0.12.85] - 2026-07-12

### Added
- Opt-in, alert-only IDN homograph detection compares observed registrable
  domains with allowlisted, trusted, and recent local domains using embedded,
  version-pinned Unicode 17.0.0 UTS #39 confusable and script data. Structured
  alerts retain safe ASCII/punycode subjects and explain decoded Unicode,
  scripts, restriction level, skeleton collision, and matching corpus source;
  no domain is blocked automatically.
- Tools and `HostsGuard.Cli idn-homograph` expose the default-off setting,
  local comparison-corpus size, and standard version. The setting persists and
  round-trips with portable policy exports.

## [0.12.84] - 2026-07-12

### Added
- FW Rules now offers read-only analysis for exact and semantic duplicates,
  provable allow/block overlaps, fully shadowed allows, disabled rules, inactive
  profile rules, Group Policy override, and inbound-block policy. Canonicalization
  covers profile/local/remote/interface, identity, address, and merged port-range
  selectors; unknown Windows special selectors remain review-only rather than
  producing speculative contradictions.
- `HostsGuard.Cli firewall-analyze` filters and exports findings. Exact-duplicate
  `HG_` rules alone can be selected for cleanup: preview binds the full live rule
  set, active profiles, policy-modify state, and sorted selection to SHA-256;
  apply refuses stale/mismatched state and restores earlier deletions if a batch
  fails. Semantic/foreign/policy-managed findings are never cleanup-eligible.

## [0.12.83] - 2026-07-12

### Added
- FW Activity now includes a collapsed, sortable local-listener exposure audit
  covering TCP/UDP and IPv4/IPv6. Rows show owning process path, exact SCM
  service when unambiguous, package family, bind scope, active profiles, and
  effective blanket/restricted/default inbound coverage with explicit snapshot-
  only wording that never claims outside-host reachability.
- `HostsGuard.Cli listeners` provides protocol, port, process/identity, and risk
  filters plus CSV/JSON export. Windows ownership capture now includes UDP
  OWNER_PID tables, executable paths, and package family names; local listener
  rows stay out of remote connection history.

### Changed
- Firewall rule projection now retains COM profile masks and local-address
  selectors. The pure analyzer applies block precedence and conservatively
  handles remote-port/address, interface, local-address, program, service,
  package, profile, and default-inbound constraints. Unknown identity or scoped
  selectors never become false blanket coverage.

## [0.12.82] - 2026-07-12

### Added
- An always-on, payload-free detector correlates blocked inbound 5157/5152
  events by globally routable source across distinct local ports in a bounded
  sliding window. Threshold, window, cooldown, source count, and per-source port
  count are configurable at construction; repeated ports, expired observations,
  loopback/private/link-local/multicast/reserved/documentation sources, and
  low-volume traffic do not alert.
- A detection creates one deduplicated `port_scan` warning with sampled local
  ports and one firewall-category audit event. The existing alert preferences
  can keep this type surfaced or log-only, and support diagnostics include its
  safe surface/unread counts without packet data.

### Fixed
- WFP blocked-event parsing is now direction-aware. Inbound events map the
  source endpoint to remote and destination endpoint to local; outbound events
  use the inverse. Consent records and scan detection therefore use the actual
  remote peer and target local port.

## [0.12.81] - 2026-07-12

### Added
- A report-only proxy/PAC monitor snapshots `ProxyEnable`, `ProxyServer`,
  `ProxyOverride`, and `AutoConfigURL` for every loaded user SID plus machine
  WinHTTP manual/advanced proxy state. It polls every two minutes and emits one
  deduplicated before/after alert when the observed state diverges from the last
  explicitly accepted baseline; no proxy setting is auto-reverted.
- Tools and `HostsGuard.Cli proxy status|accept-baseline` expose the comparison
  and let an operator accept a legitimate enterprise change. Proxy credentials
  and PAC URL userinfo/query/fragment data are redacted before persistence,
  logging, RPC, UI, or recovery capture; fingerprints retain secret-only drift
  detection without retaining raw values.

## [0.12.80] - 2026-07-12

### Added
- Tools and the CLI can create, list, and preview integrity-protected full-state
  recovery points containing a SQLite online backup, exact hosts content, and an
  explicit allowlist of non-secret service JSON. Each manifest records app/schema
  versions, component sizes, and SHA-256 hashes; secret-bearing AI, webhook,
  settings-lock, loopback-token, update, and downloaded-intelligence state stays out.
- Restore requires the exact SHA-256 returned by a fresh preview. The service
  stages the restore for startup, creates a verified pre-restore snapshot before
  replacement, and automatically restores that fallback after validation failure
  or an interrupted partial apply.

### Changed
- Protobuf compatibility tests now compare the live descriptor against an
  embedded baseline and reject field or enum renumbering, type/cardinality/oneof
  changes, unreserved deletion, and removed reservations while permitting additive
  fields and enum values.

## [0.12.79] - 2026-07-12

### Added
- Tools → DNS now lists each eligible adapter with its exact DHCP/static and
  effective resolver state before mutation. Physical adapters default selected;
  VPN, PPP, tunnel, TAP, TUN, and WireGuard-style adapters are visible but require
  an explicit check so a resolver change cannot silently rewrite VPN topology.
- Resolver requests carry selected adapter IDs and an optional probe host. The
  service runs a bounded system-path lookup requiring both A and AAAA answers and
  reports resolver round-trip time after a successful apply.

### Fixed
- DNS resolver writes now snapshot `NameServer` presence, value, and registry
  kind for every selected adapter. Partial write failure rolls back the whole
  transaction; failed/cancelled health probes restore every adapter exactly even
  if an interface went down, flush the DNS cache, and record a rollback audit
  event. Legacy clients still target active physical adapters and never a VPN.
- Adapter IDs remain deliberately machine-local and are not serialized into the
  portable policy format; importing policy on another PC cannot target an
  unrelated interface GUID.

## [0.12.78] - 2026-07-12

### Fixed
- Offscreen WPF capture now sizes and renders the window content surface rather
  than the non-client window bounds. Dark and light README images therefore
  contain the complete 1600×1000 shell and footer instead of a transparent/black
  bottom band that previously passed dimension and file-size checks.
- Every tab capture now fails on transparent edge bands, implausible theme
  luminance, insufficient luminance range, or too few detailed image tiles.
  Manifest schema 2 persists these measurements, and the release gate enforces
  them alongside dimensions and hashes.
- README installer examples use an explicit `<version>` filename template so
  they cannot silently retain an old release number. The release gate now keeps
  source/version/render checks green during development while reserving current
  installer, hash, and winget-version enforcement for `-RequireArtifacts` release
  cuts; published winget manifests remain internally validated in both modes.

## [0.12.77] - 2026-07-12

### Security
- The bundled native SQLite engine is pinned to SourceGear.sqlite3 3.53.3 for
  both win-x64 and win-arm64, replacing 3.50.4.5 and incorporating SQLite's
  WAL-reset corruption fix. A runtime-only service probe (`--sqlite-version`)
  reports the engine that actually loads; the version floor now rejects anything
  below 3.53.3 and verifies native assets for both release architectures.

### Changed
- Direct Serilog references in production diagnostics and its tests are upgraded
  from 4.3.1 to 4.4.0. Redaction coverage now proves ambient W3C TraceId and SpanId
  survive sink reconstruction, while the existing file-sink test verifies events
  drain on logger disposal.

### Tests
- Added two-connection WAL write/RESTART-checkpoint stress, recovery from a copied
  uncheckpointed WAL crash image, online backup/restore with schema and policy
  verification, and full integrity checks. The package-hygiene and vulnerability
  gates now report no vulnerable or undeferred outdated direct packages.

## [0.12.76] - 2026-07-12

### Fixed
- Scheduled domain-list, blocklist-intelligence, and domain-firewall refreshes
  are now tracked instead of fire-and-forgotten. A shared lifecycle guard
  suppresses overlapping ticks, rejects callbacks after disposal, propagates
  shutdown cancellation, and drains the active task for up to five seconds
  before the owning service component releases its database/firewall resources.
- Disposal is idempotent for all three coordinators. Lifecycle tests hold each
  refresh inside its fetch/resolve operation and verify teardown cannot finish
  until the accepted task drains, preventing post-disposal database, hosts-file,
  and Windows Firewall access.

## [0.12.75] - 2026-07-12

### Fixed
- Live connections now merge normalized TCP/UDP packet endpoints from the
  existing kernel ETW session with the authoritative IPHLPAPI TCP snapshot.
  A bounded coalescing buffer deduplicates repeated packets and polled TCP tuples
  with a sliding 30-second idle window, so UDP/53 and UDP/443 reach DNS-bypass
  detection and TCP flows shorter than the two-second poll are retained.
- ETW endpoint direction and process attribution cover send/receive traffic for
  IPv4 and IPv6. Bandwidth-session disposal now stops and joins its pump thread;
  synthetic coverage verifies deduplication, DNS-bypass delivery, TCP/UDP state,
  both address families, and idempotent shutdown, with an opt-in live ETW test.
- Handshake-token reads now tolerate up to one second of an empty or locked file
  during service token rotation instead of relying on five scheduler-sensitive
  attempts, preventing transient unauthenticated client reconnects under load.

## [0.12.74] - 2026-07-12

### Added
- DNS-path registry tamper baseline: HostsGuard now baselines and diffs the
  DNS-relevant registry surface the hosts-file watch can't see — DoH policy
  (`EnableAutoDoh`, `DoHPolicy`), NetBIOS / smart-name-resolution policy, and
  global name-server overrides (Tcpip/Tcpip6 `NameServer`). The first run records
  the baseline; later runs raise a critical `hosts_tamper` alert with the
  before/after value for each changed key, then re-baseline so an acknowledged
  change doesn't re-fire. Complements the existing `DataBasePath` redirect check.

## [0.12.73] - 2026-07-12

### Added
- Detect apps bypassing system DNS: an opt-in "Apps bypassing system DNS" alert
  type (off by default) flags a process that talks DNS itself — direct UDP/TCP
  port 53 to a public resolver, or a known DoH/DoT endpoint — instead of using
  the system resolver (and therefore evading the hosts-file blocklist). The
  Windows DNS Client (svchost) and LAN/loopback resolvers are never flagged; each
  process fires once per bypass kind.

## [0.12.72] - 2026-07-12

### Added
- Offline ASN attribution: live connections and connection history now show the
  autonomous-system number + org ("AS15169 Google LLC") of the remote IP, read
  from a DB-IP IP-to-ASN Lite MMDB via the same offline MaxMind.Db reader the
  country GeoIP uses — zero cloud. The ASN database refreshes alongside GeoIP
  (`RefreshGeoIp` / Tools → Refresh GeoIP) best-effort, so a missing ASN DB never
  fails the country refresh. Connection history persists the ASN (schema v33) and
  its CSV export gains an ASN column; a missing/absent DB degrades to blank.

## [0.12.71] - 2026-07-12

### Added
- Newly-observed-domain flag: a purely local "never seen before on this machine"
  signal (no cloud NRD feed). Domains whose `first_seen` falls within a
  meta-configurable window (`newly_observed_window_hours`, default 24h) render a
  green "NEW" cue in the Hosts activity grid. An opt-in "Newly observed domains"
  alert type (off by default, since a fresh install would otherwise flag
  everything) fires exactly once on a domain's first contact when enabled.

## [0.12.70] - 2026-07-12

### Added
- Temp-block ("block until"): the mirror of temp-allow. Block a domain for a
  fixed window (15 min / 1 hour / 8 hours from the Hosts activity context menu,
  or `HostsGuard.Cli temp-block <domain> <minutes>`), and the service reverts it
  to its prior state automatically at expiry — restoring a prior whitelist,
  dropping an unmanaged domain back to unmanaged, or leaving a pre-existing
  permanent block intact. Windows persist and re-arm across service restarts, so
  a reboot never turns a temporary block into a permanent one, and a manual
  allow/block during the window wins over the auto-revert. `temp-block list`
  (CLI) and `ListTempBlocks` (RPC) enumerate pending windows. Schema v32.

## [0.12.69] - 2026-07-12

### Added
- Algorithmic/DGA domain detection: a local, offline heuristic scores the
  registrable name (not subdomains, so random CDN subdomains are ignored) and
  raises a one-time, user-mutable "Algorithmic / DGA-looking domains" alert when
  an observed domain's registered name looks machine-generated (DGA malware /
  DNS tunnel). Curated-known domains are never flagged.
- DNS-rebinding detection: when a public registrable domain resolves to a
  private-LAN address (RFC1918/CGNAT/link-local), HostsGuard raises a
  user-mutable "DNS rebinding / out-of-scope answers" alert. Alert-only
  (split-horizon corporate DNS is legitimate); hosts-file sinks, loopback, and
  local names are never flagged.
- Diagnostics now surface the actual .NET runtime version and the loaded SQLite
  engine version — in the service status (`HostsGuard.Cli status`), the Tools
  health glance, and `diagnostics.json` — so the deployed patch level is provable
  at runtime instead of inferred from the app version.

### Fixed
- Manual-edit adoption no longer flags IPv4-mapped IPv6 sink literals (e.g.
  `::ffff:0.0.0.0`) as suspicious redirects, so those block forms don't raise a
  spurious critical tamper alert. Fire-and-forget AI categorization now runs on
  a shutdown-linked token (and logs failures defensively) so it stops with the
  service instead of racing teardown.
- Usage-budget enforcement now re-derives real block state on each sweep, so a
  quota can no longer silently stop enforcing after the user manually deletes a
  block the enforcer had recorded over but didn't own — the next over-limit
  sweep re-applies a quota-owned block instead of trusting a stale timestamp.
- The IP-format blocklist coordinator now drains an in-flight scheduled refresh
  before disposing, so a timer-driven refresh can no longer reach the database
  or firewall after shutdown has disposed them (the same teardown race fixed for
  the other background timers, previously missed for this newer coordinator).

### Security
- Self-update JSON parsing (the remote GitHub release feed and the on-disk
  manifest) now rejects duplicate keys, closing duplicate-key smuggling on the
  updater's only untrusted-remote input.
- Self-update now refuses a release-feed asset whose name isn't a plain file
  name (path separators or `..`), and always writes the staged installer under
  `Path.GetFileName`. Previously a crafted/compromised feed could place the
  hash-matched, LocalSystem-executed installer outside the updates directory —
  the SHA-256 pin constrained content, not write location.
- Self-update version comparison now fails closed: an unparseable *installed*
  version is treated as "not older" so a garbled build stamp can never make
  every remote release look newer and auto-stage an update.

## [0.12.68] - 2026-07-12

### Added
- Manual-edit adoption (NET-188): when you hand-edit the hosts file in a text
  editor, HostsGuard now dedupes and organizes the whole file into its canonical
  category sections, curated-categorizes the entries, and imports the new
  `0.0.0.0`/`127.0.0.1`/`::` block entries into the managed list as `manual`
  rows — so hand-added blocks show up in the app exactly like in-app blocks. The
  AI categorizer (when enabled) fills in categories the curated table doesn't
  know. Adoption runs automatically on external change and once at service
  startup (catching edits made while the service was stopped).
- A hand edit that maps a domain to a **real routable IP** (a redirect, e.g.
  `93.184.216.34 www.bank.example`) is never adopted and still raises the
  critical hosts-tamper alert — only additive sink/loopback block entries are
  imported silently (as an informational "manual edits adopted" alert).
- New `HostsControl` RPCs `AdoptHostsEntries`, `SetHostsAdoption`, and
  `GetHostsAdoptionStatus`; a `HostsGuard.Cli adopt-hosts [status|now|on|off]`
  command; a **Tools → Adopt manual hosts edits** card (toggle + "Adopt &
  organize now"); and portable-policy round-trip of the toggle. Default: on.

## [0.12.67] - 2026-07-10

### Added
- Portable, install-free builds: each release now ships single-file,
  self-contained `win-x64` and `win-arm64` portable ZIPs (app + CLI + service,
  no .NET runtime required) alongside the Inno Setup installers, so HostsGuard
  can be run or scripted without going through setup. No functional change from
  0.12.66.

## [0.12.66] - 2026-07-10

### Added
- SHA-256-verified service self-update (no code signing, by policy): the
  service can check the GitHub release feed, download the matching installer
  asset, verify it against the SHA-256 the feed pins for that asset — a
  mismatch or a digest-less feed is rejected outright — and stage it under
  `%ProgramData%\HostsGuard\updates`. The staged installer applies on the next
  service start; the pending manifest is consumed before launch so a crashing
  installer can never loop, and the staged bytes are re-verified at apply time
  so a tampered file is deleted instead of executed. Exposed as a Tools card
  and `HostsGuard.Cli update check|stage`, with an offline
  `update stage --path <installer> [--sha256 <hash>]` option.
- A Service health card at the top of the Tools tab: at-a-glance service
  state (version, elevation, uptime), per-monitor up/down (DNS, connections,
  bandwidth, opt-in SNI), enforcement posture (mode, kill-switch, secure
  rules, pending consent), activity-persistence drop counters, database
  schema OK/mismatch, blocklist freshness, and the hosts-file scale warning —
  unhealthy rows highlight and the summary reads out via a live region.
- German (Deutsch) and French (Français) UI locales: both translate the same
  curated core-string set as the Spanish satellite (tabs, menus, consent
  prompt, About, IP blocklists, usage-budget blocking), with English fallback
  for the rest, and appear in View → Language. New gates keep every satellite
  key valid against the neutral resources and keep new locales tracking the
  Spanish core-key set so no language silently lags.
- Cross-pipe log correlation: every GUI-initiated RPC now runs inside a W3C
  activity whose `traceparent` travels over the named pipe, so the app's
  "rpc sent" log line and the elevated service's "rpc handled" line share one
  TraceId — a GUI action can be followed into the service's log. Both
  processes gain a redacted rotating file log (`%APPDATA%`/`%ProgramData%`
  `HostsGuard\logs`) whose template renders the trace id, and the redaction
  boundary now preserves correlation ids when it rebuilds an event.
- `tools\e2e-elevated.ps1`: an elevated interactive end-to-end harness for the
  paths the headless suite cannot reach — it verifies the live LocalSystem
  service over the pipe, asserts a CLI `block-app` writes a real enabled
  Windows Firewall rule (and that the blocked executable actually cannot dial
  out), drives the Security-audit consent path with a synthetic dropped
  connection, and asserts posture restore both on mode-switch and on service
  stop. Preflight refuses hosts whose firewall is disabled instead of flipping
  a profile the operator turned off; Filtering Platform audit policy is
  enabled for the run and restored afterwards.

### Changed
- Structural split of the four largest source files, behavior-preserving:
  the CLI's twenty pipe-connected commands now share one connect/error
  wrapper instead of repeating it; ConsentBroker's command-line-rule engine
  moved to its own partial; FW Activity and Tools ViewModels split into
  per-feature partial files (history/decisions/posture, policy
  subscriptions/VPN/AI/IP-blocklists). No XAML binding or RPC changes.

### Added
- The blocklist catalog is now a browsable gallery: every curated source
  carries tags, license, homepage, and a description, shown as new
  Tags/License columns, a hover summary, and a per-row Site button on the
  Blocklists tab (also served over the RPC surface for the CLI). Imports run
  an explicit transform pipeline: plain adblock domain rules (`||example.com^`)
  now convert losslessly to hosts blocks instead of being dropped, while rules
  with `$modifiers` (third-party, script, …) are stripped and never imported
  as bare domains — reported as a separate "modifier-stripped" count in
  preview and import results alongside duplicates/invalid/hijack.
- Usage budgets can now enforce, not just alert: a quota rule can opt into
  "Block on exceed" (default off). Crossing the rolling-window limit applies a
  scoped block — a hosts-file entry for a domain rule, `HG_QuotaBlock_*`
  outbound firewall rules for an app rule (resolved from the matching running
  processes) — raises an alert, and ledgers the action. The block clears
  automatically when the window slides back under the limit, and lifting it is
  one click: disable the rule, delete it, or reset quota history. Manual
  allowlists and manual blocks are never overridden. Exposed in the FW
  Activity quota editor and `usage-quota set --block`.
- IP-format blocklists: subscribe HTTPS sources of IPv4/IPv6/CIDR entries
  (e.g. HaGeZi `ips/doh`, `ips/tif`) and enforce them as chunked `HG_IPBlock_*`
  Windows Firewall outbound block rules — this stops hardcoded-IP C2 and
  DoH-bootstrap-IP bypass that hosts-file blocking cannot. Sources refresh
  daily behind the same churn guard as domain blocklists, keep the previous
  payload for one-step rollback, round-trip through portable policy, and
  surface in the decision explainer via live rule matching. Managed from a new
  Tools card and `HostsGuard.Cli ip-blocklists`. Non-routable targets
  (loopback, RFC1918, link-local, multicast) and over-wide CIDRs are refused
  so a hostile list can never block the LAN or all traffic; lists beyond the
  32,768-address rule cap are truncated with an explicit warning.

### Changed
- Extended the property/fuzz test suite to hammer the untrusted parsers with
  seeded random and truncated input — domain normalization, the DDR SVCB wire
  parser, the raw-socket TLS ClientHello reader, and portable-policy JSON import —
  asserting they stay total (never throw an unhandled exception).

### Added
- Encrypted-DNS status now reports whether Windows DNR (Discovery of
  Network-designated Resolvers, RFC 9463) is enabled, so you can see when a
  network may auto-provision an encrypted resolver and silently steer DNS. Adds
  an RFC 9460/9461 SVCB/HTTPS wire parser for DDR designated-resolver records
  (target, ALPN, port, DoH template) as the basis for resolver-upgrade discovery.
- Very large hosts files (100k+ blocked entries, e.g. HaGeZi Ultimate / oisd Big)
  now raise a scale warning in service status and the CLI `status` command,
  suggesting firewall IP rules instead — a hosts file that size measurably slows
  system-wide DNS resolution. Nothing is capped or refused.
- Unicode internationalized domain names (IDNs) can now be blocked: domains are
  normalized to their ASCII/punycode (`xn--`) form on the way in, so entries like
  `münchen.de` or `例え.jp` are accepted, stored, and matched instead of being
  rejected as invalid. The same normalization strips trailing dots, so a
  manually-added `0.0.0.0 example.com.` line is now removable via unblock.
- Service status and the support-bundle `diagnostics.json` now report runtime
  health: SNI/bandwidth monitor liveness, secure-rules and kill-switch state,
  pending-consent count, ECH-unavailable observations, persistence dropped-write
  and batch counters, and the on-disk vs compiled schema version — so a support
  engineer can tell whether the service is healthy or quietly shedding work. The
  CLI `status` command prints the new health and schema-version lines.

### Security
- The opt-in loopback API now bounds the request-body read itself, so a chunked
  POST (which reports no content length and previously slipped the size check)
  can no longer submit an over-limit body; oversized bodies are rejected with 413
  instead of being silently truncated.

### Fixed
- The IPC handshake token is now published atomically (write + ACL a temp file,
  then rename over the destination), and the reader retries briefly past a
  transient empty/locked read, so the desktop UI can no longer grab a partial or
  not-yet-protected token during a rotation and be forced to reconnect.
- Background AI auto-categorization of a freshly blocked domain now logs every
  failure (including a malformed AI response) as `ai_categorize_failed` instead
  of letting some exception types escape as an unobserved task exception.
- The service now recovers from a corrupt or unopenable state database instead
  of failing to start: on open it runs a fast `quick_check`, and on corruption
  (or any open failure) it quarantines the bad file and its WAL/SHM sidecars to a
  timestamped `.corrupt` name, rebuilds an empty versioned schema, and records
  both a log event and an alert — so a power-loss-torn `hostsguard.db` can never
  brick the elevated service responsible for restoring safe network posture.
- Stopped the activity-persistence flush from being able to drop a pending DNS
  sighting: the bounded write queue now shrinks under back-pressure by refusing
  (and counting) the newest write instead of silently evicting the oldest, and
  `Flush` inserts its marker in order via an awaiting write so it can never bump
  a queued sighting out — prior sightings are guaranteed persisted on flush, and
  shed writes are exposed via a new dropped-writes counter.
- Hardened service shutdown against a background-timer/database race: the
  Secure-Rules tamper-guard, schedule enforcer, and temp-allow scheduler now
  drain any in-flight timer callback before returning from `Dispose`, and the
  database fails fast with a typed `ObjectDisposedException` on the coordinator
  read/write paths after disposal (which those coordinators now swallow) instead
  of surfacing an opaque SQLite error on a background thread at stop.

- Kept the Firewall Rules workbench within the viewport by rebalancing column widths, truncating long values with full-value tooltips, and removing the horizontal navigation regression in both themes.
- Clarified the read-only Windows Firewall indexing action, removed its unnecessary confirmation interruption, and added live rule-creation guidance that prevents conflicting package and program targets before submission.

## [0.12.65] - 2026-07-09

- Re-imagined the WPF workbench around a premium operator-console shell: a crisp vector brand lockup, calmer dark/light surface hierarchy, a continuous primary-tab rail, denser tables, a scroll-safe status sidebar, and mockup-aligned spacing across every primary view.
- Polished secondary Hosts File navigation, alert severity rows, confirmation/input/connection-consent dialogs, and semantic keyboard-focus states; visual smoke now captures all three dialogs in dark and light themes.
- Replaced the generic About message box with a localized, accessible product dialog that presents version/build identity, split-trust architecture, local-first privacy posture, and a direct repository action.

## [0.12.64] - 2026-07-09

### Fixed
- Freed the native linked-list returned by the Windows DNS cache snapshot API so
  every resolver-cache view no longer leaks dnsapi-heap memory, and the walk now
  covers the full list even past the display limit.
- Cached the firewall rule snapshot used by consent covering-rule checks with a
  short TTL (invalidated on the broker's own rule writes), replacing a full COM
  rule enumeration on every blocked-connection event in Notify/Learning mode.
- Localized the consent prompt's dynamic strings (direction, PID, scope labels,
  country/signer fallbacks, trust-publisher/folder offers, service scope, PTR
  status, and the countdown) through neutral resources with Spanish
  translations, gated by a resource-coverage regression.
- Fixed the consent prompt's duplicate TabIndex so keyboard order now flows
  scopes, trust checkboxes, duration, then action buttons unambiguously.
- Consent decision delivery now reports whether the service applied the
  decision, and the shell warns explicitly when an Allow/Block was not applied
  instead of silently leaving the connection blocked with the prompt closed.
- Threat-intel IP checks on the per-connection hot path are now lock-free; the
  refresh's disk write no longer stalls live connection processing.

## [0.12.63] - 2026-07-09

### Security
- Fixed `Unblock` removing non-sink-address hosts-file lines (e.g. legitimate
  `192.168.x.x` mappings) instead of only `0.0.0.0`/`127.0.0.1`/`::`/`::1`
  block entries.
- Fixed LIKE wildcard injection in managed-domain search and usage-rollup
  filters so underscore and percent characters in search terms match literally
  instead of acting as SQL wildcards.

### Fixed
- Added shared confirmation guardrails to Hosts Activity block, allow, unblock,
  root-block, and temporary-allow commands so feed actions cannot write hosts
  entries without an explicit operator decision.
- Made bulk hosts-file block/allow operations commit database state only after
  the hosts-file reconcile succeeds, preserving state consistency when antivirus
  or another process is holding the hosts file.
- Logged a bounded domain preview for bulk hosts-file events and preserved the
  caller source when blocking a root domain from Hosts Activity.
- Localized the consent prompt reputation hyperlink and added an i18n guard for
  nested XAML text so interactive prompt copy cannot bypass resource coverage.
- Guarded enforcement-pause and consent-broker state persistence against I/O
  exceptions so a transient file-system failure cannot crash the service timer
  callbacks or leave enforcement in an inconsistent state.
- Made the loopback API disposal wait for the request-serving loop to exit
  before releasing the cancellation token, preventing a race on shutdown.
- Made AI categorizer config saves atomic via write-to-temp-then-rename,
  matching the crash-safe pattern used by every other config writer.
- Made `SetHostsProtection(Enabled=false)` return an explicit error instead of
  silently succeeding while actually hardening the DACL again.
- Made `GetTempAllows` skip rows with malformed expiry dates instead of crashing
  the entire temp-allow system on one corrupt database row.
- Added error logging to the domain-firewall periodic refresh so failures in DNS
  resolution or rule application are surfaced in the event ledger instead of
  being silently swallowed.
- Fixed `DomainPurpose` label-prefix matching for "ocsp." and "stun." entries so
  domains containing the substring in the middle of a label (e.g.
  "notocsp.example.com") no longer receive a false purpose label.
- Made `Domains.GetRoot` return consistent lowercase for 2-label domains,
  matching the lowered output already produced for 3+ label domains.
- Made `Unblock` short-circuit when no block lines were removed, avoiding
  unnecessary file rewrites and tamper-watch churn.
- Moved the self-change hash recording in `AtomicWrite` after the successful
  `File.Move` so a failed swap cannot register a phantom hash that suppresses
  a future tamper alert for identical content written by an external actor.
- Added periodic PID-to-process-name cache eviction in the connection monitor
  so recycled PIDs do not carry stale names after long service uptime.

## [0.12.62] - 2026-07-09

### Security
- Hardened all CSV exports against spreadsheet formula injection while
  preserving RFC-4180 quoting for event, connection-history, usage-quota, and
  traffic-profile exports.

### Fixed
- Made repeated support-bundle exports write distinct zip paths instead of
  reusing the same second-resolution filename.
- Fixed support-bundle export on fresh databases with an empty event log by
  using the resilient event-ledger row mapper for diagnostic log reads.
- Improved GUI and CLI service-failure messaging so app/service version
  mismatches and handler errors are not mislabeled as unreachable service
  failures.
- Removed WPF menu access-key markers from neutral and Spanish labels so the UI
  follows HostsGuard's no-keyboard-shortcut interaction contract.
- Made webhook delivery startup/disposal idempotent so duplicate `Start` calls
  cannot create duplicate event-bus subscriptions or lose the active loop.
- Guarded the consent broker sweep lifecycle so queued timer callbacks cannot
  touch SQLite after service shutdown has begun.

## [0.12.61] - 2026-07-09

### Added
- Added redacted metadata-only traffic profile exports for support bundles, FW
  Activity, and `HostsGuard.Cli traffic-profile`, with time/app/action/protocol
  filters, JSON/CSV output, Wireshark display-filter hints, and an explicit
  no-payload guarantee.
- Added `HostsGuard.Cli support-bundle` so filtered support zips can be created
  from the command line.

### Changed
- Tightened diagnostics redaction so free-form Windows executable paths are
  scrubbed before support/profile export.

## [0.12.60] - 2026-07-09

### Added
- Added optional app/domain usage-budget alert rules backed by retained daily
  usage rollups, with `usage_budget` alert inbox entries when thresholds are
  crossed.
- Added WPF Firewall Activity controls and `HostsGuard.Cli usage-quota`
  list/set/delete/reset/export commands for quota rules and quota history.
- Added portable-policy round-trip and regression coverage for usage-budget
  rules without introducing traffic shaping or default blocking.

## [0.12.59] - 2026-07-09

### Changed
- Made dependency hygiene transitive deferrals source-backed: the ratchet now
  prints each owning package/version, observed resolved-to-latest drift, reason,
  and revisit trigger while continuing to fail vulnerable, direct-outdated, or
  undeferred transitive packages.

## [0.12.58] - 2026-07-09

### Changed
- Hardened blocklist parsing with edge-case fixtures for hosts comments,
  adblock exclusions, wildcard-like entries, IPv4/IPv6 null routes, duplicates,
  malformed lines, and hijack diagnostics.
- Rejected adblock cosmetic/filter syntax during blocklist import instead of
  accidentally trimming it into a bare domain.

## [0.12.57] - 2026-07-09

### Changed
- Moved policy-subscription ViewModel status, confirmation, and row display text
  through the neutral localization resources, and added regression coverage that
  fails missing `I18n.T` resource keys.
- Expanded the XAML localization gate to cover hint `Tag` values,
  `TargetNullValue` fallbacks, and dynamic button content setters.

## [0.12.56] - 2026-07-09

### Added
- Added optional remote portable-policy subscriptions with HTTPS fetch, preview
  diffs before apply, SHA-256 trust pinning, manual/default-off auto-apply
  metadata, and rollback to the checkpoint captured before the latest
  subscription apply.
- Added a Tools tab policy-subscriptions editor with saved source metadata,
  preview/apply/save/remove actions, trust state, and latest error/hash status.

## [0.12.55] - 2026-07-09

### Added
- Added WPF smoke coverage that fails major tab status readouts without polite
  live-region announcements and verifies actionable empty-state copy.
- Added an Alerts tab empty state for an empty alert inbox, with guidance to
  refresh or adjust alert type settings.

### Changed
- Promoted main shell and tab status readouts to polite live regions for screen
  readers.

## [0.12.54] - 2026-07-09

### Added
- Added versioned visual-smoke metadata for the tracked README screenshots,
  including app/service binary versions, dimensions, and SHA-256 hashes.

### Changed
- Visual smoke now refreshes the dark/light README screenshots after a
  successful offscreen WPF run, and the release version gate fails stale
  screenshot manifests, missing README references, or changed screenshot files.

## [0.12.53] - 2026-07-09

### Added
- Added an analyst-grade local connection history explorer with persisted
  host/domain attribution, typed app/domain/IP/status/protocol/time filters,
  paging metadata, async filtered CSV export, retention controls, and a
  confirmed clear-history action.

## [0.12.52] - 2026-07-09

### Added
- Added HTTPS/SVCB-aware DNS diagnostics in the service, WPF Tools tab, and
  `HostsGuard.Cli dns-cache`, including ECH posture text that distinguishes
  ECH-hidden SNI from cache-only/unobservable states without enabling blocking
  by default.

## [0.12.51] - 2026-07-09

### Added
- Added WFP 5157/5152 filter-origin/runtime and interface-index/name capture
  for blocked connection triage, with provenance persisted in the event ledger
  and surfaced in consent history.
- Added external firewall-rule block alerts so drops caused by non-HostsGuard
  filters are labeled clearly in Activity/Alerts instead of looking like
  HostsGuard-owned decisions.

## [0.12.50] - 2026-07-09

### Added
- Added UWP/MSIX app-container package discovery and package-scoped Windows
  Firewall rule authoring in the service, WPF Firewall Rules tab, and
  `HostsGuard.Cli firewall-packages|block-package|allow-package|unblock-package`.
- Added portable-policy, drift, secure-rule, and decision-explainer support for
  package-family/SID firewall rules.

## [0.12.49] - 2026-07-09

### Added
- Added `tools/release-version-gate.ps1` to verify app, installer, README,
  CHANGELOG, and winget manifest versions, release URLs, and built installer
  SHA256 hashes.

### Changed
- Updated winget manifests to the current release artifact naming and hashes.

## [0.12.48] - 2026-07-09

### Added
- Added portable-policy import preview/diff counts shared by WPF and
  `HostsGuard.Cli import-policy --preview`, plus pre-import policy checkpoints
  and restore actions through WPF and `HostsGuard.Cli import-policy --restore-checkpoint`.

### Changed
- Policy import confirmations now show added/changed/removed counts before
  applying broad domain, firewall, DNS, schedule, profile, and subscription
  changes.

## [0.12.47] - 2026-07-09

### Added
- Added blocklist source-health persistence with applied/previous SHA-256
  hashes, previous and attempted domain counts, last error state, and checkpoint
  IDs surfaced in WPF and `HostsGuard.Cli blocklists list|stats`.
- Added scheduled-refresh churn guarding and `HostsGuard.Cli blocklists rollback`
  / WPF Restore actions for source checkpoints.

### Fixed
- Fixed blocklist refresh replacement so source-owned domains that disappear
  from a refreshed list are removed from the database and hosts file unless
  they are preserved by another source or manual ownership.

## [0.12.46] - 2026-07-09

### Added
- Added installer safe-posture recovery and `HostsGuard.Cli safe-posture-smoke`
  verification so fresh installs/upgrades restore Normal/Allow posture, disarm
  DNS-bypass, flow-teardown, and kill-switch controls, and leave hosts-file
  blocks unchanged.

### Fixed
- Fixed safe-posture recovery order so disabling an engaged VPN kill-switch
  cannot restore a prior block-all posture after recovery already set outbound
  Allow.

## [0.12.45] - 2026-07-09

### Added
- Added a WPF "Restore safe network posture" action in the top command band and
  posture rail. It mirrors `HostsGuard.Cli safe-posture`, restores normal
  filtering/default outbound/DNS-bypass/kill-switch/flow-teardown posture, and
  leaves hosts-file blocks unchanged.

### Changed
- Refined the WPF shell toward a denser premium operations console with a
  persistent command band, safer posture rail actions, stronger dark/light theme
  surfaces, tuned table/inspector chrome, and refreshed README screenshots.

## [0.12.44] - 2026-07-08

### Added
- Added a Windows DNS resolver-cache viewer and targeted cache-entry flush. The
  service now lists `DnsGetCacheDataTable` rows, exposes `DnsControl.ListCache`
  and `FlushCacheEntry`, adds the Tools-tab cache table, and provides
  `HostsGuard.Cli dns-cache` / `dns-flush-entry`.

## [0.12.43] - 2026-07-08

### Added
- Added persistent daily app/domain data-usage rollups. The bandwidth
  aggregator now writes resolved endpoint bytes into a `usage_daily` table under
  the history retention policy, with a `Monitoring.GetUsageRollups` RPC, FW
  Activity usage table, and `HostsGuard.Cli usage` filters.

## [0.12.42] - 2026-07-08

### Added
- Added opt-in per-app VPN binding. The service can bind a program to one
  adapter by maintaining `HG_VPNBind_*` Windows Firewall rules scoped to the
  other active interfaces, without changing default outbound posture or
  hosts-file blocks. Bindings are visible in Tools, included in portable policy,
  and interface aliases now appear in the firewall rule viewer and explainer.

## [0.12.41] - 2026-07-08

### Added
- Added command-line-aware consent for common interpreters (`python`, `node`,
  `pwsh`, `java`, `wscript`, and `cscript`). Prompts show the extracted
  script/module identity, script-bound allows stay remote/protocol/port scoped
  instead of broadly allowing the interpreter, and script-bound blocks are
  enforced by the broker without writing a broad block rule.

## [0.12.40] - 2026-07-08

### Added
- Added LAN attack-surface toggles for LLMNR, mDNS, NetBIOS-NS, SSDP/UPnP,
  WPAD, and inbound SMB. The service applies reversible registry posture where
  Windows exposes it, creates auditable `HG_LAN_*` firewall rules, shows
  "what breaks" notes in Tools, and round-trips the posture through portable
  policy.

## [0.12.39] - 2026-07-08

### Added
- Added per-app domain-scoped firewall rules (`HG_Domain_*`) whose remote IP
  lists populate from observed DNS answers and periodic re-resolution, with FW
  Activity actions, portable-policy round-trip, and decision-explainer evidence.

## [0.12.38] - 2026-07-08

### Changed
- Refined the WPF shell toward a more premium operational-console design with
  updated dark/light theme tokens, carded status rail sections, stronger table
  and inspector chrome, vector tab/action icons, and refreshed dark/light
  screenshots.
- Expanded rendered visual smoke coverage to include the Alerts tab so evidence
  filenames match all six primary tabs.

## [0.12.37] - 2026-07-08

### Added
- Added a stateful in-app alert inbox for low-volume security events: binary
  identity changes, threat-intel hits, hosts tamper, kill-switch engagement,
  firewall drift, and unknown network fingerprints. Alerts support unread/read
  acknowledgement, per-type surface/log-only settings, a left-rail unread
  badge, and typed monitoring RPCs.
- Added `HostsGuard.Cli safe-posture` to recover from traffic-breaking posture
  without changing hosts-file block entries: normal mode, default outbound
  Allow, encrypted-DNS/QUIC/CNAME reactive blocks off, flow teardown off, and
  kill-switch off.

## [0.12.36] - 2026-07-08

### Added
- Added opt-in immediate IPv4 TCP flow teardown after IP, app, consent, or
  kill-switch blocks, plus a FW Activity right-click action to close an
  established IPv4 TCP connection. Every successful teardown is ledgered.

## [0.12.35] - 2026-07-08

### Added
- Added a report-only full Windows Firewall drift baseline. The service
  snapshots every rule, logs foreign rule additions/changes/vanishes as
  firewall events, and surfaces drift status/details on the FW Rules tab.

## [0.12.34] - 2026-07-08

### Added
- Added exact per-source blocklist efficacy stats. The service now keeps
  per-domain hourly DNS hit rollups, surfaces hits/30d in the Blocklists table,
  and exposes the same data through `HostsGuard.Cli blocklists stats`.

## [0.12.33] - 2026-07-08

### Added
- Added a timed global enforcement pause for 5, 15, or 60 minutes from the tray
  and status rail. The service temporarily clears hosts-file blocks, sets
  default outbound to Allow, logs pause/resume edges, auto-resumes the saved
  posture, and suspends safely under the VPN kill-switch.

## [0.12.32] - 2026-07-08

### Refactored
- Split large WPF row ViewModels, HostsDatabase domain areas, and ConsentBroker
  review/history/persistence sections into focused files without changing the
  public behavior surface.

## [0.12.31] - 2026-07-08

### Tests
- Verified the audit-exposed gap list is now covered by targeted regressions for
  service reconnect/token rotation, event-ledger LIKE escaping, SQL-paged event
  category filters, and retention sweeps.

## [0.12.30] - 2026-07-08

### Fixed
- `BandwidthMonitor` now caches remote-IP text for a bounded TTL so per-kernel
  byte events do not repeatedly stringify the same endpoint on the hot path.
- `DohIntelligence.CurrentIps` now caches state-file stat checks briefly and
  invalidates immediately on trusted saves/imports, avoiding per-connection file
  system probes for DoH/DoT categorization.

## [0.12.29] - 2026-07-08

### Fixed
- `HostsActivityViewModel.Upsert` now uses a keyed domain index for live DNS
  events instead of repeated UI-thread linear scans across the 1000-row feed.
- Added regressions proving the index is cleared for active-filter drops and
  bounded-feed evictions before the same domain appears again.

## [0.12.28] - 2026-07-08

### Fixed
- `HostsDatabase.Dispose` now clears only the SQLite pool tied to its own
  connection instead of clearing every process-wide pool, keeping unrelated live
  database instances intact.
- Re-enabled service-test assembly parallelization after three consecutive
  green runs, and added a regression proving one database disposal does not
  break another live database.

## [0.12.27] - 2026-07-08

### Fixed
- Webhook, bandwidth, and connection-feed background loops now catch and log
  unexpected per-event/tick failures instead of silently dying for the rest of
  service uptime, and their `Dispose` paths wait briefly for cancellation to
  drain.
- Added a webhook loop regression proving a non-network sender exception does
  not stop subsequent deliveries.

## [0.12.26] - 2026-07-08

### Fixed
- `SniSniffer.Start` now mutates capture sockets and pump threads under the same
  gate as `Stop`, each pump uses its captured cancellation token, and `Stop`
  joins pump threads before returning so SNI callbacks cannot fire after
  shutdown completes.

## [0.12.25] - 2026-07-08

### Fixed
- `ServiceState.Dispose` now disposes `AiCategorizer`, which in turn disposes
  its owned disposable completer/DeepSeek `HttpClient`; regression coverage
  verifies the service shutdown path releases the AI completer.

## [0.12.24] - 2026-07-08

### Fixed
- Category-filtered event-ledger queries now translate `EventTaxonomy` into a
  SQLite `CASE` predicate so counts and pages are filtered in SQL instead of
  materializing the full log before paging.
- Added deterministic mixed-ledger coverage that compares SQL category pages to
  the taxonomy-derived in-memory result across categories, limits, and offsets.

## [0.12.23] - 2026-07-08

### Fixed
- Moved DNS/SNI SQLite persistence off ETW/sniffer callbacks into a bounded
  single-reader batch queue while keeping live blocked/hidden stamps synchronous
  with `GetActivity` semantics.
- Activity and sparkline snapshot RPCs now flush queued activity writes before
  reading SQLite, and exact-domain hide flushes first so hidden rows do not
  bounce back behind a queued feed insert.
- Added burst and shutdown-drain tests proving ordered live DNS delivery,
  blocked/hidden stamping, batched persistence, and graceful queue drain.

## [0.12.22] - 2026-07-08

### Fixed
- Added a service-driven SQLite retention sweep that bounds `log`,
  `resolved_hosts`, `domain_usage`, `app_bandwidth`, and `feed_hourly` under the
  configured history window while periodically running `PRAGMA optimize` and
  bounded incremental vacuum maintenance.
- Existing databases now migrate to `auto_vacuum=INCREMENTAL` without losing
  data; regression tests cover fake-clock pruning and idempotent no-op sweeps.

## [0.12.21] - 2026-07-08

### Fixed
- Event-ledger search now uses SQLite `LIKE ... ESCAPE '\'` semantics so
  literal `_`, `%`, `[`, and backslash terms filter correctly instead of being
  treated as wildcards or SQL Server bracket escapes.

## [0.12.20] - 2026-07-08

### Fixed
- Reconnect now drops stale named-pipe clients, re-reads the service handshake
  token, rebuilds tab view-models with the fresh client, and restarts live DNS,
  firewall-connection, and consent-prompt streams with bounded retry after
  transient service disconnects.

## [0.12.19] - 2026-07-07

### Added
- Added a local dependency hygiene ratchet that fails on vulnerable packages,
  outdated direct packages, or new undeferred transitive NuGet drift while
  documenting the current TraceEvent, SQLitePCLRaw, xUnit-runner, and UI-support
  deferrals.

### Changed
- Updated direct test/build package pins for xUnit, xUnit runner, coverlet, and
  Grpc.Tools; the full suite remains at 803 tests.

## [0.12.18] - 2026-07-07

### Changed
- Routed the main WPF shell, dialogs, consent prompt labels, menus, inspectors,
  tooltips, and accessibility names through the neutral resource pipeline.
- Added pseudo-locale support and a XAML localization gate that fails on new
  hard-coded English literals or missing neutral resource keys.

## [0.12.17] - 2026-07-07

### Added
- Added `win-arm64` publish support alongside `win-x64`, with runtime-scoped
  `dist\dotnet\<rid>` output, architecture-labeled Inno installers, winget
  entries for both architectures, and x64-compatible release smoke while
  ARM64 smoke is skipped on non-ARM64 hosts.

## [0.12.16] - 2026-07-07

### Changed
- Replaced the browser-opening "Check for updates" command with a read-only
  GitHub latest-release metadata check that compares SemVer, reports release
  date, asset, and hash status, handles offline/API failures in the status bar,
  and never auto-installs.

## [0.12.15] - 2026-07-07

### Fixed
- Firewall Activity live connection counts no longer overwrite operator action
  results such as resolve, explain, block, allow, and scope-block statuses;
  explicit feed transitions can reclaim the status line.

## [0.12.14] - 2026-07-07

### Added
- Added a settings-lock PasswordBox watermark using a compiled-window local
  style plus an attached empty-state helper, avoiding the shared theme
  dictionary parse trap while keeping headless style tests green.

## [0.12.13] - 2026-07-07

### Fixed
- Added a public fallback path for the WPF DataGrid width repair so grouped
  dense grids can recover if WPF's private column-width invalidation hook
  changes, plus a regression test that forces the fallback path.

## [0.12.12] - 2026-07-07

### Added
- Added a checked rendered WPF visual smoke harness that launches the app
  offscreen, captures all primary tabs in dark and light themes at 1600x1000,
  verifies theme chrome, and fails on dense-grid horizontal scrollbar
  regressions with PNG/JSON evidence.

## [0.12.11] - 2026-07-07

### Fixed
- Finished per-command WPF service-failure feedback across Hosts Activity,
  Firewall Activity, Firewall Rules, Raw Hosts, Blocklists, Tools, and shell
  menu commands so stopped-service/RPC failures update the relevant status line
  with action-specific recovery text instead of falling through to a generic
  modal path.

## [0.12.10] - 2026-07-07

### Added
- Added a rule decision explainer and simulator through `FirewallControl`,
  WPF Firewall Activity, and `HostsGuard.Cli explain`.
- Explanations now show ordered hosts, firewall-rule, trust, profile-default,
  and VPN kill-switch evidence with the next safe action for the operator.

## [0.12.9] - 2026-07-07

### Added
- Added source-scoped blocklist preview, enable/disable, and rollback across the
  ListControl API, WPF Blocklists view, and CLI `blocklists` subcommands.
- Blocklist imports now track per-source domain ownership so removing a source
  deletes only domains owned solely by that source while preserving manual,
  allowlisted, and overlapping-source rows.

## [0.12.8] - 2026-07-07

### Added
- Exposed the persisted structured event ledger through `Monitoring.ListEvents`,
  the WPF Firewall Activity history panel, and `HostsGuard.Cli events`, with
  paging plus time/action/reason/domain/process/category filters.
- Added redacted CSV export for CLI event-ledger output and tests covering
  event filters, taxonomy categories, and export-safe redaction.

## [0.12.7] - 2026-07-07

### Changed
- Expanded portable-policy export/import to preserve non-secret mutable privacy
  state: consent mode/trust sets, inbound consent, DoH/SNI/CNAME/QUIC posture,
  DoH intelligence, kill-switch intent, AI settings/knowledge/overrides, and
  webhook endpoint intent.
- Portable-policy import now reports omitted AI API keys and webhook signing
  secrets instead of carrying secrets across machines.

## [0.12.6] - 2026-07-07

### Fixed
- Hardened outbound event webhooks against SSRF: loopback API configuration now
  rejects non-HTTPS, loopback, private, link-local, metadata, ULA, and CGNAT
  destinations before saving, and webhook delivery uses the same public-only
  connect-time guard as remote list fetching.

## [0.12.5] - 2026-07-07

### Changed
- Added the 2026-07-07 improvement backlog to the actionable roadmap and moved
  signing/toast/elevated/interactive gates into the blocked roadmap.
- Modernized the roadmap target language from .NET 8 to the shipped .NET 10
  architecture.

### Fixed
- Started NET-126 by giving the Hosts tab per-command service-failure feedback:
  block/allow/remove/bulk/categorize/refresh commands now catch service/RPC
  failures and write action-specific `StatusText` instead of bubbling a generic
  failure path.

## [0.12.4] - 2026-07-07

### Changed
- Closed more of the generated-reference UX gap with native dark title-bar
  theming, a top-level Tools menu, a left-rail update check action, and refreshed
  dark/light Hosts Activity screenshots.
- Made the DNS activity grid read more like the reference by showing `Observed`
  for undecided rows, preserving fitted columns without horizontal scrolling,
  and tinting blocked rows with the danger surface.
- Added the inspector header close affordance so the selected DNS detail panel
  matches the mock's dismissible right rail.

## [0.12.3] - 2026-07-07

### Changed
- Tightened the WPF shell against the generated design reference with a
  concept-scale 1280x800 default window, icon-led main navigation, and a
  denser operational left rail.
- Reworked Hosts Activity controls into a single-line command bar with
  search, AI purpose lookup, block/allow decisions, activity toggles, and
  refresh in the same order as the reference.
- Refitted the DNS activity table and selected-domain inspector so the grid
  avoids horizontal scrolling while the inspector keeps the action stack
  visible.
- Re-captured README screenshots in both dark and light themes after the
  parity pass.

## [0.12.2] - 2026-07-07

### Changed
- Re-imagined the WPF shell around a persistent status rail with service health,
  filtering posture, key counters, refresh/reset actions, scale, and theme
  controls visible across the app.
- Modernized the activity workbench with denser command bars, tighter table
  chrome, selected-row inspectors for DNS and firewall triage, and action chips
  that keep common block/allow decisions adjacent to the selected item.
- Rebalanced high-density Hosts Activity and Firewall Activity layouts so the
  live grids remain visible in the first viewport at 125% DPI.
- Re-captured README screenshots in both dark and light themes after the
  redesign.

## [0.12.1] — 2026-07-05

### Changed
- Premium-polished the WPF shell and core controls with stronger hover, focus,
  selected, disabled, command-bar, badge, empty, and service-recovery states
  across dark and light themes.
- Reduced startup lockout: the shell becomes usable after the service handshake
  while tab data continues loading, then reports the fully loaded connected
  state once background refreshes finish.
- Refined confirmation, consent, and text-input dialogs with clearer guidance,
  safer defaults, accessible labels/help text, and broader two-theme smoke
  coverage.
- Re-captured README screenshots in both themes after the UI pass.

## [0.12.0] — 2026-07-04

### Added
- **NET-103 — Subscribable rule groups.** HG_ firewall rules can be assigned to a
  named group (Firewall Rules → right-click → *Assign to group…*) and the whole
  group toggled on/off atomically from a chips strip on the Firewall Rules tab.
  Groups round-trip through the portable policy (NET-089), so a shareable rule set
  exports and re-imports. New `Firewall.AssignRuleGroup`/`ListRuleGroups`/
  `ToggleRuleGroup` RPCs and a `rule_groups` table (schema v13).

- **NET-117 — Trust-by-folder.** A consent prompt now offers *Trust all software
  in "&lt;folder&gt;"*; once trusted, any binary under that folder auto-allows
  without prompting — the driver-free "trust this whole install/portable-app
  directory" (Windows Firewall can't glob paths, so this is enforced in the
  consent broker). A Tools → *Trusted folders* card reviews/removes them. New
  `Consent.GetTrustedFolders`/`SetTrustedFolders` RPCs, a `trust_folder` decision
  flag, and `Core.PathScope`; the set persists in `consent_state.json`.

- **NET-123 — Endpoint knowledge pack.** The curated offline domain-purpose table
  gains a versioned pack (`DomainPurpose.EndpointPackVersion`) of ~45 common
  Windows/vendor endpoints — DoH resolvers, browser/vendor updaters and telemetry
  (Firefox, Apple, Edge/Bing, NVIDIA, Brave), SmartScreen/activation, and common
  apps (Discord/Slack/Spotify/LinkedIn/VS Code) — so the feed explains them
  deterministically with no AI call. User overrides (NET-107) still win.

- **NET-121 — "Explain / look up connection".** The Firewall Activity connections
  view's research menu now pivots on the connection's *resolved domain* (the
  meaningful identity) rather than the raw IP — VirusTotal, who.is, and Google on
  the site, plus AbuseIPDB on the IP — the standard "what is this connection"
  triage flow.

- **NET-044b — Outbound event webhooks.** The service can POST each engine event
  (the ActivityEvent stream) to configured HTTP(S) endpoints, signed with an
  `X-HG-Signature` HMAC-SHA256 of the body, with bounded exponential-backoff
  retries (retry on transport error / 429 / 5xx; 4xx is terminal). Config lives in
  the ACL-locked `%ProgramData%\HostsGuard\webhooks.json` (so the shared secret
  stays SYSTEM+Admins-only) and is settable via the loopback API
  (`GET`/`POST /webhooks`, secret redacted on read). Delivery is off until a URL
  is configured; enabling it via the loopback API takes effect without a restart.

- **NET-104 — Inbound-connection consent.** An *Inbound prompts* toggle on the
  Firewall Activity toolbar lets Notify/Learning mode also prompt on unruled
  inbound connections and produce a scoped inbound Allow/Block rule — closing the
  other direction for users who want it. Off by default (unsolicited inbound is
  noisy): inbound blocks are dropped without a prompt until enabled. New
  `Consent.SetInboundConsent` RPC; the opt-in persists in `consent_state.json`.

- **NET-119 — VPN-presence kill-switch.** A *VPN kill-switch* card on the Tools
  tab watches a chosen VPN adapter; whenever it goes down, HostsGuard forces
  default-outbound Block on every firewall profile so nothing leaks outside the
  tunnel, and restores the exact prior per-profile posture when it reconnects.
  Enforcement flips the profile default (like the consent-mode rails), so existing
  Allow rules still apply — keep one for the VPN client and the tunnel can
  reconnect. Opt-in, off by default; an engaged state survives a service restart
  without capturing its own block-all as the "prior". New
  `Firewall.GetKillSwitch`/`SetKillSwitch` RPCs; the config persists in
  `killswitch_state.json`.

## [0.11.0] — 2026-07-04

### Changed
- **NET-116 — Broadened accessibility regression gate.** The headless WPF smoke
  now also asserts that every icon-only (non-text) button carries an
  `AutomationProperties.Name` and every realized DataGrid column has a header
  label, across both themes — passing clean today and guarding the five main tabs
  against a11y regressions.

### Added
- **NET-097 (manifest) — winget package manifest.** A validated winget manifest
  (`winget/`, schema 1.6.0, `SysAdminDoc.HostsGuard`) is ready to submit to
  microsoft/winget-pkgs — winget accepts the unsigned Inno installer (signing is
  required only for MSIX). The service self-update leg remains signing-gated.

- **NET-124 — Group live connections by country.** The Firewall Activity view
  gains a *Group by country* toggle (a triage axis alongside Group by app; combine
  both to nest country → app), persisted like the other view toggles.

- **NET-113 — Trust-by-publisher.** A consent prompt for a signed app now offers
  *Trust all software signed by "&lt;publisher&gt;"*; once trusted, any binary
  signed by that Authenticode publisher auto-allows without prompting (the
  simplewall #1727 ask). A Tools → *Trusted publishers* card reviews and removes
  them. New `Consent.GetTrustedPublishers`/`SetTrustedPublishers` RPCs and a
  `trust_publisher` decision flag; the set persists in `consent_state.json`.

- **NET-105 — Single-write bulk block/allow.** New `BlockMany`/`AllowMany` RPCs
  apply a whole selection in one DB update + one hosts-file reconcile instead of N
  per-domain rewrites (each of which was a separate AV-lock opportunity that could
  leave "blocked X of Y"). The feed and Managed Domains bulk actions now issue one
  RPC; `AllowMany` respects the settings lock.

- **NET-115 — "Block/Allow this site" from a live connection.** The Firewall
  Activity connections view gains right-click *Block this site (domain)* / *Allow
  this site (domain)* that pivot a connection to a durable hosts-file rule on its
  resolved hostname (the driver-free answer to rotating IPs), falling back to
  blocking the raw IP when the row has no resolved host.

- **NET-118 — Rule provenance column.** The Firewall Rules tab now shows an
  **Origin** column deriving why each rule exists from its HG_ name prefix —
  consent, learning, baseline, child-allow, temporary, app-scope, DoH/QUIC block,
  manual — plus adopted/system for non-HG_ rules, turning an opaque list into an
  auditable one.

- **NET-114 — CLI per-app firewall verbs.** `HostsGuard.Cli block-app <exe> [out|in]`
  creates the HG_ program-block rule and `unblock-app` removes it — scriptable
  per-app control to match the existing per-domain `block`/`allow`/`unblock` verbs.

- **NET-112 — Encrypted-DNS-only safety warning.** When the OS is configured to
  require encrypted DNS with no plaintext fallback, arming the DoH block (or
  "See everything") now warns that resolution could break if the DNS server
  changes — the current resolver is already exempted from the block, but a strict
  encrypted-only posture has no Do53 fallback. Best-effort detection via the
  Windows DoH per-interface `DohFlags`, surfaced on `DohStatus.dns_encrypted_only`.

### Security
- **NET-122 — SQLite pin regression gate.** A test asserts the bundled native
  SQLite stays ≥ 3.50.2, failing the build if the dependency ever regresses to the
  vulnerable 2.1.x bundle that would reopen CVE-2025-6965.

- **NET-110 — The settings lock now protects the hosts file.** Previously the
  lock gated firewall/mode/posture mutations but not hosts mutations, so an armed
  lock could not stop a desktop process from whitelisting a tracker or wiping
  every block (`Allow`/`Unblock`/`SetHostsText`/`EmergencyReset`/`TempAllow`/
  `Reconcile`/`RestoreBackup`). Those posture-*weakening* operations are now
  refused with a typed `locked` error when the lock is armed, while
  posture-*strengthening* `Block`/`BlockRoot` always proceed — locked means "can't
  weaken, can always strengthen."

## [0.10.0] — 2026-07-04

### Added
- **NET-099 — Allow-all / Block-all on a prompt burst.** The consent prompt gains
  *Allow all from this app* / *Block all from this app* buttons: one whole-app
  rule (per direction in the queue) answers every pending prompt from the same
  program at once — the fix for an app that fans out to many endpoints. Backed by
  a new `apply_to_app` flag on `ConnectionDecision`.

- **NET-101 — Time-boxed Learning-mode auto-lock.** The tray's Filtering-mode
  menu gains *Learning — 15 min, then lock* and *Learning — 1 hour, then lock*:
  the service arms a bounded Learning window and the consent sweep auto-reverts to
  Normal (deny-by-default) on expiry, leaving the auto-allowed batch for review in
  the Learning-review panel. The deadline persists across a service restart. Plain
  Learning is unchanged (unbounded). `FilteringMode` gains a `learn_minutes` field
  (SetMode arms the window; GetMode reports minutes remaining, shown in the mode
  status line).

- **NET-109 — TLS SNI capture (recover DoH-hidden hostnames).** A driver-free
  raw-socket capture (`SIO_RCVALL`, elevation the LocalSystem service already has —
  no kernel driver, no third-party capture library) reads the TLS ClientHello SNI
  from outbound HTTPS (TCP/443) segments and names connections whose DNS was
  resolved out-of-band (DoH). Recovered hostnames flow into the persistent
  resolved-host store (source `sni`), so the connections feed's Site column and
  the activity feed name the dial automatically. ECH-encrypted SNI carries no
  cleartext name and is reported as unavailable (never fabricated). Opt-in via a
  Tools → *Capture TLS SNI* toggle (new `SetSniCapture` RPC, schema-lock updated;
  `sni_capture` on `DohStatus`); off by default. The ClientHello parser
  (`Core.TlsClientHello`) and packet layer are fully unit-tested.

- **NET-108 — Link DNS → process → per-domain bandwidth.** The ETW kernel byte
  counters now also tally per-(PID, remote-IP), and the bandwidth aggregator maps
  each remote IP to its resolved domain (forward-DNS cache → persistent store) to
  attribute bytes per domain, keyed by the requesting process, in a new
  `domain_usage` table (schema v12). The Hosts Activity feed gains a **Data**
  column showing per-domain data volume (sent+recv), and `ActivityRow` carries a
  `bytes` field. Bare-IP dials with no DNS name contribute to no domain. This
  per-domain usage feeds the NET-094 quota work.

- **NET-098 — i18n wiring + first non-English locale (Spanish).** The i18n
  scaffold is now wired to real `.resx` resources with a `{svc:Loc}` XAML markup
  extension and a shipped Spanish satellite assembly (`Strings.es.resx`). The
  app's primary navigation (all five tab headers + the Hosts File sub-tabs) and
  the File/View/Help menus resolve from resources and render fully in Spanish; a
  new View → Language selector (System / English / Español) persists the choice
  to `config.json` and applies on the next launch (the culture is pinned before
  any window is built). Missing keys fall back to the English default so an
  incomplete locale never blanks the UI.

- **NET-095 — Adopt existing Windows Firewall rules (opt-in, non-destructive).**
  An *Import existing rules* button on the Firewall Rules tab reads the machine's
  current non-HG_ Windows Firewall rules into HostsGuard's view so onboarding
  isn't a blank slate — nothing on the live firewall is mutated. Adopted rules
  persist in a new `adopted_rules` table (schema v11) and are marked ★ in the
  Flags column, visually distinct from HG_-authored rules. New
  `AdoptFirewallRules` RPC (schema-lock updated) and an `adopted` flag on
  `FirewallRule`.

- **NET-093 — Child-process auto-allow (opt-in).** A new *Inherit to children*
  toggle on the Firewall Activity tab lets a direct child of an app that already
  has an HG allow rule inherit that allow — bounded to a 1-hour TTL rule
  (`HG_Child_*`, reaped on expiry and on restart) — instead of raising a fresh
  consent prompt for every child an installer/updater spawns. One level deep,
  allow verdicts only, and off by default so deny-by-default is preserved. The
  service resolves a connection's parent PID + image path via
  `ProcessTree.GetParent` (`NtQueryInformationProcess`); new `SetChildInherit`
  RPC (schema-lock updated) and a `child_inherit` flag on `GetMode`.

- **NET-107 — In-app AI-knowledge review & promote panel.** A new *AI knowledge
  review* card on the Tools tab lists what the AI has learned (all, or only what's
  new since your last review), with per-row **Promote** (into a persisted
  user-override store that beats the AI and survives restart), **Discard**, and an
  editable "promote as" value. A *Correct a domain* mini-form and a right-click
  *Fix purpose…* / *Fix category…* on the Hosts Activity feed re-label a domain
  directly; the correction is remembered and wins over both the curated tables and
  the AI everywhere the label is resolved (feed purpose, categorization). New
  `ListAiKnowledge`/`PromoteKnowledge`/`OverrideKnowledge` RPCs (schema-lock
  updated), a `user_overrides` table (schema v10), and a themed `InputDialog`
  behind an `IPrompt` seam.

- **NET-089 — Full portable-policy export/import.** File → *Export policy (JSON)*
  writes one versioned JSON document covering managed domains (status, category,
  notes, reason, source), HG_-authored firewall rules, scheduled block windows,
  named rule-set profiles, the settings-lock state (armed flag + password hash,
  never plaintext), network→profile auto-switch mappings, allow/blocklist
  subscriptions, and carried meta settings. *Import policy (JSON)* reconstructs
  the whole policy on a clean machine and reconciles the hosts file to match; the
  round-trip is idempotent (re-applying the same document changes nothing). New
  `Policy.ExportPolicy`/`ImportPolicy` RPCs (schema-lock updated), a versioned
  `HostsGuard.Core.PortablePolicy` DTO, and CLI `export-policy`/`import-policy`
  subcommands give the UI, CLI, and service the same capability. Import respects
  the settings lock.

## [0.9.13] — 2026-07-03

### Changed
- **Dependency alignment.** The stray 8.0.x framework packages
  (`System.Diagnostics.EventLog`, `System.Management`,
  `Microsoft.Extensions.DependencyInjection`) are re-pinned to 10.0.9 to match the
  runtime and inherit .NET 10 servicing; `MaxMind.Db` → 5.1.0 and the test SDK →
  18.7.0. Full suite green after the bumps.
- **Tabs grouped by domain.** Order is now Hosts Activity → Hosts File →
  Firewall Activity → Firewall Rules → Tools, so the hosts views sit together
  and the firewall views sit together instead of interleaving.

### Added
- **Export connection history to CSV.** The Firewall Activity → History card has
  an "Export CSV" button that writes the loaded connection history (time,
  process, PID, protocol, remote, port, country, firewall status) to a CSV file
  for reporting — RFC-4180 quoted, opens cleanly in Excel.
- **One-click "See everything" (close DNS bypass).** A prominent toggle in the
  Tools tab enables the QUIC/UDP-443 and DoH-bootstrap firewall blocks together,
  forcing browsers doing their own encrypted DNS back onto the OS resolver — so
  ad/tracker domains they load finally appear in the activity feed and can be
  blocked. Fixes "ads load but never show up."

## [0.9.12] — 2026-07-03

### Added
- **Unblock from the feed.** A new "Unblock (remove from hosts)" right-click
  action on the Hosts Activity feed removes the selected domains' `0.0.0.0`
  entries so they resolve again — bulk-capable, distinct from "Allow" (which also
  whitelists against future blocklists).
- **"Blocked only" troubleshooting filter.** A one-click toggle shows *only*
  currently-blocked domains (overriding "Hide blocked"): refresh a page, see
  exactly what HostsGuard blocked, and right-click → Unblock to test. Blocked
  status now renders in red so an over-block is easy to spot.

## [0.9.11] — 2026-07-03

### Changed
- **Cleaner, consolidated hosts-file categories.** Categorization now uses a
  small canonical taxonomy (Advertising, Tracking & Analytics, Telemetry, CDN,
  Streaming, Gaming, Email & Marketing, Gambling, Adult, Malware, Social Media,
  Other) instead of dozens of fragmented per-vendor sections ("Snapchat
  Tracking", "LinkedIn CDN", "Oracle Maxymiser", …). A new `Canonicalize` step
  folds any legacy or AI-assigned label into the taxonomy, and the service
  re-files an existing hosts file into these sections once on start (idempotent).

### Added
- **Promoted the machine's AI-learned knowledge into the shipped curated tables.**
  ~14 new domain→category mappings and 55 new domain→purpose annotations
  reviewed from the AI knowledge log are now built in, so fresh installs
  categorize and annotate them offline with no API key.

### Fixed
- **Bulk block/allow now applies to every selected feed row.** The Hosts
  Activity "Block" and "Allow" menu items were bound to the singular
  `SelectedItem`, so a multi-selection only blocked/allowed one domain. They now
  act on the whole selection and report "blocked X of Y" if any fail (e.g. a
  transient hosts-file lock) instead of silently dropping the rest.

## [0.9.9] — 2026-07-03

### Fixed
- **Bulk hide now hides every selected domain.** The feed's "Hide domain" menu
  was bound to the singular `SelectedItem`, so hiding a multi-selection only hid
  one row. It now sends the whole selection in one call (menu relabeled "Hide
  domain(s)"); multi-select with Ctrl/Shift, then right-click within the
  selection to hide them all.

## [0.9.8] — 2026-07-03

### Fixed
- **Right-clicking a feed/connection/rule row now selects it first.** WPF grids
  don't select on right-click, so context-menu actions (Hide domain, Block,
  Allow, …) acted on the previously *left-clicked* row — right-clicking a domain
  and choosing "Hide domain" hid a different row and left the one you clicked
  visible. Every grid now selects the row under the pointer before its menu
  opens (an existing multi-selection is preserved).
- **SRV / underscore domains can now be hidden.** The hide RPC required names to
  pass registrable-domain validation, which silently rejected real feed entries
  like `_ldap._tcp.dc._msdcs…` and `_stun._udp…` — they could never be hidden.
  Hiding is a per-row display flag, so it now accepts any feed key.

## [0.9.7] — 2026-07-03

### Added
- **Generic shield app + tray icon** — a clean mauve-gradient shield replaces the
  previous icon across the executable, window/tray, and installer.

### Accessibility
- **Locked in screen-reader names across every tab (NET-088).** The headless WPF
  smoke test now walks all five tabs in both themes and asserts every
  text/combo/password input exposes an `AutomationProperties.Name` — a new
  unnamed field now fails the suite instead of silently shipping a control a
  screen reader can't announce.

### Security
- **Narrowed the control-pipe + session-token grant from Authenticated Users to
  INTERACTIVE (NET-087).** The bearer token that authorizes every IPC call was
  readable by any authenticated principal — including service accounts and, over
  SMB, remote (NETWORK) logons. It is now granted only to the INTERACTIVE group
  (the desktop console/RDP user), which also excludes remote clients without
  needing a reject-remote flag the Kestrel named-pipe transport doesn't expose.
  Preserves the no-UAC unelevated-mutation UX (the interactive user is trusted).

## [0.9.6] — 2026-07-03

Post-audit UX/perf/security polish and README screenshots.

### Security
- **Closed the SSRF DNS-rebinding window in list fetching.** The guard resolved
  and validated a blocklist/allowlist host, but `HttpClient` re-resolved for the
  actual GET — a rebinding server could return a public IP to the guard and a
  private one to the fetch. The fetcher now dials through a `ConnectCallback`
  that re-resolves and connects only to a public address, so the socket can
  never reach loopback/private/link-local/metadata regardless of the second
  lookup.

### Fixed
- Settings-lock password field now clears after arm/disarm/unlock instead of
  leaving the masked value on screen.
- Loopback API domain mutations catch a locked hosts file (AV hold) and return
  a clean 503 instead of an exception that could stop the listener.
- Exiting with unsaved Raw Editor changes now prompts before discarding them.

### Changed
- Live firewall-connection upserts use a keyed index (O(1)) instead of scanning
  every row on each event.
- The History and Learning-review cards show guidance text when empty instead
  of a blank grid.
- "Hide this group" is now also on the row right-click menu, so the whole-group
  hide is reachable by keyboard, not just the group header.
- Tooltips have rounded corners, matching the app's corner-radius scale.

### Docs
- README now shows dark + light Hosts Activity screenshots captured from the
  .NET WPF app (replacing the removed Python-era `screenshot.png`).

## [0.9.5] — 2026-07-03

Deep engineering + quality audit pass.

### Security
- **AI endpoint must be https.** The DeepSeek categorizer sends the API key as
  a Bearer header; a misconfigured `http://` endpoint would leak it in
  cleartext. The completer now fails closed (refuses to send the key over a
  non-https endpoint) and `SetAiConfig` rejects one up front.

### Fixed
- **File errors on import/export were misreported as "service unavailable."**
  The menu-bar export/import commands and the CLI `export` had no file-I/O
  error handling; a bad path or permission denial threw an uncaught
  `IOException`, which the app's global handler classifies as lost
  connectivity. File I/O is now caught and surfaced in the status bar (app) or
  as a clean error + exit 2 (CLI).

### Changed
- **Singular-aware status counts.** Status lines across every tab (feed,
  connections, managed domains, firewall rules, blocklists, schedules,
  intelligence, bandwidth/timeline, export) now read "1 domain" / "2 domains"
  instead of "1 domains", via a shared `Plural` helper.

## [0.9.4] — 2026-07-03

### Fixed
- **Hidden entries came back.** Same class of bug as Hide blocked: the live DNS
  stream had no hidden filtering, so a domain hidden via "Hide root" (or the new
  domain hide) reappeared the moment it resolved again. The service now stamps
  each live event with its authoritative hidden state (exact-domain or
  hidden-root), and the feed drops hidden events unless Show hidden is on — so
  hides stick.

### Added
- **Hide domain** — a new context-menu action that hides just the exact domain
  under the cursor, alongside the existing **Hide root** (which still hides the
  whole root including future subdomains). Both are remembered.
- **Hide this group now stores the listed domains.** Right-clicking a
  group-by-root header hides every exact domain currently listed under that root
  (remembered) rather than blanket-hiding the root — so a new subdomain that
  shows up later still surfaces.

## [0.9.3] — 2026-07-03

### Fixed
- **"Hide blocked" now actually hides.** The live DNS feed's blocked flag was
  always false (the ETW monitor can't know a domain's managed status), so the
  stream kept re-adding blocked domains as normal rows right after the snapshot
  hid them. The service now stamps each live event with the authoritative
  managed status from the DB — the same source the snapshot uses.
- **View no longer opens "smushed."** The DataGrid column-width repair (WPF
  clamps columns to minimum width on a first layout with no viewport) is now
  applied to every primary tab grid, not just the connections grid — no more
  needing Reset view + a theme toggle to fix the columns.

### Added
- **Hide reverse DNS** toggle on Hosts Activity — hides `*.in-addr.arpa` /
  `*.ip6.arpa` PTR lookups, which are background noise rather than real
  destinations.
- **Hide a whole group by right-clicking its header.** With Group by root on,
  right-click any root section band → "Hide this group" (hides the root; Show
  hidden brings it back).
- **View settings are remembered across restarts.** Group by root, Hide
  blocked, Show hidden, Hide reverse DNS (Hosts Activity) and Group by app,
  Resolve IPs (Firewall Activity) persist to config and restore on launch.

## [0.9.2] — 2026-07-03

### Fixed
- **"Resolve IPs" now works and remembers results.** Reverse-DNS moved from a
  fragile client-side path to the service, exposed as a `ResolveHosts` RPC
  (bounded concurrency, 3s per-lookup timeout). More importantly, every
  resolved IP→host mapping — both reverse-DNS (PTR) results and the live
  forward-DNS the monitor already sees — is now **persisted** in a new
  `resolved_hosts` table (schema v9). Connection events fill their Site column
  from this store automatically, so once an IP is resolved it always shows its
  host on every future sighting, across restarts, with no need to re-check the
  box. The checkbox now only resolves addresses that are still unknown.

## [0.9.1] — 2026-07-03

Knowledge-promotion release: reviewed field data from the AI knowledge log is
now baked into the shipped defaults, so fresh installs are informative out of
the box — no API key required.

### Added
- **~120 curated purpose entries** promoted from reviewed AI research —
  Google/Microsoft/Xbox/Steam/Dropbox/GitHub/Adobe/Yandex infrastructure, AI
  APIs, package registries, ad networks, trackers, consent platforms,
  certificate authorities, and blocklist sources — plus pattern rules:
  `*.in-addr.arpa` → "Reverse DNS lookup (PTR)" and `stun.*` → "STUN server",
  which alone de-noise dozens of feed rows.
- **Curated category defaults** (new `DomainCategories` table) for ~45
  universally-agreed ad/tracking/telemetry domains in the hosts-file section
  style ("Google Ads", "Microsoft Telemetry", "Major Ad Networks"). Blocking
  any of them auto-assigns the category with zero AI involvement, and AI
  Categorize consults the curated table first — only unknown domains spend
  API tokens. Curated categorization also works with no key configured.

### Fixed
- **Null-selection crash** (found in this machine's crash log): right-clicking
  Block / Hide root / Research / Block remote IP with no row selected passed a
  null domain into the RPC layer and threw. All context-menu commands now show
  "Select a row first" instead.

## [0.9.0] — 2026-07-03

### Added
- **Menu bar** — a themed File / View / Help strip above the tabs.
  - **File**: Import hosts file… (replaces the live file after a confirm,
    snapshotting a backup first), Export hosts file…, Export managed domains
    as JSON (with categories), Export AI knowledge, Save hosts file (Raw
    Editor changes), Backup hosts file, Exit.
  - **View**: checkable toggles for Group by root / Hide blocked / Show
    hidden / Group by app / Resolve IPs, a UI-scale submenu, theme toggle,
    **Reset view** (every filter and toggle back to defaults at 100%), and
    **Refresh all** (re-queries every tab).
  - **Help**: GitHub repository link and About.

### Changed
- **Group-by-root headers restyled** — flat, styled section bands (accent
  root name + domain count) with the normal grid rows directly beneath, so
  the grouped feed reads exactly like the ungrouped one, just sectioned.
  Replaces the expander-based headers from 0.8.1.

## [0.8.1] — 2026-07-03

### Added
- **Group by root (Hosts Activity)** — a toolbar toggle that collapses
  subdomain noise under expandable root-domain headers with counts (thirty
  CDN hostnames become one `live-video.net (30)` group). Rows stay individual
  underneath, so every context-menu action still works per-subdomain.
  Composes with search, "Hide blocked", and "Show hidden".

## [0.8.0] — 2026-07-03

AI knowledge release: DeepSeek research across the whole product, with every
result recorded in a reviewable knowledge log (the promotion path into the
app's curated built-ins).

### Added
- **AI purpose research (Hosts Activity)** — the "AI purposes" button has
  DeepSeek research every feed domain missing a Purpose and fills the column
  with a concise description ("Steam game content delivery"). Curated purposes
  always win; learned ones fill the gaps and persist across restarts.
- **Resolve IPs + AI identify (Firewall Activity)** — a "Resolve IPs" checkbox
  reverse-DNS-resolves remote addresses the live DNS cache didn't cover
  (throttled, cached), and "AI identify" fills a new **Info** column with a
  short explanation of what each connection is likely for ("Chrome syncing
  browsing data to Google"). Identifications persist and auto-apply to future
  sightings of the same host.
- **AI Categorize (Managed Domains + Raw Editor)** — one click has DeepSeek
  categorize every hosts-file entry (including entries HostsGuard doesn't
  manage — they're adopted into the DB) and organize the file under
  "# Category" sections. The file's existing section names are passed to the
  model as the preferred vocabulary, so your hand-made organization is reused,
  not replaced.
- **AI knowledge log** — everything DeepSeek learns (purposes, categories,
  connection identifications) lands in a persistent `ai_knowledge` store
  (schema v8). "Export AI knowledge" in Tools writes it to
  `%APPDATA%\HostsGuard\ai_knowledge.json` for review and for promoting
  entries into the app's built-in purpose/category tables.

## [0.7.0] — 2026-07-03

Feature release: site names on live connections, downloaded blocklist
intelligence with block-candidate flagging, and DeepSeek AI categorization
that organizes the hosts file the way you already do by hand.

### Added
- **Site column on Firewall Activity** — live connections show the domain each
  remote IP was resolved as, fed by the ETW DNS pipeline (a new IP→domain
  cache). Unlike reverse PTR, a CDN IP maps to the site the machine actually
  asked for. The name can land a moment after the first sighting.
- **Blocklist intelligence** — every catalog blocklist (HaGezi, StevenBlack,
  OISD, AdAway, …) is downloaded into a local reference index on first service
  start and weekly after that — never imported as blocks. Hosts Activity
  domains found on any reference list render **yellow** with a "Lists" column
  and a tooltip naming the lists — a clear block-candidate signal. Tools gains
  an intelligence status card with a manual refresh.
- **AI categorization (DeepSeek)** — add a DeepSeek API key under Tools and
  HostsGuard buckets blocked domains into hosts-file categories in your
  existing "# Google Ads / # Microsoft Telemetry" style, persists them to the
  Category column (new on Managed Domains), and re-homes the hosts entries
  under matching "# Category" section headers (existing hand-made sections are
  appended to, never rewritten). With auto-categorize on, every new manual
  block is filed automatically; "Categorize uncategorized domains" back-fills
  the rest. The key lives in the service's ACL-locked data folder and is
  write-only over RPC.

### Fixed
- **Monitor status flags** — `status`/CLI reported dns=off/connections=off
  unconditionally (hardcoded); they now reflect the live ETW monitor and
  connection feed state.

## [0.6.6] — 2026-07-03

### Fixed
- **Intermittent "can't reach its background service" on block/allow** — three
  bugs stacked. Antivirus briefly holds the hosts file open to scan it after
  every change, so a follow-up block hit a sharing violation; the raw exception
  escaped the service handler as an opaque gRPC error; and the app classified
  every gRPC error as lost connectivity, telling the user to restart a service
  that was healthy the whole time. Now: the hosts write retries for ~1 s
  (rides out the scan), a persistent hold returns a calm typed error in the
  status line ("hosts file is locked by another program…") instead of a popup,
  and the service-unavailable dialog only appears for actual transport
  failures (reproduced with rapid consecutive blocks before the fix; clean
  after).

## [0.6.5] — 2026-07-03

### Fixed
- **Dark-mode context menus** — the menu container and its separators still
  rendered in system (light) colors: the ContextMenu default template ships
  its own chrome, and menu separators resolve `MenuItem.SeparatorStyleKey`
  rather than the implicit Separator style. Both are now fully themed
  (rounded, token-colored) in dark and light, including the tray menu and
  every grid's right-click menu.

### Added
- **Hide blocked** toggle on the Hosts Activity feed — hides domains that are
  already blocked (snapshot and live events) so the feed shows only traffic
  that still needs a decision; the status line reports how many were hidden.

### Verified
- Blocking writes hosts entries as `0.0.0.0 domain.com` — confirmed end-to-end
  against the live service (CLI block → hosts-file entry → unblock cleanup).
  This has been the engine's format since the .NET port.

## [0.6.4] — 2026-07-03

Third premium-polish pass: the remaining system-chrome surfaces now follow the
theme, search became live everywhere, and a long-standing grouped-grid layout
bug was found and fixed.

### Fixed
- **Live-connections grid collapse** — the grouped Firewall Activity grid could
  render every column at minimum width (a WPF race: the grid's internal scroll
  viewport reports zero when the tab first realizes, the width distribution
  clamps all columns, and no public invalidation path recovers). A visibility
  guard now revives the scroll host and reruns the width computation. This bug
  predates this release.
- **Status-bar counters** — the old Run markup rendered "Hosts blocked:1234"
  with no space; counters now read "Hosts file: N · Blocked: N · Allowed: N"
  with explanatory tooltips.
- **Firewall Rules search** — the filter now also matches the service column,
  which its tooltip already promised.
- **Learning review loads on connect** — the card populated only after a manual
  Refresh; it now loads with the rest of the tab.
- **CLI help** — `help`, `--help`, `-h`, `-?`, and `/?` print usage and exit 0
  (falling into usage from an unknown command still exits 1).

### Changed
- **Search-as-you-type** — Hosts Activity, Managed Domains, and Firewall Rules
  re-query 350 ms after typing stops (matching the live Firewall Activity
  filter) instead of waiting for Refresh; a down service degrades to a calm
  status line. Search and entry fields across the app gained watermark hints.
- **Themed system chrome** — scrollbars, expander chevrons, grid column headers
  (hover + sort indicators, resize grippers preserved), context/tray menu items
  (token highlight, check-glyph support), and status-bar separators now render
  from Hg.* tokens instead of Aero system colors in both themes.
- **Interaction polish** — buttons gained hover shades (new `Hg.AccentHover`
  token; dark `Hg.DangerHover` retuned for white-text contrast), text inputs
  and combos show hover borders, the active tab carries an accent indicator,
  combo text no longer underlaps the chevron, and the checkbox glyph switches
  to `Hg.OnSel` for correct contrast in both themes.
- **Clearer shell** — "FW" tabs spell out Firewall, the tray menu checkmarks
  the active filtering mode, the UI-scale picker shows percentages, timestamps
  in activity/history/decision grids display compactly ("14:32:07" today)
  instead of raw ISO strings, the raw hosts editor flags unsaved changes,
  consent history explains its empty state, the blocklist health column is
  labeled, and the settings-lock card names its password field and unlock
  window.

## [0.6.3] — 2026-07-03

Second premium-polish pass focused on interaction-state consistency, visible
policy-authoring guidance, and clearer Tools trust feedback.

### Changed
- **Design system — semantic button states** — neutral, accent, and danger
  buttons now keep their semantic color on hover/press instead of collapsing
  back to the neutral surface treatment.
- **Accessibility — stronger keyboard focus** — tab headers and DataGrid cells
  now expose visible token-based focus geometry in both themes.
- **UX — clearer policy authoring** — the FW Rules create form now uses visible
  labels, a short ownership explanation, and a less cramped grid layout.
- **Tools — clearer trust/status feedback** — DNS intelligence, Secure Rules,
  Defender, and general Tools status messages now sit in tokenized status
  strips with polite live-region announcements.
- **Microcopy — schedule/profile guidance** — scheduled blocking, network
  profiles, DNS, and maintenance cards now explain accepted inputs and expected
  outcomes without relying on tooltips.

### Fixed
- **Smoke coverage — refined guidance stays present** — the WPF smoke now
  switches through FW Rules and Tools to verify the visible guidance survives in
  both dark and light themes.

## [0.6.2] — 2026-07-03

Premium polish pass across the WPF shell, prompts, CLI recovery copy, and
service-test reliability.

### Added
- **UI — consistent empty states** — Hosts Activity, FW Activity, Managed
  Domains, Blocklists, FW Rules, and Schedules now show clear helper text
  instead of blank tables when there is no matching data.
- **UX — themed confirmation dialog** — destructive policy actions now use a
  tokenized HostsGuard dialog with calmer copy, safer button ordering, and
  keyboard focus on the non-destructive action.
- **Tests — command disabled-state coverage** — added WPF ViewModel tests that
  prove blank block/inspect/create/save/restore actions stay disabled until the
  required input exists.

### Changed
- **Design system — shared control polish** — buttons, text/password inputs,
  checkboxes, ComboBoxes, DataGrid rows/cells, and reusable section/empty-state
  text now share tighter spacing, visible focus, hover/disabled states, and
  token-based theming in both dark and light modes.
- **Microcopy — service recovery and consent flow** — service-unavailable text,
  filtering-mode descriptions, consent prompt buttons, blocklist/lockdown
  confirmations, and CLI errors now describe what happened and how to recover.
- **Accessibility — stronger labels and focus targets** — icon/text controls and
  form fields across the WPF shell gained clearer AutomationProperties names,
  tooltips, and explicit disabled affordances.

### Fixed
- **Test determinism — firewall scheduler race** — service schedule tests now
  disable the background timer explicitly instead of racing a real-time sweep
  against deterministic `SweepAt(...)` assertions.

## [0.6.1] — 2026-07-02

Deep audit hardening pass.

### Fixed
- **Security — per-app "block Internet" had a coverage gap** — the hand-typed
  Internet CIDR set skipped all of `172.x`, so a scope-block rule failed to
  cover public addresses in `172.0–15` and `172.32–255` (only `172.16/12` is
  private). It also over-included CGNAT (`100.64/10`) and link-local
  (`169.254/16`) that the classifier treats as LAN. The set is now generated
  from the same excluded-range list `IsLan()` uses — gap-free and self-
  consistent — with a containment regression test proving every public sample
  is covered and every private/reserved address is not.
- **UX — calmer service-unavailable dialog** — a dropped/absent service
  connection surfaced a raw `StatusCode=Unavailable` gRPC dump in an error
  dialog; connectivity failures now show a calm, actionable message.
- **Accessibility — ComboBox focus ring** — a Tab-focused ComboBox had no
  visible focus indicator (WCAG 2.4.7); added a themed focus-ring trigger.
- **Visual — themed CheckBox** — the CheckBox was the only control without a
  themed template, falling back to the light default WPF box that clashed with
  the dark controls; added a tokenized template with check glyph, hover, and
  keyboard focus.

## [0.6.0] — 2026-07-02

Roadmap-drain release: the entire 2026-07-02 research batch (NET-044, 070, 071,
073, 074, 076, 077, 079, 083, 084, 085) plus the .NET 10 LTS migration (081).
The one strategic spike, NET-086 (local DNS forwarder), was decided **NO-GO** —
HostsGuard stays an observer/enforcer that fails open, never a resolver (full
rationale + revisit criteria in RESEARCH.md § Design Decisions). Only
operator-gated items (NET-052 code signing and its dependents) and a deferred
loopback-webhook sub-item (NET-044b) remain.

### Added — optional headless JSON-RPC/OpenAPI loopback (NET-044)
- **Loopback API (off by default)** — set `HG_LOOPBACK_API=1` to expose a
  token-authed HTTP surface on `127.0.0.1:HG_PORT` (default 7847): `GET /status
  /stats /domains /log /openapi.json` and `POST /domains {action, domain}`.
  1 MB body cap, `hostsguard.error.v1` error shape, `X-HG-Token` header
  (minted to `%ProgramData%\HostsGuard\loopback_token` in the ACL-locked dir),
  the active port advertised in the OpenAPI `servers` list, `/log` validates
  `limit` and filters by `action`/`reason`, and `POST` respects the settings
  lock. Built on in-box `HttpListener` — no extra dependency; the request
  router is a pure method (fully unit-tested without a socket).

### Added — consent-prompt micro-features (NET-085)
- **Reputation lookup** — the consent prompt has a "look up ↗" link that opens a
  VirusTotal search for the process (or remote IP), one click from the decision.
- **Most-triggered apps** — the FW Activity decisions panel ranks the top 5 apps
  by how often they trigger consent decisions.
- **Optional block sound** — a "Sound on block" toggle plays a system sound when
  a new connection is blocked/prompted (off by default; persists in config.json,
  foreign keys preserved).

### Added — firewall rule scheduler (NET-084)
- **Scheduled firewall rules** — a schedule target prefixed `fw:` names an HG_
  firewall rule instead of a domain: the rule is enabled inside its weekly
  window (cross-midnight supported) and disabled outside, so a rule can be
  time-of-day gated without deleting it (NetLimiter-style). Only HostsGuard's
  own rules are ever touched; domain schedules keep working unchanged.
  (Bandwidth throttling is deliberately out — quota tracking/notify only.)

### Fixed
- **Test determinism** — the service test assembly no longer runs collections
  in parallel; the process-global SQLite `ClearAllPools` / pipe-ACL teardown
  occasionally cross-tripped an unrelated test under parallel load.

### Added — automatic network-profile switching (NET-083)
- **Auto profile switch** — HostsGuard fingerprints the joined network by its
  default-gateway MAC (stable per LAN, DHCP-independent) and auto-activates the
  profile you mapped to it: stricter posture on untrusted/public Wi-Fi, relaxed
  at home. A Little Snitch premium feature with no free-Windows analog. Mapping
  is user-editable (Policy RPCs GetCurrentNetwork / GetNetworkProfiles /
  SetNetworkProfile); switches route through the same recoverable, logged path
  as a manual switch and fire once per network change.

### Added — settings/rule lock + hosts write protection (NET-079)
- **Settings lock** — arm a password lock (Tools tab) that refuses filtering-
  mode, firewall-posture, and HG_ rule changes until unlocked, with an optional
  timed unlock (1–240 min) so you're not re-prompted constantly (TinyWall's
  pattern). Password is PBKDF2-SHA256 (210k iterations, self-describing hash);
  the lock state persists but the timed-unlock window resets on service restart.
  Enforced service-side on SetMode, SetGlobalMode, SetDefaultOutbound,
  CreateRule, DeleteRule, and per-app scope blocks.
- **Hosts write protection** — one-click enforcement of the SYSTEM+Admins-only
  DACL on the hosts file (Tools tab), so malware or a non-admin can't silently
  rewrite it. New Policy RPCs GetLockState / SetLock / Unlock /
  SetHostsProtection (schema-lock updated deliberately).

### Added — blocklist source health + mirror fallback (NET-077)
- **Mirror fallback** — curated sources carry a fallback URL; when the primary
  fetch fails the importer retries the mirror before giving up (HaGezi,
  StevenBlack, OISD wired). A ↔ mirror flag shows which sources have one.
- **Merge health report** — import now scans the list and reports duplicates
  dropped, invalid lines dropped, **hosts-hijack entries** (a domain pointed at
  a routable IP rather than a sink like 0.0.0.0 — the StevenBlack hijack check;
  excluded from the block set), and how many imported domains an allowlist kept
  unblocked. Surfaced inline in the Blocklists status line and the event log.
  Per-source enable/disable already exists via subscribe/unsubscribe.

### Added — global outbound modes + per-app scope blocks (NET-076)
- **Global outbound selector** — a tray "Global outbound" submenu applies
  Block-all or Allow-all outbound posture (default-outbound action on every
  profile) without a restart; never touches the firewall on/off switch.
- **Per-app scope blocks** — right-click a connection → "Block app scope" to
  block a program's access to the **Internet** (public ranges), **LAN**
  (RFC1918/CGNAT/link-local/ULA), **localhost** (loopback), or all **inbound**
  — Portmaster-style scope rules built from explicit CIDR sets (COM can't
  negate, so Internet is the complement set).
- **Block-P2P heuristic** — connections to a raw public IP with no preceding
  DNS lookup are flagged **DIRECT-IP** in FW Activity. The ETW resolution event
  now yields resolved A/AAAA addresses, correlated against later connections
  within a 10-minute window (LAN/localhost never count). A classic malware /
  P2P signal HostsGuard can compute from its own DNS+connection pipeline.

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
