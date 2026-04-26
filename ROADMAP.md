# HostsGuard Roadmap

Real-time network privacy manager for Windows — DNS activity, hosts file, Windows Firewall, connection monitor. Roadmap focuses on deeper protocol coverage, automation, and pro-grade analysis.

## Planned Features

### DNS & Resolver
- **DoH/DoT sniffing** — integrate `pktmon` or `Npcap` to capture DNS-over-HTTPS/TLS queries that bypass `Get-DnsClientCache`
- **Resolver switcher** — one-click switch between system resolver and Cloudflare / Quad9 / NextDNS / AdGuard DNS with per-interface apply
- **DNS response inspection** — show A/AAAA/CNAME chains, TTLs, NXDOMAIN vs blocked, resolver latency
- **Chrome/Edge DoH override** — detect browser-level DoH and prompt to disable or route through system resolver
- **PTR on demand** — reverse DNS chips on connection rows with LRU cache

### Blocklists & Policy
- **Scheduled blocklist refresh** — cron-style auto-update of imported lists with diff summary (X added, Y removed)
- **Rule groups** — label domains by source ("my custom", "OISD", "malware") for selective disable/enable
- **Temporary allow** — allow a domain for N minutes, auto-revert
- **Per-process allow/block** — rule keyed to `process.exe` + remote host, not just global
- **Regex/wildcard hosts entries** — resolver-side matching via a small WFP callout or transparent proxy; hosts file stays flat

### Firewall & Process
- **Process tree view** — parent/child PID column so you can see `svchost.exe -k NetworkService` descendants
- **Signed-binary badge** — Authenticode signature status on each process (Microsoft / trusted vendor / unsigned)
- **Rule diff** — compare current firewall state to a saved baseline, show drift
- **Learning-mode pause** — suppress new-process prompts during app installs
- **SID/AppContainer awareness** — break out rules for UWP apps via package family name

### Analysis & Export
- **Session recording** — record a timestamped capture of all DNS+conns for N minutes, save as `.hgsession`
- **CSV/JSONL connection dump** — structured export for Splunk/Grafana
- **GeoIP locally (MaxMind mmdb)** — offline GeoIP lookup with ASN, drop dependency on ip-api.com rate limits
- **Threat intel overlay** — cross-reference remote IPs against local URLhaus / Feodo / abuse.ch lists

### Platform & Distribution
- **Headless service mode** — optional background service with JSON-RPC, GUI becomes a thin client
- **PowerShell CLI** — `hostsguard block <domain>`, `hostsguard status`, `hostsguard rules export` for scripting
- **Portable mode** — `--portable` stores everything next to the exe instead of `%APPDATA%`
- **MSI/signed installer** — Authenticode-signed MSI with uninstall cleanup of `%APPDATA%` data on user choice

## Competitive Research
- **Pi-hole / AdGuard Home** — network-wide DNS blocker; HostsGuard is the single-host complement. Borrow the query-log UX and group-based policy.
- **SimpleWall** — minimalist Windows Firewall front-end with per-app rules; confirm our rule UX stays at least as fast.
- **GlassWire / Wireshark** — connection visualization and deep packet inspection. GlassWire proves users want per-process bandwidth timelines — worth adding.
- **NetLimiter** — per-process bandwidth shaping; not in scope but connection-level per-app visibility is a clear adjacency.

## Nice-to-Haves
- Sparkline timeline per domain showing hit rate over 24h
- "Explain why blocked" popover listing the rule and source list that matched
- Integration with Malwarebytes / Defender exclusions so HostsGuard doesn't fight them
- Minimal Gtk/Qt port for Linux targeting `systemd-resolved` + nftables
- Browser companion extension that reports in-tab fetch targets back to the app for richer attribution
- WSL2 guest visibility — surface connections from inside WSL distros

## Open-Source Research (Round 2)

### Related OSS Projects
- WinFIM.NET — https://github.com/OWASP/www-project-winfim.net — OWASP Windows FIM; Windows service, Native Event Log, JSON/text output — closest architectural analog
- Achiefs/fim — https://github.com/Achiefs/fim — Rust cross-platform FIM; real-time, ElasticSearch-ingestible events
- OSSEC — https://github.com/ossec/ossec-hids — HIDS with FIM + Windows registry monitoring + active response (can auto-restore a tampered file)
- Wazuh — https://github.com/wazuh/wazuh — OSSEC fork; unified XDR/SIEM, modern dashboard, FIM module
- Tripwire Open Source — https://github.com/Tripwire/tripwire-open-source — classic baseline/integrity model
- Saurabh2402/File-Integrity-Monitor — https://github.com/Saurabh2402/File-Integrity-Monitor — hash-baseline tutorial reference
- StevenBlack/hosts — https://github.com/StevenBlack/hosts — upstream canonical blocklists; HostsGuard should offer to restore FROM a trusted upstream, not just a local baseline
- Pi-hole — https://github.com/pi-hole/pi-hole — gravity restore pattern worth borrowing for "known-good" comparison
- HostsFileGet (sibling repo) — complementary project; HostsGuard should integrate its output as a trusted baseline source

### Features to Borrow
- **Windows Event Log + JSON sink** (WinFIM.NET) — log all tamper events to Application event log with structured JSON so enterprise SIEMs can ingest without custom parsers
- **Active response: auto-restore on tamper** (OSSEC) — on diff detection, replace hosts file from trusted baseline and alert (user-configurable)
- **Registry monitoring for `HKLM\...\Tcpip\Parameters\DataBasePath`** (OSSEC Windows) — malware commonly redirects the hosts path via registry; monitor that too
- **SHA-512 hash baseline** (Saurabh2402) — strong-hash baseline per-file, not just mtime; detect time-preserved tampering
- **ReadDirectoryChangesW real-time watcher** (Achiefs/fim) — sub-second detection, much lighter than poll loops
- **Baseline refresh on user intent** (Tripwire workflow) — explicit "I just updated hosts via HostsFileGet, re-baseline" button rather than silent auto-accept
- **ACL hardening** — set `hosts` to deny-write for all but SYSTEM, add file auditing SACL to generate 4663 events
- **Trust-chain restore from HostsFileGet** — if tampered, offer restore from (a) last-known-good baseline, (b) HostsFileGet cache, (c) StevenBlack upstream

### Patterns & Architectures Worth Studying
- OSSEC's **syscheck daemon model** — baseline DB + periodic walk + real-time ReadDirectoryChangesW fused; differentiate "attribute change" vs "content change" vs "new file"
- WinFIM.NET's **Windows service packaging** — runs as LocalSystem with minimal handles; good template for HostsGuard's elevated daemon
- Achiefs's **event normalization to JSON Lines** — one line per event, easy to tail/grep/ingest
- Wazuh's **agent-manager split** — local detection, remote/central alerting; even for a single-host tool, splitting detector from UI makes the detector runnable as a service while UI launches on-demand
- **Mandatory Integrity Control (MIC) / High-integrity ACL** on the baseline DB — prevents the baseline itself from being tampered
