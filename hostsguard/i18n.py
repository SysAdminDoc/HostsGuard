"""Small localization registry with English defaults and safe fallbacks."""

DEFAULT_LANGUAGE = "en"

STRINGS = {
    "en": {
        "app.initializing": "Initializing...",
        "app.loading": "Loading...",
        "app.window_title": "{app} v{version}",
        "tabs.hosts_activity": "Hosts Activity",
        "tabs.firewall_activity": "Firewall Activity",
        "tabs.hosts_file": "Hosts File",
        "tabs.firewall_rules": "Firewall Rules",
        "tabs.tools": "Tools",
        "tabs.managed_domains": "Managed Domains",
        "tabs.raw_hosts_file": "Raw Hosts File",
        "tabs.blocklists": "Blocklists",
        "tabs.services": "Services",
        "hosts_activity.search_placeholder": "Search: domain:ads !microsoft reason:blocklist",
        "hosts_activity.scan": "Scan",
        "firewall_activity.search_placeholder": "Search: proc:chrome ip!=127.0.0.1 !lan",
        "firewall_activity.lockdown": "Lockdown",
        "firewall_activity.observe": "Observe",
        "firewall_activity.learning": "Learning",
        "hosts.domains_description": "Blocked domains are written to your hosts file as 0.0.0.0. Allowed domains are excluded from blocking.",
        "hosts.search_placeholder": "Search: domain:ads source:list !telemetry",
        "hosts.refresh": "Refresh",
        "hosts.add_domain": "Add Domain",
        "hosts.sync_to_hosts": "Sync to Hosts",
        "hosts.raw_description": "Direct editing of {path}. Save writes immediately.",
        "hosts.reload": "Reload",
        "hosts.save": "Save",
        "hosts.clean_save": "Clean & Save",
        "hosts.backup": "Backup",
        "hosts.restore": "Restore",
        "hosts.reset": "Reset",
        "hosts.blocklists_description": "Import community blocklists. Each adds 0.0.0.0 entries for ad/tracking/malware domains.",
        "hosts.import_selected": "Import Selected",
        "hosts.select_all": "Select All",
        "hosts.clear": "Clear",
        "hosts.paste_domains": "Paste Domains",
        "hosts.paste_placeholder": "Paste domains, one per line",
        "hosts.add_to_hosts": "Add to Hosts",
        "hosts.database_only": "Database Only",
        "hosts.auto_refresh": "Auto-Refresh",
        "hosts.subscribe_checked": "Subscribe Checked",
        "hosts.allowlist_subscriptions": "Allowlist Subscriptions",
        "hosts.allowlist_description": "Domains from these URLs are whitelisted (never blocked), overriding blocklists. One URL per line.",
        "hosts.save_apply_now": "Save & Apply Now",
        "hosts.services_description": "One-click block popular services via the hosts file. Best-effort (exact hostnames, no wildcards); pair with Block Encrypted DNS so apps can't bypass it.",
        "firewall.description": "Windows Firewall rules. HostsGuard rules use the HG_ prefix.",
        "firewall.search_placeholder": "Search: action:block program:chrome source:hostsguard !orphan",
        "firewall.refresh": "Refresh",
        "firewall.new_rule": "Rule",
        "firewall.block_ip_out": "Block IP Out",
        "firewall.block_ip_both": "Block IP In+Out",
        "firewall.block_program": "Block Program",
        "firewall.enable_profiles": "Enable Profiles",
        "firewall.save_baseline": "Save Baseline",
        "firewall.show_drift": "Show Drift",
        "firewall.delete_hg_rules": "Delete HG Rules",
        "tools.dns_network": "DNS + Network",
        "tools.flush_dns": "Flush DNS",
        "tools.winsock_reset": "Winsock Reset",
        "tools.dhcp_renew": "DHCP Renew",
        "tools.check_browser_doh": "Check Browser DoH",
        "tools.refresh_doh_list": "Refresh DoH List",
        "tools.block_encrypted_dns": "Block Encrypted DNS (DoH/DoT)",
        "tools.block_windows_telemetry": "Block Windows Telemetry",
        "tools.apply": "Apply",
        "tools.scheduled_blocking": "Scheduled Blocking...",
        "tools.record_session": "Record Session",
        "tools.config_data": "Config + Data",
        "tools.export_config": "Export Config",
        "tools.import_config": "Import Config",
        "tools.export_connections": "Export Connections",
        "tools.export_support_bundle": "Export Support Bundle",
        "tools.ui_scale": "UI Scale",
        "tools.prune_history": "Prune History (30d)",
        "tools.clear_favicons": "Clear Favicons",
        "tools.open_config_folder": "Open Config Folder",
        "tools.learning_mode": "Learning Mode",
        "tools.view_trusted": "View Trusted",
        "tools.view_untrusted": "View Untrusted",
        "tools.clear_all_trust": "Clear All Trust",
        "tools.backup_recovery": "Backup + Recovery",
        "tools.restore_hosts_from_db": "Restore Hosts from DB",
        "tools.restore_firewall_rules": "Restore Firewall Rules",
        "tools.sync_hosts_to_db": "Sync Hosts File to DB",
        "tools.use_machine_policy": "Use Machine Policy",
        "tools.backup_hosts_now": "Backup Hosts Now",
        "tools.save_current_to_profile": "Save Current to Profile",
        "tools.rebaseline": "Re-baseline (accept current)",
        "tools.harden_hosts_acl": "Harden Hosts ACL",
        "tools.restore_from_stevenblack": "Restore from StevenBlack",
        "tools.auto_restore_on_tamper": "Auto-restore on tamper",
        "tools.event_log": "Event Log",
        "tools.event_log_search_placeholder": "Search: action:blocked reason:firewall !telemetry",
        "tools.clear_log": "Clear Log",
    }
}


class _SafeFormatDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def normalize_language(language):
    lang = str(language or DEFAULT_LANGUAGE).replace("_", "-").lower()
    return lang if lang in STRINGS else DEFAULT_LANGUAGE


def tr(key, fallback=None, lang=None, **values):
    language = normalize_language(lang)
    text = STRINGS.get(language, {}).get(key)
    if text is None:
        text = fallback if fallback is not None else key
    if values:
        try:
            return text.format_map(_SafeFormatDict(values))
        except Exception:
            return text
    return text


def registered_keys(lang=DEFAULT_LANGUAGE):
    return frozenset(STRINGS.get(normalize_language(lang), {}))
