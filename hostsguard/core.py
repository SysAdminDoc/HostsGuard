"""Core data, configuration, import/export, and utility boundaries."""
from .app import (
    APP, SCHEMA_VER, VER,
    DB, ConnDB, HostsMgr, LearnDB,
    canonical_reason, categorize, clean_hosts, get_root, load_cfg, norm_line,
    reason_label, save_cfg, looks_like_domain,
    _apply_import_plan, _build_import_plan, _dependency_versions,
    _format_import_plan, _parse_search_query, _redact_support_config,
    _redact_support_text, _sqlite_integrity, _support_bundle_payload,
    _write_support_bundle,
)

__all__ = [name for name in globals() if not name.startswith("__")]
