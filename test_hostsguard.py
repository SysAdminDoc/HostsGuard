"""Tests for HostsGuard's security-critical and correctness-critical package APIs."""
import ast
import io
import ipaddress
import os
import re
import shlex
import sqlite3
import sys
import datetime
import time
import json
import hashlib
import hmac
import gzip
import shutil
import tempfile
import threading
import types
import urllib.request
import urllib.error
import zipfile
import platform
import importlib.metadata as importlib_metadata
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
import pytest

os.environ.setdefault("HOSTSGUARD_SKIP_BOOTSTRAP", "1")
import hostsguard as hg_pkg
import hostsguard.app as hg
import hostsguard.core as hg_core
import hostsguard.firewall as hg_firewall
import hostsguard.i18n as hg_i18n
import hostsguard.network as hg_network
import hostsguard.service as hg_service
import hostsguard.ui as hg_ui

_ROOT = os.path.dirname(__file__)
_SRC = open(os.path.join(_ROOT, "hostsguard", "app.py"), encoding="utf-8").read()
_LAUNCHER_SRC = open(os.path.join(_ROOT, "HostsGuard.py"), encoding="utf-8").read()
_m = hg.__dict__
_is_frozen = _m["_is_frozen"]
looks_like_domain = _m["looks_like_domain"]
get_root = _m["get_root"]
norm_line = _m["norm_line"]
clean_hosts = _m["clean_hosts"]
categorize = _m["categorize"]
_ps_esc = _m["_ps_esc"]
valid_fw_addr = _m["valid_fw_addr"]
_rgb = _m["_rgb"]
_parse_fw_rules = _m["_parse_fw_rules"]
_build_import_plan = _m["_build_import_plan"]
_format_import_plan = _m["_format_import_plan"]
_apply_import_plan = _m["_apply_import_plan"]
load_cfg = _m["load_cfg"]
save_cfg = _m["save_cfg"]
_read_response_limited = _m["_read_response_limited"]
_gzip_decompress_limited = _m["_gzip_decompress_limited"]
_parse_doh_payload = _m["_parse_doh_payload"]
_verify_doh_payload_hash = _m["_verify_doh_payload_hash"]
_doh_state_payload = _m["_doh_state_payload"]
_load_doh_state = _m["_load_doh_state"]
_save_doh_state = _m["_save_doh_state"]
_current_doh_ips = _m["_current_doh_ips"]
_doh_rule_ips = _m["_doh_rule_ips"]
_parse_windows_doh_servers = _m["_parse_windows_doh_servers"]
refresh_doh_intelligence = _m["refresh_doh_intelligence"]
_redact_support_config = _m["_redact_support_config"]
_redact_support_text = _m["_redact_support_text"]
_support_bundle_payload = _m["_support_bundle_payload"]
_write_support_bundle = _m["_write_support_bundle"]
_deliver_webhook = _m["_deliver_webhook"]
_dependency_versions = _m["_dependency_versions"]
_policy_status = _m["_policy_status"]
_migrate_policy_to_programdata = _m["_migrate_policy_to_programdata"]
_parse_search_query = _m["_parse_search_query"]
_search_matches = _m["_search_matches"]
_coerce_ui_scale = _m["_coerce_ui_scale"]
_program_identity = _m["_program_identity"]
_score_rebind_candidate = _m["_score_rebind_candidate"]
_rank_rebind_candidates = _m["_rank_rebind_candidates"]
canonical_reason = _m["canonical_reason"]
reason_label = _m["reason_label"]
_service_error = _m["_service_error"]
_service_auth_ok = _m["_service_auth_ok"]
_service_content_length = _m["_service_content_length"]
_service_log_params = _m["_service_log_params"]
_service_parse_json_body = _m["_service_parse_json_body"]
_service_openapi = _m["_service_openapi"]
_service_port = _m["_service_port"]
APP = _m["APP"]
VER = _m["VER"]
SCHEMA_VER = _m["SCHEMA_VER"]
FWEngine = _m["FWEngine"]


class TestPackageBoundaries:
    def test_launcher_is_thin(self):
        code_lines = [
            line for line in _LAUNCHER_SRC.splitlines()
            if line.strip() and not line.lstrip().startswith("#") and not line.strip().startswith('"""')
        ]
        assert "from hostsguard.app import run" in _LAUNCHER_SRC
        assert len(code_lines) <= 4

    def test_facade_modules_export_expected_boundaries(self):
        assert hg_core.DB is hg.DB
        assert hg_core.HostsMgr is hg.HostsMgr
        assert hg_firewall.FWEngine is hg.FWEngine
        assert hg_firewall.valid_fw_addr is hg.valid_fw_addr
        assert hg_network.ConnWorker is hg.ConnWorker
        assert hg_network.refresh_doh_intelligence is hg.refresh_doh_intelligence
        assert hg_service._service is hg._service
        assert hg_service._deliver_webhook is hg._deliver_webhook
        assert hg_ui.MainWindow is hg.MainWindow

    def test_version_is_current(self):
        assert re.match(r"^\d+\.\d+\.\d+$", VER)

    def test_package_metadata_matches_runtime_constants(self):
        assert hg_pkg.APP == APP
        assert hg_pkg.VER == VER
        assert hg_pkg.SCHEMA_VER == SCHEMA_VER

    def test_release_metadata_versions_match_runtime(self):
        readme = open(os.path.join(_ROOT, "README.md"), encoding="utf-8").read()
        constraints = open(os.path.join(_ROOT, "constraints.txt"), encoding="utf-8").read()
        installer = open(os.path.join(_ROOT, "installer.iss"), encoding="utf-8").read()
        version_info = open(os.path.join(_ROOT, "version_info.txt"), encoding="utf-8").read()
        major, minor, patch = (int(part) for part in VER.split("."))
        assert f"version-{VER}-blue" in readme
        assert f"HostsGuard-v{VER}-Setup.exe" in readme
        assert f"HostsGuard v{VER}" in constraints
        assert f'MyAppVersion "{VER}"' in installer
        assert f'MyAppVersionInfo "{VER}.0"' in installer
        assert f"filevers=({major}, {minor}, {patch}, 0)" in version_info
        assert f"prodvers=({major}, {minor}, {patch}, 0)" in version_info
        assert f"StringStruct('FileVersion', '{VER}.0')" in version_info
        assert f"StringStruct('ProductVersion', '{VER}')" in version_info


class TestLocalizationRegistry:
    def test_registry_formats_english_strings(self):
        assert hg_i18n.tr("app.window_title", app="HostsGuard", version="3.16.0") == "HostsGuard v3.16.0"

    def test_missing_keys_and_languages_fall_back_safely(self):
        assert hg_i18n.tr("missing.key", lang="zz") == "missing.key"
        assert hg_i18n.tr("missing.key", fallback="Fallback") == "Fallback"
        assert hg_i18n.tr("app.window_title", app="HostsGuard") == "HostsGuard v{version}"

    def test_primary_tabs_route_through_registry(self):
        for key in ("tabs.hosts_activity", "tabs.firewall_activity", "tabs.hosts_file", "tabs.firewall_rules", "tabs.tools"):
            assert key in hg_i18n.registered_keys()
            assert f'T("{key}"' in _SRC


class TestConfigPersistence:
    def test_save_cfg_creates_directory_and_round_trips_utf8(self, tmp_path):
        old_path = _m["CFG_PATH"]
        cfg_path = tmp_path / "nested" / "config.json"
        _m["CFG_PATH"] = str(cfg_path)
        try:
            save_cfg({"language": "en", "label": "Café"})
            assert cfg_path.exists()
            assert cfg_path.read_text(encoding="utf-8").endswith("\n")
            assert load_cfg()["label"] == "Café"
            assert not list(cfg_path.parent.glob("*.tmp"))
        finally:
            _m["CFG_PATH"] = old_path

    def test_load_cfg_fails_closed_for_invalid_json(self, tmp_path):
        old_path = _m["CFG_PATH"]
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text("{not-json", encoding="utf-8")
        _m["CFG_PATH"] = str(cfg_path)
        try:
            assert load_cfg() == {}
        finally:
            _m["CFG_PATH"] = old_path


class TestBoundedResponseReads:
    def test_limited_response_reader_accepts_exact_limit(self):
        assert _read_response_limited(io.BytesIO(b"abc"), 3, "test payload") == b"abc"

    def test_limited_response_reader_rejects_oversized_payload(self):
        with pytest.raises(ValueError, match="exceeds"):
            _read_response_limited(io.BytesIO(b"abcd"), 3, "test payload")

    def test_limited_gzip_reader_accepts_exact_output_limit(self):
        data = gzip.compress(b"abc")
        assert _gzip_decompress_limited(data, 3, "geoip") == b"abc"

    def test_limited_gzip_reader_rejects_oversized_output(self):
        data = gzip.compress(b"abcd")
        with pytest.raises(ValueError, match="after decompression"):
            _gzip_decompress_limited(data, 3, "geoip")


class TestDestructiveActionGuards:
    def test_context_delete_actions_use_confirmations(self):
        assert '_confirm(s,"Remove managed domain"' in _SRC
        assert '_confirm(s,"Remove managed domains"' in _SRC
        assert '_confirm(s,"Delete firewall rule"' in _SRC
        assert 'm.addAction("Delete").triggered.connect(lambda:(fw.delete(name)' not in _SRC


class TestBootstrapGuards:
    def test_freeze_support_runs_before_bootstrap_and_qt_imports(self):
        tree = ast.parse(_SRC)
        freeze_line = None
        bootstrap_line = None
        qt_import_line = None
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Attribute) and call.func.attr == "freeze_support":
                    freeze_line = node.lineno if freeze_line is None else min(freeze_line, node.lineno)
                elif isinstance(call.func, ast.Name) and call.func.id == "_maybe_bootstrap":
                    bootstrap_line = node.lineno
            elif isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("PySide6"):
                qt_import_line = node.lineno if qt_import_line is None else min(qt_import_line, node.lineno)
        assert freeze_line is not None
        assert bootstrap_line is not None
        assert qt_import_line is not None
        assert freeze_line < bootstrap_line
        assert freeze_line < qt_import_line

    def test_frozen_detection_uses_sys_frozen(self, monkeypatch):
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        assert _is_frozen() is True

    def test_bootstrap_skips_runtime_pip_when_frozen(self):
        skip_pos = _SRC.index("if _is_frozen(): return")
        pip_pos = _SRC.index("_pip_install_dependency(pkg,_cf)")
        assert skip_pos < pip_pos

    def test_frozen_detection_uses_meipass(self, monkeypatch):
        monkeypatch.delattr(sys, "frozen", raising=False)
        monkeypatch.setattr(sys, "_MEIPASS", r"C:\Temp\hg", raising=False)
        assert _is_frozen() is True

    def test_unfrozen_detection(self, monkeypatch):
        monkeypatch.delattr(sys, "frozen", raising=False)
        monkeypatch.delattr(sys, "_MEIPASS", raising=False)
        assert _is_frozen() is False


class LearnStub:
    def __init__(self):
        self._trusted = {"old.exe"}
        self._untrusted = {"bad.exe"}
        self.saved = 0

    def save(self):
        self.saved += 1

    def trust(self, proc):
        self._trusted.add(proc.lower())
        self._untrusted.discard(proc.lower())
        self.save()

    def untrust(self, proc):
        self._untrusted.add(proc.lower())
        self._trusted.discard(proc.lower())
        self.save()


class TestImportPlanning:
    def test_import_plan_validates_and_counts_rows(self):
        plan = _build_import_plan({
            "version": "3.16.0",
            "schema": SCHEMA_VER,
            "domains": [
                {"domain": "Example.COM.", "status": "allowed", "source": "manual"},
                {"domain": "bad-domain", "status": "blocked"},
                {"domain": "example.com", "status": "blocked"},
            ],
            "fw_state": [
                {"name": "HG_Test", "direction": "Out", "action": "block", "remote_addr": "8.8.8.8"},
                {"name": "HG_Bad", "direction": "Sideways", "action": "Block"},
            ],
            "trusted": ["Good.EXE", ""],
            "untrusted": ["Bad.EXE"],
        })
        assert plan["domains"] == [("example.com", "whitelisted", "manual", "manual")]
        assert plan["fw_state"][0]["action"] == "Block"
        assert plan["trusted"] == ["good.exe"]
        assert plan["untrusted"] == ["bad.exe"]
        assert any("invalid domain" in e for e in plan["errors"])
        assert any("duplicate domain" in e for e in plan["errors"])
        assert any("direction" in e for e in plan["errors"])
        assert "Skipped invalid entries" in _format_import_plan(plan)

    def test_import_rejects_newer_schema(self):
        with pytest.raises(ValueError, match="newer"):
            _build_import_plan({"schema": SCHEMA_VER + 1, "domains": []})

    def _open_db(self, path):
        _m["DB_PATH"] = str(path)
        return _m["DB"]()

    def test_apply_import_plan_creates_backup_and_applies(self, tmp_path):
        db = self._open_db(tmp_path / "apply.db")
        learn = LearnStub()
        plan = _build_import_plan({
            "domains": [{"domain": "new.example.com", "status": "blocked", "source": "import"}],
            "fw_state": [{"name": "HG_Import", "direction": "Out", "action": "Allow", "remote_addr": "1.1.1.1"}],
            "trusted": ["NewApp.exe"],
            "untrusted": ["OtherApp.exe"],
        })
        result = _apply_import_plan(db, learn, plan)
        assert result["domains"] == 1 and result["fw_state"] == 1
        assert result["backup"] and os.path.exists(result["backup"])
        assert any(r[0] == "new.example.com" for r in db.get_domains())
        assert any(r[0] == "HG_Import" for r in db.get_fw_state())
        assert "newapp.exe" in learn._trusted
        assert "otherapp.exe" in learn._untrusted
        db.close()

    def test_apply_import_plan_restores_db_and_learning_on_failure(self, tmp_path, monkeypatch):
        db = self._open_db(tmp_path / "rollback.db")
        db.add_domain("keep.example.com", "blocked", "manual")
        learn = LearnStub()
        plan = _build_import_plan({
            "domains": [{"domain": "new.example.com", "status": "blocked", "source": "import"}],
            "fw_state": [{"name": "HG_Fail", "direction": "Out", "action": "Block"}],
            "trusted": ["NewApp.exe"],
        })
        def fail_save(*args, **kwargs):
            raise RuntimeError("forced fw failure")
        monkeypatch.setattr(db, "save_fw_rule", fail_save)
        with pytest.raises(RuntimeError, match="forced fw failure"):
            _apply_import_plan(db, learn, plan)
        domains = {r[0] for r in db.get_domains()}
        assert "keep.example.com" in domains
        assert "new.example.com" not in domains
        assert learn._trusted == {"old.exe"}
        assert learn._untrusted == {"bad.exe"}
        db.close()


class TestReasonTracking:
    def _open_db(self, path):
        _m["DB_PATH"] = str(path)
        return _m["DB"]()

    def test_canonical_reason_covers_policy_sources(self):
        assert canonical_reason(source="manual", action="blocked") == "manual"
        assert canonical_reason(source="list:Ads", action="blocked") == "blocklist"
        assert canonical_reason(source="allowlist", action="whitelisted") == "allowlist"
        assert canonical_reason(source="schedule", action="blocked") == "schedule"
        assert canonical_reason(source="service:YouTube", action="blocked") == "service"
        assert canonical_reason(source="telemetry", action="blocked") == "telemetry"
        assert canonical_reason(action="fw_blocked", details="Firewall blocked IP") == "firewall"
        assert canonical_reason(details="Encrypted DNS blocked") == "doh"

    def test_domain_reason_storage_and_filters(self, tmp_path):
        db = self._open_db(tmp_path / "reasons.db")
        db.add_domain("manual.example.com", "blocked", "manual")
        db.add_domains_bulk([
            ("ads.example.com", "blocked", "list:Ads"),
            ("allow.example.com", "whitelisted", "allowlist"),
            ("svc.example.com", "blocked", "service:YouTube"),
            ("telemetry.example.com", "blocked", "telemetry"),
            ("scheduled.example.com", "blocked", "schedule"),
        ])
        assert {r[0] for r in db.get_domains(reason="manual")} == {"manual.example.com"}
        assert {r[0] for r in db.get_domains(reason="blocklist")} == {"ads.example.com"}
        assert {r[0] for r in db.get_domains(reason="allowlist")} == {"allow.example.com"}
        assert {r[0] for r in db.get_domains(reason="service")} == {"svc.example.com"}
        assert {r[0] for r in db.get_domains(reason="telemetry")} == {"telemetry.example.com"}
        assert {r[0] for r in db.get_domains(reason="schedule")} == {"scheduled.example.com"}
        db.close()

    def test_log_reason_storage_and_filters(self, tmp_path):
        db = self._open_db(tmp_path / "log-reasons.db")
        db.log_event("manual.example.com", "blocked", "", "Hosts block", "manual")
        db.log_event("list:Ads", "blocked", "", "Blocklist imported", "blocklist")
        db.log_event("allowlist", "whitelisted", "", "Allowlist applied", "allowlist")
        db.log_event("service:YouTube", "blocked", "", "Service preset enabled", "service")
        db.log_event("windows_telemetry", "blocked", "", "Telemetry preset enabled", "telemetry")
        db.log_event("encrypted_dns", "fw_blocked", "", "Encrypted DNS blocked", "doh")
        db.log_event("8.8.8.8", "fw_blocked", "", "Firewall blocked IP", "firewall")
        assert [r[2] for r in db.get_log(reason_filter="manual")] == ["manual.example.com"]
        assert [r[2] for r in db.get_log(reason_filter="blocklist")] == ["list:Ads"]
        assert [r[2] for r in db.get_log(reason_filter="allowlist")] == ["allowlist"]
        assert [r[2] for r in db.get_log(reason_filter="service")] == ["service:YouTube"]
        assert [r[2] for r in db.get_log(reason_filter="telemetry")] == ["windows_telemetry"]
        assert [r[2] for r in db.get_log(reason_filter="doh")] == ["encrypted_dns"]
        assert [r[2] for r in db.get_log(reason_filter="firewall")] == ["8.8.8.8"]
        db.close()

    def test_feed_reason_defaults_and_domain_reason_overlay(self, tmp_path):
        db = self._open_db(tmp_path / "feed-reasons.db")
        assert db.feed_upsert("observed.example.com", "browser.exe") is True
        rows = db.feed_get()
        assert rows[0][0] == "observed.example.com"
        assert rows[0][8] == "observed"
        db.add_domain("observed.example.com", "blocked", "list:Ads")
        rows = db.feed_get()
        assert rows[0][8] == "blocklist"
        db.close()


class TestServiceContract:
    def test_auth_requires_matching_token(self):
        assert _service_auth_ok({"X-HG-Token": "secret"}, "secret") is True
        assert _service_auth_ok({"X-HG-Token": "wrong"}, "secret") is False
        assert _service_auth_ok({}, "secret") is False
        assert _service_auth_ok({"X-HG-Token": "secret"}, "") is False

    def test_consistent_error_body_shape(self):
        err = _service_error("bad_request", "Invalid body", {"field": "domain"})
        assert err["ok"] is False
        assert err["schema"] == "hostsguard.error.v1"
        assert err["error"] == {"code": "bad_request", "message": "Invalid body", "details": {"field": "domain"}}

    def test_json_body_validation_and_size_limit(self):
        assert _service_parse_json_body(b'{"action":"block","domain":"example.com"}', 41)["domain"] == "example.com"
        with pytest.raises(ValueError, match="bad JSON"):
            _service_parse_json_body(b"{", 1)
        with pytest.raises(ValueError, match="JSON object"):
            _service_parse_json_body(b'["not-object"]', 14)
        with pytest.raises(ValueError, match="negative"):
            _service_parse_json_body(b"", -1)
        with pytest.raises(OverflowError, match="exceeds"):
            _service_parse_json_body(b"{}", _m["SERVICE_BODY_LIMIT"] + 1)

    def test_content_length_and_port_validation(self):
        assert _service_content_length("0") == 0
        assert _service_content_length("12") == 12
        with pytest.raises(ValueError, match="integer"):
            _service_content_length("abc")
        with pytest.raises(ValueError, match="negative"):
            _service_content_length("-1")
        assert _service_port("7847") == 7847
        assert _service_port(65535) == 65535
        with pytest.raises(ValueError, match="integer"):
            _service_port("bad")
        with pytest.raises(ValueError, match="between"):
            _service_port("0")
        with pytest.raises(ValueError, match="between"):
            _service_port("70000")

    def test_log_query_param_validation(self):
        params = _service_log_params({"limit": ["50"], "since": ["2026-07-02T12:00:00Z"],
                                      "action": ["blocked"], "reason": ["firewall"]})
        assert params == {"limit": 50, "since": "2026-07-02T12:00:00Z", "action": "blocked", "reason": "firewall"}
        with pytest.raises(ValueError, match="limit"):
            _service_log_params({"limit": ["0"]})
        with pytest.raises(ValueError, match="since"):
            _service_log_params({"since": ["not-a-date"]})
        with pytest.raises(ValueError, match="action"):
            _service_log_params({"action": ["delete"]})
        with pytest.raises(ValueError, match="reason"):
            _service_log_params({"reason": ["made-up"]})

    def test_openapi_contract_lists_current_endpoints_and_schemas(self):
        spec = _service_openapi()
        assert spec["openapi"] == "3.1.0"
        assert spec["servers"][0]["url"] == "http://127.0.0.1:7847"
        assert _service_openapi(9001)["servers"][0]["url"] == "http://127.0.0.1:9001"
        assert set(spec["paths"]) == {"/status", "/domains", "/stats", "/log", "/openapi.json"}
        assert spec["components"]["securitySchemes"]["HgToken"]["name"] == "X-HG-Token"
        assert "reason" in spec["components"]["schemas"]["Domain"]["required"]
        log_params = {p["name"] for p in spec["paths"]["/log"]["get"]["parameters"]}
        assert {"limit", "since", "action", "reason"} <= log_params
        assert "GET /status /domains /stats /log /openapi.json, POST /domains" in _SRC


class _WebhookResp:
    def __init__(self, status=200):
        self.status = status
        self.closed = False

    def close(self):
        self.closed = True


class _WebhookLogger:
    def __init__(self):
        self.rows = []

    def info(self, msg):
        self.rows.append(("info", msg))

    def warning(self, msg):
        self.rows.append(("warning", msg))

    def debug(self, msg):
        self.rows.append(("debug", msg))


class TestWebhookDelivery:
    def test_success_adds_hmac_signature_header(self):
        calls = []

        def opener(req, timeout):
            calls.append((req, timeout))
            return _WebhookResp(204)

        cfg = {
            "webhook_url": "https://hooks.example.com/services/abc",
            "webhook_secret": "shared-secret",
        }
        result = _deliver_webhook(
            "blocked",
            {"domain": "ads.example.com"},
            cfg,
            opener=opener,
            sleep=lambda _: None,
            logger=_WebhookLogger(),
            now=datetime.datetime(2026, 7, 2, 12, 0, 0),
        )
        assert result == {"ok": True, "status": "delivered", "attempts": 1, "http_status": 204}
        req, timeout = calls[0]
        assert timeout == 5.0
        payload = json.loads(req.data.decode("utf-8"))
        assert payload["event"] == "blocked"
        assert payload["domain"] == "ads.example.com"
        headers = {k.lower(): v for k, v in req.header_items()}
        expected = hmac.new(b"shared-secret", req.data, hashlib.sha256).hexdigest()
        assert headers["x-hg-signature"] == f"sha256={expected}"
        assert headers["x-hg-schema"] == "hostsguard.webhook.v1"

    def test_transient_failure_retries_then_succeeds(self):
        calls = []
        sleeps = []
        logger = _WebhookLogger()

        def opener(req, timeout):
            calls.append(req)
            if len(calls) == 1:
                raise urllib.error.URLError("temporary outage")
            return _WebhookResp(202)

        result = _deliver_webhook(
            "tamper",
            {"msg": "hosts file modified externally"},
            {"webhook_url": "https://hooks.example.com/services/abc", "webhook_retries": 2, "webhook_backoff_seconds": 0.25},
            opener=opener,
            sleep=sleeps.append,
            logger=logger,
        )
        assert result["ok"] is True
        assert result["attempts"] == 2
        assert len(calls) == 2
        assert sleeps == [0.25]
        assert any(level == "warning" and "webhook retry" in msg for level, msg in logger.rows)

    def test_retry_exhaustion_returns_failure_status(self):
        calls = []
        sleeps = []
        logger = _WebhookLogger()

        def opener(req, timeout):
            calls.append(req)
            raise urllib.error.URLError("network down")

        result = _deliver_webhook(
            "blocked",
            {"domain": "ads.example.com"},
            {"webhook_url": "https://hooks.example.com/services/abc", "webhook_retries": 2, "webhook_backoff_seconds": 0.1},
            opener=opener,
            sleep=sleeps.append,
            logger=logger,
        )
        assert result["ok"] is False
        assert result["status"] == "failed"
        assert result["attempts"] == 3
        assert len(calls) == 3
        assert sleeps == [0.1, 0.2]
        assert any(level == "warning" and "webhook exhausted" in msg for level, msg in logger.rows)

    def test_disabled_mode_does_not_call_opener(self):
        logger = _WebhookLogger()

        def opener(req, timeout):
            raise AssertionError("disabled webhook should not open a request")

        result = _deliver_webhook(
            "blocked",
            {"domain": "ads.example.com"},
            {"webhook_enabled": False, "webhook_url": "https://hooks.example.com/services/abc"},
            opener=opener,
            logger=logger,
        )
        assert result["ok"] is False
        assert result["status"] == "disabled"
        assert result["attempts"] == 0
        assert any(level == "debug" and "webhook disabled" in msg for level, msg in logger.rows)


class TestSupportBundle:
    def test_config_redaction_marks_webhooks_tokens_and_domains(self):
        cfg = {
            "webhook_url": "https://hooks.example.com/services/abc",
            "webhook_secret": "shared-secret",
            "service_token": "a" * 64,
            "schedules": [{"target": "private.example.com"}],
            "fw_program_identities": {r"C:\Users\me\AppData\Local\App\app.exe": {"path": r"C:\Users\me\AppData\Local\App\app.exe"}},
            "active_dir": r"C:\Users\me\AppData\Roaming\HostsGuard",
            "blocklist_refresh_hours": 24,
        }
        redacted = _redact_support_config(cfg)
        assert redacted["webhook_url"].startswith("<REDACTED_URL:")
        assert redacted["webhook_secret"] == "<REDACTED_SECRET>"
        assert redacted["service_token"] == "<REDACTED_SECRET>"
        assert redacted["schedules"][0]["target"].startswith("<REDACTED_DOMAIN:")
        assert all("Users" not in k for k in redacted["fw_program_identities"])
        assert list(redacted["fw_program_identities"].values())[0]["path"].startswith("<REDACTED_PATH:")
        assert redacted["active_dir"].startswith("<REDACTED_PATH:")
        assert redacted["blocklist_refresh_hours"] == 24

    def test_payload_redacts_private_values_and_writes_zip(self, tmp_path):
        event_rows = [
            (1, "2026-07-02T10:00:00", "secret.example.com", "blocked", r"C:\Apps\browser.exe",
             "Blocked 8.8.8.8 via https://hooks.example.com/" + "b" * 40, "manual")
        ]
        fw_rows = [
            ("HG_Block_App", "Out", "Block", "8.8.8.8", "Any", r"C:\Program Files\App\app.exe", "2026")
        ]
        payload = _support_bundle_payload(
            {"webhook_url": "https://hooks.example.com/services/abc"},
            {"blocked": 1},
            "ok",
            "ok",
            "token=" + ("c" * 40) + " domain=secret.example.com ip=8.8.8.8",
            event_rows,
            fw_rows,
            {"blocked_entries": 1},
            {"python": "3.12"},
            [],
        )
        joined = "\n".join(payload.values())
        assert "secret.example.com" not in joined
        assert "https://hooks.example.com" not in joined
        assert "8.8.8.8" not in joined
        assert "b" * 40 not in joined
        assert "<REDACTED_DOMAIN:" in joined
        assert "<REDACTED_URL:" in joined
        assert "<REDACTED_IP:" in joined
        assert "<REDACTED_SECRET>" in joined
        out = tmp_path / "support.zip"
        _write_support_bundle(str(out), payload)
        with zipfile.ZipFile(out) as z:
            names = set(z.namelist())
            assert {"manifest.json", "config.redacted.json", "firewall_state.redacted.json",
                    "event_log.redacted.jsonl", "hostsguard.log.redacted.txt"} <= names


class TestPolicyMigration:
    def test_policy_status_reports_user_machine_drift(self, tmp_path):
        user = tmp_path / "user"
        machine = tmp_path / "machine"
        user.mkdir(); machine.mkdir()
        (user / "config.json").write_text('{"mode":"user"}', encoding="utf-8")
        (machine / "config.json").write_text('{"mode":"machine"}', encoding="utf-8")
        st = _policy_status(str(user), str(user), str(machine), portable=False)
        assert st["scope"] == "user"
        assert st["active_dir"] == str(user.resolve())
        assert st["user_files"] == ["config.json"]
        assert st["machine_files"] == ["config.json"]
        assert st["drift"] == ["config.json"]
        machine_active = _policy_status(str(machine), str(user), str(machine), portable=False)
        assert machine_active["scope"] == "machine"

    def test_policy_migration_copies_policy_files(self, tmp_path):
        src = tmp_path / "src"
        dst = tmp_path / "ProgramData"
        src.mkdir()
        (src / "hostsguard.db").write_text("db", encoding="utf-8")
        (src / "config.json").write_text("cfg", encoding="utf-8")
        result = _migrate_policy_to_programdata(str(src), str(dst), portable=False)
        assert sorted(result["files"]) == ["config.json", "hostsguard.db"]
        assert (dst / "hostsguard.db").read_text(encoding="utf-8") == "db"
        assert (dst / "config.json").read_text(encoding="utf-8") == "cfg"

    def test_policy_migration_rolls_back_partial_target_replace(self, tmp_path, monkeypatch):
        src = tmp_path / "src"
        dst = tmp_path / "ProgramData"
        src.mkdir(); dst.mkdir()
        (src / "hostsguard.db").write_text("new-db", encoding="utf-8")
        (src / "config.json").write_text("new-cfg", encoding="utf-8")
        (dst / "config.json").write_text("old-cfg", encoding="utf-8")
        real_replace = os.replace
        calls = {"n": 0}
        def flaky_replace(src_path, dst_path):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("forced replace failure")
            return real_replace(src_path, dst_path)
        monkeypatch.setattr(os, "replace", flaky_replace)
        with pytest.raises(OSError, match="forced"):
            _migrate_policy_to_programdata(str(src), str(dst), portable=False)
        assert not (dst / "hostsguard.db").exists()
        assert (dst / "config.json").read_text(encoding="utf-8") == "old-cfg"


class TestAdvancedSearchGrammar:
    def test_parse_field_negative_and_not_equal_terms(self):
        terms = _parse_search_query('domain:ads.example.com !telemetry action!=allowed "quoted value"')
        assert terms == [
            {"field": "domain", "op": "contains", "value": "ads.example.com"},
            {"field": "", "op": "not_contains", "value": "telemetry"},
            {"field": "action", "op": "ne", "value": "allowed"},
            {"field": "", "op": "contains", "value": "quoted value"},
        ]

    def test_match_supports_field_aliases_and_negation(self):
        record = {"domain": "ads.example.com", "action": "blocked", "reason": "blocklist", "process": "browser.exe"}
        assert _search_matches(record, "domain:ads reason:blocklist !telemetry")
        assert _search_matches(record, "proc:browser", {"proc": "process"})
        assert not _search_matches(record, "domain:ads !browser")
        assert not _search_matches(record, "action!=blocked")

    def test_match_handles_special_characters_in_quoted_values(self):
        record = {"details": "Firewall blocked 1.2.3.4:443 for C:\\Apps\\Foo Bar\\app.exe"}
        assert _search_matches(record, 'details:"1.2.3.4:443"')
        assert _search_matches(record, '"Foo Bar"')
        assert not _search_matches(record, 'details!="Firewall blocked 1.2.3.4:443 for C:\\Apps\\Foo Bar\\app.exe"')


class TestUiScale:
    def test_accepts_supported_scale_percentages(self):
        for pct in (90, 100, 110, 125, 150):
            assert _coerce_ui_scale(f"{pct}%") == pct

    def test_invalid_scale_falls_back_or_snaps_to_nearest(self):
        assert _coerce_ui_scale("bad") == 100
        assert _coerce_ui_scale(118) == 125
        assert _coerce_ui_scale(80) == 90


class TestReleaseConstraints:
    def test_constraints_pin_core_release_dependencies(self):
        path = os.path.join(os.path.dirname(__file__), "constraints.txt")
        text = open(path, encoding="utf-8").read()
        for name in ("PySide6", "psutil", "maxminddb", "pyinstaller"):
            assert re.search(rf"^{re.escape(name)}==\d", text, re.IGNORECASE | re.MULTILINE), name

    def test_dependency_versions_report_release_smoke_tools(self):
        versions = _dependency_versions()
        for name in ("PySide6", "psutil", "maxminddb", "PyInstaller"):
            assert name in versions
            assert versions[name]
            assert "unavailable" not in str(versions[name]).lower()


class TestNormLine:
    def test_standard_entry(self):
        assert norm_line("0.0.0.0 ads.example.com") == "0.0.0.0 ads.example.com"

    def test_127_entry(self):
        assert norm_line("127.0.0.1 ads.example.com") == "0.0.0.0 ads.example.com"

    def test_with_comment(self):
        assert norm_line("0.0.0.0 ads.example.com # block ads") == "0.0.0.0 ads.example.com"

    def test_domain_only_no_normalize(self):
        assert norm_line("ads.example.com", normalize=False) == "ads.example.com"

    def test_empty(self):
        assert norm_line("") is None

    def test_comment_line(self):
        assert norm_line("# this is a comment") is None

    def test_localhost(self):
        assert norm_line("127.0.0.1 localhost") is None

    def test_invalid_domain(self):
        assert norm_line("0.0.0.0 -invalid") is None

    def test_trailing_dot(self):
        assert norm_line("0.0.0.0 example.com.") == "0.0.0.0 example.com"

    def test_case_normalization(self):
        assert norm_line("0.0.0.0 ADS.Example.COM") == "0.0.0.0 ads.example.com"

    def test_ipv6_entry(self):
        assert norm_line(":: ads.example.com") == "0.0.0.0 ads.example.com"

    def test_ip_after_zero_is_kept(self):
        assert norm_line("0.0.0.0 192.168.1.1") == "0.0.0.0 192.168.1.1"

    def test_tab_separated(self):
        assert norm_line("0.0.0.0\tads.example.com") == "0.0.0.0 ads.example.com"


class TestGetRoot:
    def test_simple(self):
        assert get_root("example.com") == "example.com"

    def test_subdomain(self):
        assert get_root("www.example.com") == "example.com"

    def test_deep_subdomain(self):
        assert get_root("a.b.c.example.com") == "example.com"

    def test_co_uk(self):
        assert get_root("www.example.co.uk") == "example.co.uk"

    def test_com_au(self):
        assert get_root("mail.example.com.au") == "example.com.au"

    def test_co_jp(self):
        assert get_root("sub.example.co.jp") == "example.co.jp"

    def test_two_part(self):
        assert get_root("google.com") == "google.com"


class TestLooksLikeDomain:
    def test_valid(self):
        assert looks_like_domain("example.com") is True

    def test_subdomain(self):
        assert looks_like_domain("sub.example.com") is True

    def test_no_dot(self):
        assert looks_like_domain("localhost") is False

    def test_ip(self):
        assert looks_like_domain("192.168.1.1") is False

    def test_empty(self):
        assert looks_like_domain("") is False

    def test_none(self):
        assert looks_like_domain(None) is False

    def test_ignored(self):
        assert looks_like_domain("ip6-localhost") is False

    def test_hyphenated(self):
        assert looks_like_domain("my-domain.example.com") is True

    def test_leading_hyphen(self):
        assert looks_like_domain("-invalid.com") is False


class TestCleanHosts:
    def test_deduplicates(self):
        lines = ["0.0.0.0 a.com\n", "0.0.0.0 a.com\n", "0.0.0.0 b.com\n"]
        result, stats = clean_hosts(lines)
        domains = [l.split()[-1] for l in result if l.strip() and not l.strip().startswith('#')]
        assert domains.count("a.com") == 1
        assert stats['dupes'] == 1

    def test_preserves_comments(self):
        lines = ["# my custom comment\n", "0.0.0.0 a.com\n"]
        result, stats = clean_hosts(lines)
        assert any("# my custom comment" in l for l in result)

    def test_whitelist(self):
        lines = ["0.0.0.0 blocked.com\n", "0.0.0.0 allowed.com\n"]
        result, stats = clean_hosts(lines, wl={"allowed.com"})
        domains = [l.split()[-1] for l in result if l.strip() and not l.strip().startswith('#')]
        assert "allowed.com" not in domains
        assert stats['whitelist'] == 1

    def test_empty(self):
        result, stats = clean_hosts([])
        assert stats['total'] == 0

    def test_idempotent(self):
        # Regression: cleaning already-cleaned output must not keep duplicating the
        # Windows header or the managed-by marker (the old version did on every run).
        lines = ["0.0.0.0 a.com\n", "0.0.0.0 b.com\n"]
        first, _ = clean_hosts(lines)
        second, _ = clean_hosts([l + "\n" for l in first])
        assert first == second
        headers = [l for l in second if l.startswith("# Copyright (c) 1993-2009")]
        assert len(headers) == 1
        markers = [l for l in second if "entries managed by" in l]
        assert len(markers) == 1

    def test_no_blank_line_growth(self):
        # Regression: kept comment lines used to retain their line endings and the
        # header filter never matched, doubling blank lines each pass.
        lines = ["0.0.0.0 a.com\n"]
        r1, _ = clean_hosts(lines)
        r2, _ = clean_hosts([l + "\n" for l in r1])
        assert r1.count("") == r2.count("")


class TestPsEsc:
    def test_simple(self):
        assert _ps_esc("hello") == "'hello'"

    def test_single_quote(self):
        assert _ps_esc("it's") == "'it''s'"

    def test_injection(self):
        result = _ps_esc("'; Remove-Item C:\\")
        assert result.startswith("'") and result.endswith("'")
        assert "''" in result

    def test_semicolon(self):
        assert _ps_esc("test; whoami") == "'test; whoami'"

    def test_pipe(self):
        assert _ps_esc("test | whoami") == "'test | whoami'"

    def test_empty(self):
        assert _ps_esc("") == "''"

    def test_newline_injection_stays_quoted(self):
        # A newline can't break out of a single-quoted PowerShell string.
        r = _ps_esc("a'\nStop-Computer")
        assert r.startswith("'") and r.endswith("'")
        assert r.count("'") % 2 == 0  # all quotes balanced/doubled


class TestCategorize:
    def test_google(self):
        assert categorize("www.google.com", 443) == "Google"

    def test_social(self):
        assert categorize("www.facebook.com", 443) == "Social"

    def test_private_ip(self):
        assert categorize("192.168.1.1", 80) == "LAN"

    def test_web_port(self):
        assert categorize("unknown.example.com", 443) == "Web"

    def test_dns_port(self):
        assert categorize("resolver.example.com", 53) == "DNS"

    def test_unresolved_host_is_not_lan(self):
        # Regression: placeholder '-' host (unresolved public IP) used to be
        # classified LAN; it must fall through to port-based classification.
        assert categorize("-", 443) == "Web"
        assert categorize("-", 0) == ""

    def test_empty_host_falls_through_to_port(self):
        assert categorize("", 443) == "Web"


class TestValidFwAddr:
    def test_single_ip(self):
        assert valid_fw_addr("8.8.8.8") is True

    def test_ipv6(self):
        assert valid_fw_addr("2606:4700:4700::1111") is True

    def test_cidr(self):
        assert valid_fw_addr("10.0.0.0/8") is True

    def test_range(self):
        assert valid_fw_addr("192.168.1.1-192.168.1.50") is True

    def test_empty(self):
        assert valid_fw_addr("") is False
        assert valid_fw_addr(None) is False

    def test_garbage(self):
        assert valid_fw_addr("not-an-ip") is False
        assert valid_fw_addr("999.999.999.999") is False

    def test_injection_attempt_rejected(self):
        assert valid_fw_addr("8.8.8.8; Remove-Item") is False


class TestDohIntelligence:
    def _state_path(self, tmp_path):
        path = tmp_path / "doh_resolvers.json"
        _m["DOH_STATE_PATH"] = str(path)
        return path

    def test_parse_doh_payload_accepts_json_and_text(self):
        payload = {
            "resolvers": [
                {"ip": "1.1.1.1"},
                {"serverAddress": "2606:4700:4700::1111"},
                {"ip": "not-an-ip"},
            ],
            "nested": {"addresses": ["8.8.8.8", "https://9.9.9.9/dns-query"]},
        }
        assert _parse_doh_payload(payload) == {"1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111"}
        text = "8.8.4.4 # google secondary\nhttps://149.112.112.112/dns-query\nbad-value"
        assert _parse_doh_payload(text) == {"8.8.4.4", "149.112.112.112"}

    def test_hash_check_accepts_plain_and_prefixed_sha256(self):
        raw = b'{"ips":["1.1.1.1"]}'
        digest = hashlib.sha256(raw).hexdigest()
        assert _verify_doh_payload_hash(raw, digest) == digest
        assert _verify_doh_payload_hash(raw, f"sha256:{digest}") == digest
        with pytest.raises(ValueError, match="SHA-256"):
            _verify_doh_payload_hash(raw, "0" * 64)

    def test_rule_ips_merge_state_and_preserve_dns_exemption(self, tmp_path):
        self._state_path(tmp_path)
        _save_doh_state(_doh_state_payload(["9.9.9.9", "bad"], "test", "", "2026-07-02T00:00:00Z"))
        ips = _doh_rule_ips(ips={"1.1.1.1", "9.9.9.9", "not-an-ip"}, exempt={"1.1.1.1"})
        assert ips == ["9.9.9.9"]
        assert "9.9.9.9" in _current_doh_ips()

    def test_windows_doh_servers_parse_convertto_json_shapes(self):
        assert _parse_windows_doh_servers('"1.1.1.1"') == {"1.1.1.1"}
        assert _parse_windows_doh_servers('[{"ServerAddress":"8.8.8.8"},{"ServerAddress":"2606:4700:4700::1111"}]') == {
            "8.8.8.8", "2606:4700:4700::1111"
        }

    def test_refresh_rolls_back_failed_remote_update(self, tmp_path, monkeypatch):
        path = self._state_path(tmp_path)
        original = _save_doh_state(_doh_state_payload(["9.9.9.9"], "old", "a" * 64, "2026-07-02T01:00:00Z"))
        monkeypatch.setitem(_m, "_windows_known_doh_ips", lambda: set())
        def fail_fetch(*args, **kwargs):
            raise ValueError("forced hash failure")
        monkeypatch.setitem(_m, "_fetch_doh_resolver_list", fail_fetch)
        with pytest.raises(ValueError, match="forced hash failure"):
            refresh_doh_intelligence("https://example.test/doh.json", "0" * 64)
        with open(path, encoding="utf-8") as f:
            assert json.load(f) == original

    def test_remote_refresh_requires_hash(self, tmp_path, monkeypatch):
        path = self._state_path(tmp_path)
        _save_doh_state(_doh_state_payload(["9.9.9.9"], "old", "", "2026-07-02T01:00:00Z"))
        monkeypatch.setitem(_m, "_windows_known_doh_ips", lambda: set())
        with pytest.raises(ValueError, match="doh_resolver_sha256"):
            refresh_doh_intelligence("https://example.test/doh.json", "")
        with open(path, encoding="utf-8") as f:
            assert json.load(f)["ips"] == ["9.9.9.9"]

    def test_refresh_merges_windows_and_remote_after_validation(self, tmp_path, monkeypatch):
        self._state_path(tmp_path)
        monkeypatch.setitem(_m, "_windows_known_doh_ips", lambda: {"1.1.1.1"})
        monkeypatch.setitem(_m, "_fetch_doh_resolver_list",
                            lambda url, expected: _doh_state_payload(["8.8.8.8"], url, "b" * 64, "2026-07-02T02:00:00Z"))
        state = refresh_doh_intelligence("https://example.test/doh.json", "b" * 64)
        assert state["ips"] == ["1.1.1.1", "8.8.8.8"]
        assert "Windows known DoH servers" in state["source"]
        assert "https://example.test/doh.json" in state["source"]

    def test_block_doh_replaces_existing_rules_before_create(self, monkeypatch):
        calls = []
        def fake_ps(cmd, t=20):
            calls.append(cmd)
            return True, ""
        monkeypatch.setitem(_m, "_ps", fake_ps)
        engine = FWEngine()
        created = engine.block_doh(exempt={"1.1.1.1"}, ips={"1.1.1.1", "8.8.8.8"})
        removes = [c for c in calls if c.startswith("Remove-NetFirewallRule")]
        creates = [c for c in calls if c.startswith("New-NetFirewallRule")]
        assert len(removes) == 3
        assert len(creates) == 3
        assert created == ["HG_DoH_IPs", "HG_DoT_TCP", "HG_DoT_UDP"]
        assert "8.8.8.8" in creates[0]
        assert "1.1.1.1" not in creates[0]


class TestRgb:
    def test_basic(self):
        assert _rgb("#7aa2f7") == "122,162,247"

    def test_black(self):
        assert _rgb("#000000") == "0,0,0"

    def test_white(self):
        assert _rgb("#ffffff") == "255,255,255"


# ── DB behavior tests: exercise the real UPSERT/migration SQL against sqlite ──

class TestDomainUpsert:
    """Verify the add_domain UPSERT preserves user data across re-blocks."""
    def _mkdb(self):
        c = sqlite3.connect(":memory:")
        c.execute("CREATE TABLE domains(domain TEXT PRIMARY KEY,status TEXT DEFAULT 'blocked',"
                  "category TEXT,source TEXT,reason TEXT,added TEXT,modified TEXT,hits INTEGER DEFAULT 0,notes TEXT)")
        return c

    _UPSERT = ("""INSERT INTO domains(domain,status,category,source,reason,added,modified,hits)VALUES(?,?,?,?,?,?,?,0)
                ON CONFLICT(domain) DO UPDATE SET status=excluded.status,modified=excluded.modified,
                source=CASE WHEN excluded.source!='' THEN excluded.source ELSE domains.source END,
                reason=CASE WHEN excluded.reason!='' THEN excluded.reason ELSE domains.reason END,
                category=CASE WHEN excluded.category!='' THEN excluded.category ELSE domains.category END""")

    def test_reblock_preserves_notes_added_hits(self):
        c = self._mkdb()
        c.execute("INSERT INTO domains(domain,status,category,source,reason,added,modified,hits,notes)"
                  "VALUES('x.com','blocked','Ads','manual','manual','2020-01-01','2020-01-01',7,'note')")
        c.execute(self._UPSERT, ('x.com', 'whitelisted', '', '', '', '2026-01-01', '2026-01-01'))
        row = c.execute("SELECT status,category,source,reason,added,hits,notes FROM domains WHERE domain='x.com'").fetchone()
        assert row == ('whitelisted', 'Ads', 'manual', 'manual', '2020-01-01', 7, 'note')

    def test_new_source_overrides(self):
        c = self._mkdb()
        c.execute(self._UPSERT, ('y.com', 'blocked', '', 'manual', 'manual', '2026', '2026'))
        c.execute(self._UPSERT, ('y.com', 'blocked', '', 'list:foo', 'blocklist', '2026', '2026'))
        assert c.execute("SELECT source,reason FROM domains WHERE domain='y.com'").fetchone() == ('list:foo', 'blocklist')


class TestLegacyMigrationIntegration:
    """Exercise the REAL DB._migrate/_rename_legacy against a pre-versioning DB on disk."""
    def _legacy_db(self, tmp_path):
        p = str(tmp_path / "legacy.db")
        c = sqlite3.connect(p)
        # Pre-versioning shapes: domains + log with old column names, plus a real feed row.
        c.execute("CREATE TABLE domains(domain TEXT PRIMARY KEY,status TEXT,category TEXT,source TEXT,"
                  "date_added TEXT,date_modified TEXT,hit_count INTEGER,notes TEXT)")
        c.execute("INSERT INTO domains VALUES('legacy.com','blocked','ads','manual','2020','2020',9,'keep')")
        c.execute("CREATE TABLE log(id INTEGER PRIMARY KEY,timestamp TEXT,domain TEXT,action TEXT,process_name TEXT,details TEXT)")
        c.execute("INSERT INTO log(timestamp,domain,action,process_name,details) VALUES('2020','legacy.com','blocked','x.exe','d')")
        c.commit(); c.close()
        return p

    def _open_db(self, path):
        _m["DB_PATH"] = path
        return _m["DB"]()

    def _backups(self, tmp_path):
        return sorted((tmp_path / "backups").glob("hostsguard_db_v*_to_v*.sqlite"))

    def test_migration_recovers_domains_and_log(self, tmp_path):
        path = self._legacy_db(tmp_path)
        db = self._open_db(path)
        # These queries returned [] on legacy DBs before the rename migration shipped.
        rows = db.get_domains()
        assert any(r[0] == 'legacy.com' and r[6] == 9 for r in rows), "domains query broken after migration"
        assert db.get_domains(status='blocked'), "status filter broken"
        log_rows = db.get_log(limit=10)
        assert any(r[2] == 'legacy.com' for r in log_rows), "log query broken after migration"
        # Notes and hits preserved through the rename
        row = [r for r in rows if r[0] == 'legacy.com'][0]
        assert row[7] == 'keep' and row[6] == 9
        db.close()

    def test_migration_creates_pre_change_backup(self, tmp_path):
        path = self._legacy_db(tmp_path)
        db = self._open_db(path)
        backups = self._backups(tmp_path)
        assert len(backups) == 1
        b = sqlite3.connect(backups[0])
        cols = {r[1] for r in b.execute("PRAGMA table_info(domains)").fetchall()}
        row = b.execute("SELECT domain,hit_count FROM domains WHERE domain='legacy.com'").fetchone()
        b.close(); db.close()
        assert {"date_added", "date_modified", "hit_count"} <= cols
        assert row == ("legacy.com", 9)

    def test_migration_is_idempotent(self, tmp_path):
        path = self._legacy_db(tmp_path)
        db1 = self._open_db(path)      # first migration
        first_backups = self._backups(tmp_path)
        db1.close()
        db2 = self._open_db(path)  # re-open: must not error or lose data
        assert any(r[0] == 'legacy.com' for r in db2.get_domains())
        db2.close()
        assert self._backups(tmp_path) == first_backups

    def test_migration_failure_preserves_backup(self, tmp_path, monkeypatch):
        path = self._legacy_db(tmp_path)
        def fail_rename(self):
            raise RuntimeError("forced migration failure")
        monkeypatch.setattr(_m["DB"], "_rename_legacy", fail_rename)
        with pytest.raises(RuntimeError):
            self._open_db(path)
        backups = self._backups(tmp_path)
        assert len(backups) == 1
        b = sqlite3.connect(backups[0])
        backup_cols = {r[1] for r in b.execute("PRAGMA table_info(domains)").fetchall()}
        b.close()
        c = sqlite3.connect(path)
        live_cols = {r[1] for r in c.execute("PRAGMA table_info(domains)").fetchall()}
        c.close()
        assert "date_added" in backup_cols
        assert "date_added" in live_cols

    def test_fresh_db_has_all_tables(self, tmp_path):
        db = self._open_db(str(tmp_path / "fresh.db"))
        db.add_domain('new.com', 'blocked', 'manual')
        assert any(r[0] == 'new.com' for r in db.get_domains())
        # schema_version stamped to current
        v = db.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        assert v is not None


class TestParseFwRules:
    """Exercise the real _parse_fw_rules against representative Get-NetFirewallRule JSON."""
    def test_single_object(self):
        j = json.dumps({"N": "HG_Block_x", "Dir": 2, "Act": 4, "En": 1, "RA": "1.2.3.4", "Proto": "TCP", "Prog": ""})
        rules = _parse_fw_rules(j)
        assert len(rules) == 1
        r = rules[0]
        assert r.name == "HG_Block_x" and r.direction == "Out" and r.action == "Block"
        assert r.enabled is True and r.source == "hostsguard"

    def test_list_and_inbound_allow(self):
        j = json.dumps([
            {"N": "A", "Dir": 1, "Act": 2, "En": 0, "RA": "Any", "Proto": "Any", "Prog": "c:\\a.exe"},
            {"N": "HG_B", "Dir": 2, "Act": 4, "En": 1, "RA": "", "Proto": "", "Prog": ""},
        ])
        rules = _parse_fw_rules(j)
        assert len(rules) == 2
        assert rules[0].direction == "In" and rules[0].action == "Allow" and rules[0].enabled is False
        assert rules[0].source == "system" and rules[1].source == "hostsguard"

    def test_list_valued_remote_address(self):
        j = json.dumps({"N": "multi", "Dir": 2, "Act": 4, "En": 1, "RA": ["1.1.1.1", "8.8.8.8"], "Proto": "Any", "Prog": ""})
        rules = _parse_fw_rules(j)
        assert rules[0].remote_addr == "1.1.1.1,8.8.8.8"

    def test_missing_fields_and_none(self):
        j = json.dumps({"N": "sparse"})  # only a name
        rules = _parse_fw_rules(j)
        assert rules[0].name == "sparse" and rules[0].protocol == "Any" and rules[0].remote_addr == ""

    def test_empty_and_garbage(self):
        assert _parse_fw_rules("") == []
        assert _parse_fw_rules("not json") == []


class TestFirewallRebindScoring:
    def _old(self):
        return {
            "path": r"C:\Program Files\Contoso Guard\1.0\guard.exe",
            "exists": False,
            "basename": "guard.exe",
            "original_filename": "guard.exe",
            "signer": "CN=Contoso Software LLC",
            "product": "Contoso Guard",
            "file_description": "Contoso Guard",
            "sha256": "a" * 64,
        }

    def test_no_match_rejects_filename_only_candidate(self):
        old = self._old()
        unrelated = {
            "path": r"C:\Program Files\Other Tool\guard.exe",
            "exists": True,
            "basename": "guard.exe",
            "original_filename": "guard.exe",
            "signer": "CN=Other Publisher",
            "product": "Other Tool",
            "signature_status": "Valid",
        }
        result = _rank_rebind_candidates(old, [unrelated])
        assert result["status"] == "none"
        assert result["matches"] == []

    def test_single_match_uses_hash_history_and_identity(self):
        old = self._old()
        candidate = {
            "path": r"C:\Program Files\Contoso Guard\2.0\guard.exe",
            "exists": True,
            "basename": "guard.exe",
            "original_filename": "guard.exe",
            "signer": "CN=Contoso Software LLC",
            "product": "Contoso Guard",
            "file_description": "Contoso Guard",
            "signature_status": "Valid",
            "sha256": "a" * 64,
        }
        unrelated = {
            "path": r"C:\Program Files\Other Tool\guard.exe",
            "exists": True,
            "basename": "guard.exe",
            "signature_status": "Valid",
        }
        result = _rank_rebind_candidates(old, [unrelated, candidate], history={old["path"]: old})
        assert result["status"] == "single"
        assert result["ambiguous"] is False
        assert result["matches"][0]["path"].endswith(r"2.0\guard.exe")
        assert "same SHA-256" in result["matches"][0]["reasons"]
        assert "same signer" in result["matches"][0]["reasons"]

    def test_ambiguous_match_flags_close_signed_candidates(self):
        old = self._old()
        first = {
            "path": r"C:\Program Files\Contoso Guard\2.0\guard.exe",
            "exists": True,
            "basename": "guard.exe",
            "original_filename": "guard.exe",
            "signer": "CN=Contoso Software LLC",
            "product": "Contoso Guard",
            "file_description": "Contoso Guard",
            "signature_status": "Valid",
        }
        second = dict(first, path=r"C:\Users\me\AppData\Local\Programs\Contoso Guard\guard.exe")
        result = _rank_rebind_candidates(old, [first, second], history={old["path"]: old})
        assert result["status"] == "ambiguous"
        assert result["ambiguous"] is True
        assert len(result["matches"]) == 2
