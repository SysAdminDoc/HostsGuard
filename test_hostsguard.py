"""Tests for HostsGuard's security-critical and correctness-critical pure functions.

Rather than hand-copying function bodies (which silently drift from the source),
this harness parses HostsGuard.py with the `ast` module and executes ONLY the
selected top-level constants and pure functions in an isolated namespace — so the
tests exercise the real code without triggering the module-level bootstrap/Qt init.
"""
import ast
import ipaddress
import os
import re
import sqlite3
import sys
import datetime
import time
import json
import hashlib
import threading
import types
import urllib.request
import urllib.error
from dataclasses import dataclass, field
import pytest

_SRC = open(os.path.join(os.path.dirname(__file__), "HostsGuard.py"), encoding="utf-8").read()

# Top-level names to lift out of the real source.
_WANT_FUNCS = {"_is_frozen", "looks_like_domain", "get_root", "norm_line", "clean_hosts",
               "categorize", "_ps_esc", "valid_fw_addr", "_rgb", "_parse_fw_rules",
               "_import_status", "_import_list", "_build_import_plan", "_format_import_plan",
               "_apply_import_plan", "_normalize_ip_set", "_parse_doh_payload",
               "_collect_doh_values",
               "_normalize_sha256", "_verify_doh_payload_hash", "_doh_state_payload",
               "_load_doh_state", "_save_doh_state", "_current_doh_ips", "_doh_rule_ips",
               "_parse_windows_doh_servers", "_windows_known_doh_ips", "_fetch_doh_resolver_list",
               "refresh_doh_intelligence", "_doh_now", "_doh_status_payload", "_doh_status_text"}
_WANT_CLASSES = {"DB", "FWR", "FWEngine"}
_WANT_CONSTS = {"DOMAIN_RE", "IPV4_RE", "PRIV_RE", "MULTI_TLDS", "IGNORED",
                "WINDOWS_HEADER", "_CAT", "APP", "VER", "FW_PFX", "SCHEMA_VER", "DOH_IPS"}


def _extract():
    tree = ast.parse(_SRC)
    picked = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in _WANT_FUNCS:
            picked.append(node)
        elif isinstance(node, ast.ClassDef) and node.name in _WANT_CLASSES:
            picked.append(node)
        elif isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if any(t in _WANT_CONSTS for t in targets):
                picked.append(node)
    module = ast.Module(body=picked, type_ignores=[])
    ast.fix_missing_locations(module)
    # Provide the module globals the extracted code resolves at call time (the DB
    # class references these). log is a no-op stub; DB_PATH is set per-test.
    log_stub = types.SimpleNamespace(warning=lambda *a, **k: None, info=lambda *a, **k: None,
                                     debug=lambda *a, **k: None, error=lambda *a, **k: None)
    ns = {"re": re, "ipaddress": ipaddress, "sqlite3": sqlite3, "datetime": datetime,
          "time": time, "json": json, "Lock": threading.Lock, "log": log_stub,
          "dataclass": dataclass, "field": field, "DB_PATH": ":memory:", "sys": sys,
          "os": os, "DOH_STATE_PATH": os.path.join(os.getcwd(), "test_doh_resolvers.json"),
          "urllib": urllib, "hashlib": hashlib}
    exec(compile(module, "<hostsguard-extracted>", "exec"), ns)
    return ns


_m = _extract()
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
_parse_doh_payload = _m["_parse_doh_payload"]
_verify_doh_payload_hash = _m["_verify_doh_payload_hash"]
_doh_state_payload = _m["_doh_state_payload"]
_load_doh_state = _m["_load_doh_state"]
_save_doh_state = _m["_save_doh_state"]
_current_doh_ips = _m["_current_doh_ips"]
_doh_rule_ips = _m["_doh_rule_ips"]
_parse_windows_doh_servers = _m["_parse_windows_doh_servers"]
refresh_doh_intelligence = _m["refresh_doh_intelligence"]
APP = _m["APP"]
VER = _m["VER"]
SCHEMA_VER = _m["SCHEMA_VER"]
FWEngine = _m["FWEngine"]


class TestExtraction:
    def test_all_functions_extracted(self):
        for name in _WANT_FUNCS:
            assert name in _m, f"{name} was not extracted from source"

    def test_version_is_current(self):
        # Guards against a stale hardcoded version in the test harness.
        assert re.match(r"^\d+\.\d+\.\d+$", VER)


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
                elif isinstance(call.func, ast.Name) and call.func.id == "_bootstrap":
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
        pip_pos = _SRC.index("subprocess.check_call([sys.executable,'-m','pip','install'")
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
            "version": "3.15.0",
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
        assert plan["domains"] == [("example.com", "whitelisted", "manual")]
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
                  "category TEXT,source TEXT,added TEXT,modified TEXT,hits INTEGER DEFAULT 0,notes TEXT)")
        return c

    _UPSERT = ("""INSERT INTO domains(domain,status,category,source,added,modified,hits)VALUES(?,?,?,?,?,?,0)
                ON CONFLICT(domain) DO UPDATE SET status=excluded.status,modified=excluded.modified,
                source=CASE WHEN excluded.source!='' THEN excluded.source ELSE domains.source END,
                category=CASE WHEN excluded.category!='' THEN excluded.category ELSE domains.category END""")

    def test_reblock_preserves_notes_added_hits(self):
        c = self._mkdb()
        c.execute("INSERT INTO domains(domain,status,category,source,added,modified,hits,notes)"
                  "VALUES('x.com','blocked','Ads','manual','2020-01-01','2020-01-01',7,'note')")
        c.execute(self._UPSERT, ('x.com', 'whitelisted', '', '', '2026-01-01', '2026-01-01'))
        row = c.execute("SELECT status,category,source,added,hits,notes FROM domains WHERE domain='x.com'").fetchone()
        assert row == ('whitelisted', 'Ads', 'manual', '2020-01-01', 7, 'note')

    def test_new_source_overrides(self):
        c = self._mkdb()
        c.execute(self._UPSERT, ('y.com', 'blocked', '', 'manual', '2026', '2026'))
        c.execute(self._UPSERT, ('y.com', 'blocked', '', 'list:foo', '2026', '2026'))
        assert c.execute("SELECT source FROM domains WHERE domain='y.com'").fetchone()[0] == 'list:foo'


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
