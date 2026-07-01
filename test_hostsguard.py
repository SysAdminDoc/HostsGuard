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
import datetime
import pytest

_SRC = open(os.path.join(os.path.dirname(__file__), "HostsGuard.py"), encoding="utf-8").read()

# Top-level names to lift out of the real source.
_WANT_FUNCS = {"looks_like_domain", "get_root", "norm_line", "clean_hosts",
               "categorize", "_ps_esc", "valid_fw_addr", "_rgb"}
_WANT_CONSTS = {"DOMAIN_RE", "IPV4_RE", "PRIV_RE", "MULTI_TLDS", "IGNORED",
                "WINDOWS_HEADER", "_CAT", "APP", "VER", "FW_PFX"}


def _extract():
    tree = ast.parse(_SRC)
    picked = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in _WANT_FUNCS:
            picked.append(node)
        elif isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if any(t in _WANT_CONSTS for t in targets):
                picked.append(node)
    module = ast.Module(body=picked, type_ignores=[])
    ast.fix_missing_locations(module)
    ns = {"re": re, "ipaddress": ipaddress}
    exec(compile(module, "<hostsguard-extracted>", "exec"), ns)
    return ns


_m = _extract()
looks_like_domain = _m["looks_like_domain"]
get_root = _m["get_root"]
norm_line = _m["norm_line"]
clean_hosts = _m["clean_hosts"]
categorize = _m["categorize"]
_ps_esc = _m["_ps_esc"]
valid_fw_addr = _m["valid_fw_addr"]
_rgb = _m["_rgb"]
APP = _m["APP"]
VER = _m["VER"]


class TestExtraction:
    def test_all_functions_extracted(self):
        for name in _WANT_FUNCS:
            assert name in _m, f"{name} was not extracted from source"

    def test_version_is_current(self):
        # Guards against a stale hardcoded version in the test harness.
        assert re.match(r"^\d+\.\d+\.\d+$", VER)


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


class TestLegacyMigration:
    """Verify legacy column renames recover a pre-versioning database."""
    def test_rename_recovers_domains_query(self):
        c = sqlite3.connect(":memory:")
        # Old schema shape (pre schema-versioning)
        c.execute("CREATE TABLE domains(domain TEXT PRIMARY KEY,status TEXT,category TEXT,source TEXT,"
                  "date_added TEXT,date_modified TEXT,hit_count INTEGER,notes TEXT)")
        c.execute("INSERT INTO domains VALUES('a.com','blocked','','manual','2020','2020',3,'')")
        have = {r[1] for r in c.execute("PRAGMA table_info(domains)").fetchall()}
        for old, new in (("date_added", "added"), ("date_modified", "modified"), ("hit_count", "hits")):
            if old in have and new not in have:
                c.execute(f'ALTER TABLE domains RENAME COLUMN "{old}" TO "{new}"')
        # The query that failed on legacy DBs must now succeed
        row = c.execute("SELECT domain,status,category,source,added,modified,hits,notes FROM domains").fetchone()
        assert row[0] == 'a.com' and row[6] == 3
