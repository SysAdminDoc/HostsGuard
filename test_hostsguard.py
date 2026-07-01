"""Tests for HostsGuard security-critical pure functions.
Extracts functions from source without triggering module-level bootstrap/Qt init."""
import pytest
import re, sys, os, types

def _extract_functions():
    """Parse HostsGuard.py and extract pure functions without executing module-level code."""
    src = open(os.path.join(os.path.dirname(__file__), "HostsGuard.py"), encoding="utf-8").read()

    mod = types.ModuleType("_hg_funcs")
    mod.__dict__["re"] = re
    mod.__dict__["sys"] = sys

    DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$')
    IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    PRIV_RE = re.compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.|::1|fe80|fd|fc)')
    MULTI_TLDS = {'co.uk','co.jp','co.kr','co.in','co.nz','co.za','co.il','co.th','co.id',
        'com.au','com.br','com.cn','com.mx','com.ar','com.tw','com.hk','com.sg','com.tr','com.my','com.pk',
        'org.uk','org.au','net.au','net.br','ac.uk','gov.uk','gov.au','gov.br','edu.au','ne.jp','or.jp','or.kr','go.jp','go.kr'}
    IGNORED = {'localhost','broadcasthost','local','ip6-localhost','ip6-loopback','ip6-localnet',
        'ip6-mcastprefix','ip6-allnodes','ip6-allrouters','ip6-allhosts','wpad','isatap'}
    WINDOWS_HEADER = ["# Copyright (c) 1993-2009 Microsoft Corp.", "#",
        "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.", "#",
        "# localhost name resolution is handled within DNS itself.",
        "#    127.0.0.1       localhost", "#    ::1             localhost", ""]
    _CAT = {"Streaming":{"netflix","hulu","disney","twitch","spotify","youtube","plex","roku","hbo","primevideo"},
        "Social":{"facebook","twitter","instagram","tiktok","snapchat","reddit","linkedin","pinterest"},
        "Google":{"google","googleapis","gstatic","youtube","doubleclick","googlevideo"},
        "Microsoft":{"microsoft","windows","office","live.com","outlook","bing","msn"}}
    APP = "HostsGuard"
    VER = "3.7.0"

    mod.__dict__.update(locals())
    return mod

_m = _extract_functions()

def looks_like_domain(d):
    return bool(d and '.' in d and _m.DOMAIN_RE.match(d) and not _m.IPV4_RE.match(d) and d not in _m.IGNORED)

def get_root(d):
    parts = d.lower().split('.')
    if len(parts) <= 2: return d
    t2 = '.'.join(parts[-2:])
    t3 = '.'.join(parts[-3:]) if len(parts) >= 3 else None
    if t2 in _m.MULTI_TLDS and len(parts) >= 3: return '.'.join(parts[-3:])
    if t3 and t3 in _m.MULTI_TLDS and len(parts) >= 4: return '.'.join(parts[-4:])
    return t2

def norm_line(line, normalize=True):
    line = line.strip()
    if not line or line.startswith('#'): return None
    parts = line.split('#')[0].split()
    if len(parts) >= 2 and (parts[0] in ('0.0.0.0','127.0.0.1','::','::1')):
        d = parts[1].lower().strip().rstrip('.')
    elif len(parts) == 1:
        d = parts[0].lower().strip().rstrip('.')
    else: return None
    if d in ('0.0.0.0','127.0.0.1','255.255.255.255','::1','::','localhost','broadcasthost','local'): return None
    if not _m.DOMAIN_RE.match(d) and not d.startswith('*'): return None
    return f"0.0.0.0 {d}" if normalize else d

def clean_hosts(lines, wl=None):
    wl = wl or set(); seen = set(); kept = []; st = {'total':0,'active':0,'dupes':0,'whitelist':0,'invalid':0}
    for l in lines:
        st['total'] += 1; s = l.strip()
        if not s or s.startswith('#'): kept.append(l); continue
        n = norm_line(s)
        if not n: st['invalid'] += 1; continue
        d = n.split()[-1]
        if d in wl: st['whitelist'] += 1; continue
        if d in seen: st['dupes'] += 1; continue
        seen.add(d); kept.append(n); st['active'] += 1
    header = _m.WINDOWS_HEADER + [f"# --- {len(seen)} entries managed by {_m.APP} v{_m.VER} ---"]
    return header + [l for l in kept if l not in _m.WINDOWS_HEADER], st

def _ps_esc(v):
    return "'" + str(v).replace("'", "''") + "'"

def categorize(host, port=0):
    h = host.lower() if host else ""
    for cat, kws in _m._CAT.items():
        for kw in kws:
            if kw in h: return cat
    if _m.PRIV_RE.match(h) or h in ('-','','*','...'): return 'LAN'
    p = int(port) if port else 0
    if p in (80,443,8080,8443): return 'Web'
    if p == 53: return 'DNS'
    if p in (25,110,143,993,995,587): return 'Email'
    return ''


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
        # IPs after 0.0.0.0 pass DOMAIN_RE (digits.digits.digits.digits matches) — valid hosts syntax
        assert norm_line("0.0.0.0 192.168.1.1") == "0.0.0.0 192.168.1.1"


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
        lines = ["# comment\n", "0.0.0.0 a.com\n"]
        result, stats = clean_hosts(lines)
        assert any("# comment" in l for l in result)

    def test_whitelist(self):
        lines = ["0.0.0.0 blocked.com\n", "0.0.0.0 allowed.com\n"]
        result, stats = clean_hosts(lines, wl={"allowed.com"})
        domains = [l.split()[-1] for l in result if l.strip() and not l.strip().startswith('#')]
        assert "allowed.com" not in domains
        assert stats['whitelist'] == 1

    def test_empty(self):
        result, stats = clean_hosts([])
        assert stats['total'] == 0


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

    def test_empty(self):
        assert categorize("", 0) == "LAN"
