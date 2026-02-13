#!/usr/bin/env python3
"""
HostsGuard v3.6.0 — Network Privacy Manager
See what connects. Block what you don't want. Simple.
"""
import sys,os,subprocess,json,sqlite3,re,shutil,time,threading,hashlib,csv,io
import tempfile,webbrowser,socket,datetime,logging
from pathlib import Path
from collections import OrderedDict,defaultdict
from dataclasses import dataclass,field
from queue import Queue,Empty
from threading import Lock,Event as TEvent
import urllib.request,urllib.error

# ─── DPI ────────────────────────────────────────────────────────────────────
os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"]="1"
os.environ["QT_ENABLE_HIGHDPI_SCALING"]="1"
if hasattr(sys,'getwindowsversion'):
    try:
        import ctypes; ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except: pass

# ─── Bootstrap ──────────────────────────────────────────────────────────────
NOWIN=getattr(subprocess,'CREATE_NO_WINDOW',0x08000000)
def _kill_remnants():
    if sys.platform!='win32': return
    pid=os.getpid(); script=os.path.abspath(__file__).lower()
    try:
        import psutil as _p
        for p in _p.process_iter(['pid','name','cmdline']):
            try:
                if p.info['pid']==pid: continue
                n=(p.info['name'] or '').lower(); cl=' '.join(p.info['cmdline'] or []).lower()
                if 'python' in n and script in cl: p.kill()
                elif 'powershell' in n and ('hostsguard' in cl or 'get-dnsclientcache' in cl or 'get-netfirewallrule' in cl): p.kill()
            except: continue
    except: pass

def _bootstrap():
    if sys.platform=='win32':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            try:
                h=ctypes.windll.kernel32.GetConsoleWindow()
                if h: ctypes.windll.user32.ShowWindow(h,0)
            except: pass
            ctypes.windll.shell32.ShellExecuteW(None,"runas",sys.executable,f'"{os.path.abspath(__file__)}"',None,1)
            os._exit(0)
    _kill_remnants()
    if sys.version_info<(3,8): print("Python 3.8+ required"); sys.exit(1)
    for pkg in ['PyQt5','psutil']:
        try: __import__(pkg if pkg=='psutil' else 'PyQt5')
        except ImportError:
            for f in [[],['--user'],['--break-system-packages']]:
                try: subprocess.check_call([sys.executable,'-m','pip','install',pkg,'-q']+f,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=NOWIN); break
                except: continue
_bootstrap()

import psutil
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
QApplication.setAttribute(Qt.AA_EnableHighDpiScaling,True)
QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps,True)

# ─── Constants ──────────────────────────────────────────────────────────────
APP="HostsGuard"; VER="3.6.0"; FW_PFX="HG_"
HOSTS_PATH=r"C:\Windows\System32\drivers\etc\hosts" if sys.platform=='win32' else "/etc/hosts"
CONFIG_DIR=os.path.join(os.environ.get('APPDATA',os.path.expanduser('~')),APP)
DB_PATH=os.path.join(CONFIG_DIR,"hostsguard.db")
CONN_DB=os.path.join(CONFIG_DIR,"connections.db")
FAV_DIR=os.path.join(CONFIG_DIR,"favicons")
CFG_PATH=os.path.join(CONFIG_DIR,"config.json")
for d in [CONFIG_DIR,FAV_DIR,os.path.join(CONFIG_DIR,"backups")]: os.makedirs(d,exist_ok=True)

log=logging.getLogger("HG")
try:
    from logging.handlers import RotatingFileHandler
    _fh=RotatingFileHandler(os.path.join(CONFIG_DIR,"hostsguard.log"),maxBytes=512_000,backupCount=1,encoding='utf-8')
    _fh.setLevel(logging.WARNING)
    _fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s',datefmt='%Y-%m-%d %H:%M:%S'))
    log.addHandler(_fh)
except: pass
log.setLevel(logging.WARNING)
SCHEMA_VER=4
WINDOWS_HEADER=["# Copyright (c) 1993-2009 Microsoft Corp.","#","# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.","#",
    "# localhost name resolution is handled within DNS itself.","#    127.0.0.1       localhost","#    ::1             localhost",""]
IGNORED={'localhost','broadcasthost','local','ip6-localhost','ip6-loopback','ip6-localnet','ip6-mcastprefix','ip6-allnodes',
    'ip6-allrouters','ip6-allhosts','wpad','isatap'}
DOMAIN_RE=re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$')
IPV4_RE=re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
PRIV_RE=re.compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.|::1|fe80|fd|fc)')
MULTI_TLDS={'co.uk','co.jp','co.kr','co.in','co.nz','co.za','co.il','co.th','co.id',
    'com.au','com.br','com.cn','com.mx','com.ar','com.tw','com.hk','com.sg','com.tr','com.my','com.pk',
    'org.uk','org.au','net.au','net.br','ac.uk','gov.uk','gov.au','gov.br','edu.au','ne.jp','or.jp','or.kr','go.jp','go.kr'}
PORTS={80:'HTTP',443:'HTTPS',22:'SSH',21:'FTP',25:'SMTP',53:'DNS',110:'POP3',143:'IMAP',993:'IMAPS',
    995:'POP3S',3389:'RDP',8080:'HTTP-Alt',8443:'HTTPS-Alt',5060:'SIP',5222:'XMPP',3306:'MySQL',
    5432:'Postgres',27017:'MongoDB',6379:'Redis',11211:'Memcached'}
RESEARCH=[("Google","https://www.google.com/search?q={d}"),("VirusTotal","https://www.virustotal.com/gui/domain/{d}"),("who.is","https://who.is/whois/{d}"),
    ("URLScan","https://urlscan.io/search/#{d}"),("Shodan","https://www.shodan.io/search?query={d}"),
    ("SecurityTrails","https://securitytrails.com/domain/{d}"),("MXToolbox","https://mxtoolbox.com/SuperTool.aspx?action=mx:{d}"),
    ("AbuseIPDB","https://www.abuseipdb.com/check/{d}"),("ThreatCrowd","https://www.threatcrowd.org/domain.php?domain={d}"),
    ("DNSDumpster","https://dnsdumpster.com/?q={d}")]
_CAT={"Streaming":{"netflix","hulu","disney","twitch","spotify","youtube","plex","roku","hbo","primevideo","crunchyroll","dazn","tubi","peacock"},
    "Social":{"facebook","twitter","instagram","tiktok","snapchat","reddit","linkedin","pinterest","tumblr","whatsapp","telegram","discord","mastodon"},
    "Gaming":{"steam","epicgames","xbox","playstation","riotgames","blizzard","ea.com","unity","twitch","mojang","valve"},
    "Cloud":{"dropbox","icloud","onedrive","gdrive","box.com","mega.nz","backblaze","wasabi","s3.amazonaws"},
    "Messaging":{"slack","teams","zoom","skype","signal","viber","line.me","webex","gotomeeting"},
    "Dev":{"github","gitlab","stackoverflow","npm","pypi","docker","aws","azure","gcp","heroku","vercel","netlify"},
    "Security":{"virustotal","malwarebytes","kaspersky","norton","avast","bitdefender","sophos","crowdstrike"},
    "Microsoft":{"microsoft","windows","office","live.com","outlook","bing","msn","skype","xbox","azure","visualstudio","msedge"},
    "Google":{"google","googleapis","gstatic","youtube","doubleclick","googlevideo","gvt1","gvt2"},
    "CDN":{"akamai","cloudflare","fastly","cloudfront","edgecast","jsdelivr","unpkg"}}

# ─── Blocklist Sources ──────────────────────────────────────────────────────
SOURCES={
    "Popular":[
        ("HaGezi Ultimate","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/ultimate.txt"),
        ("StevenBlack Unified","https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
        ("OISD Full","https://hosts.oisd.nl/"),
        ("HOSTShield Combined","https://github.com/SysAdminDoc/HOSTShield/releases/download/v.1/CombinedAll.txt")],
    "Ads & Tracking":[
        ("Disconnect Tracking","https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt"),
        ("Disconnect Ads","https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt"),
        ("EasyList","https://v.firebog.net/hosts/Easylist.txt"),("EasyPrivacy","https://v.firebog.net/hosts/Easyprivacy.txt"),
        ("AdGuard DNS","https://v.firebog.net/hosts/AdguardDNS.txt"),("AdAway","https://adaway.org/hosts.txt"),
        ("Yoyo Servers","https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"),
        ("NoCoin Crypto","https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"),
        ("HOSTShield Ads","https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/AdsTrackingAnalytics.txt")],
    "Privacy":[
        ("Windows Spy Blocker","https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"),
        ("Frogeye 1st Party","https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt"),
        ("Perflyst SmartTV","https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt")],
    "Malware":[
        ("Spam404","https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt"),
        ("Phishing Army","https://phishing.army/download/phishing_army_blocklist.txt"),
        ("URLHaus","https://urlhaus.abuse.ch/downloads/hostfile/"),
        ("Stamparm Maltrail","https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt")],
    "Vendor":[
        ("Amazon","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.amazon.txt"),
        ("Apple","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.apple.txt"),
        ("Windows/Office","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.winoffice.txt"),
        ("TikTok","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.tiktok.extended.txt"),
        ("Samsung","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.samsung.txt")]}

# ─── Theme ──────────────────────────────────────────────────────────────────
C={"bg":"#0f0f17","base":"#181824","mantle":"#13131f","crust":"#0f0f17","s0":"#252540","s1":"#333355","s2":"#444466",
   "text":"#e4e6f0","sub":"#9ea0b8","dim":"#6a6c88","blue":"#7aa2f7","green":"#9ece6a","red":"#f7768e",
   "peach":"#ff9e64","yellow":"#e0af68","mauve":"#bb9af7","teal":"#73daca","sky":"#7dcfff","sel":"rgba(122,162,247,0.12)"}

def _dp(px):
    try:
        s=QApplication.primaryScreen()
        if s: return max(1,int(px*s.logicalDotsPerInch()/96.0))
    except: pass
    return px

STYLE=f"""
*{{font-family:'Segoe UI Variable','Segoe UI','Inter',sans-serif;}}
QMainWindow,QDialog{{background:{C['bg']};}}
QWidget{{background:transparent;color:{C['text']};}}
QPushButton{{background:{C['s0']};color:{C['sub']};border:1px solid {C['s1']};padding:7px 16px;border-radius:8px;font-weight:600;}}
QPushButton:hover{{background:{C['s1']};color:{C['text']};}}
QPushButton:pressed{{background:{C['s0']};}}
QPushButton:disabled{{color:{C['dim']};}}
QPushButton[class="primary"]{{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #5b7ee5,stop:1 {C['blue']});color:#fff;border:none;font-weight:700;}}
QPushButton[class="primary"]:hover{{background:#8ab4ff;}}
QPushButton[class="danger"]{{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #d5496a,stop:1 {C['red']});color:#fff;border:none;}}
QPushButton[class="danger"]:hover{{background:#ff8ea5;}}
QPushButton[class="success"]{{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #7ab85a,stop:1 {C['green']});color:#111;border:none;}}
QPushButton[class="dim"]{{background:{C['s0']};color:{C['dim']};border:1px solid {C['s1']};}}
QPushButton[class="dim"]:hover{{color:{C['text']};background:{C['s1']};}}
QLineEdit,QTextEdit,QPlainTextEdit{{background:{C['mantle']};color:{C['text']};border:1px solid {C['s0']};border-radius:8px;padding:8px 12px;selection-background-color:{C['blue']};selection-color:#111;}}
QLineEdit:focus,QTextEdit:focus,QPlainTextEdit:focus{{border-color:{C['blue']};}}
QComboBox{{background:{C['mantle']};color:{C['text']};border:1px solid {C['s0']};border-radius:8px;padding:7px 12px;min-width:80px;}}
QComboBox::drop-down{{border:none;width:24px;}}QComboBox::down-arrow{{image:none;border-left:4px solid transparent;border-right:4px solid transparent;border-top:5px solid {C['sub']};margin-right:8px;}}
QComboBox QAbstractItemView{{background:{C['mantle']};color:{C['text']};border:1px solid {C['s1']};selection-background-color:{C['blue']};selection-color:#111;outline:none;border-radius:6px;padding:4px;}}
QTabWidget::pane{{border:none;background:{C['base']};}}
QTabBar{{background:{C['crust']};qproperty-drawBase:0;}}
QTabBar::tab{{background:transparent;color:{C['dim']};padding:12px 24px;border:none;border-bottom:2px solid transparent;font-weight:700;font-size:12px;}}
QTabBar::tab:selected{{color:{C['blue']};border-bottom-color:{C['blue']};background:rgba(122,162,247,0.05);}}
QTabBar::tab:hover:!selected{{color:{C['text']};}}
QTabBar::tab:first{{margin-left:12px;}}
QTableWidget{{background:{C['mantle']};alternate-background-color:rgba(19,19,31,0.5);color:{C['text']};border:1px solid {C['s0']};border-radius:10px;gridline-color:rgba(51,51,85,0.3);selection-background-color:{C['sel']};selection-color:{C['text']};outline:none;}}
QTableWidget::item{{padding:5px 10px;border:none;}}QTableWidget::item:selected{{background:{C['sel']};}}
QHeaderView{{background:transparent;}}
QHeaderView::section{{background:{C['crust']};color:{C['dim']};border:none;border-bottom:1px solid {C['s0']};border-right:1px solid rgba(51,51,85,0.2);padding:8px 12px;font-weight:700;font-size:10px;text-transform:uppercase;letter-spacing:0.8px;}}
QScrollBar:vertical{{background:transparent;width:6px;margin:4px 0;}}QScrollBar::handle:vertical{{background:{C['s1']};border-radius:3px;min-height:40px;}}
QScrollBar::handle:vertical:hover{{background:{C['s2']};}}QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}
QScrollBar:horizontal{{background:transparent;height:6px;}}QScrollBar::handle:horizontal{{background:{C['s1']};border-radius:3px;}}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{{width:0;}}
QGroupBox{{border:1px solid {C['s0']};border-radius:12px;margin-top:1.5em;padding:16px 12px 12px;background:{C['mantle']};}}
QGroupBox::title{{subcontrol-origin:margin;left:14px;padding:0 8px;color:{C['blue']};font-size:11px;font-weight:700;}}
QProgressBar{{background:{C['s0']};border:none;border-radius:6px;text-align:center;color:#fff;font-weight:700;min-height:10px;}}
QProgressBar::chunk{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #5b7ee5,stop:1 {C['teal']});border-radius:6px;}}
QCheckBox{{color:{C['text']};spacing:8px;}}QCheckBox::indicator{{width:18px;height:18px;border:2px solid {C['s1']};border-radius:5px;background:{C['mantle']};}}
QCheckBox::indicator:checked{{background:{C['blue']};border-color:{C['blue']};}}
QToolTip{{background:{C['s0']};color:{C['text']};border:1px solid {C['s1']};padding:6px 10px;border-radius:8px;}}
QSplitter::handle{{background:{C['s0']};width:2px;}}QLabel{{color:{C['text']};background:transparent;}}
QScrollArea{{background:transparent;border:none;}}
"""
CTX=f"QMenu{{background:{C['mantle']};color:{C['text']};border:1px solid {C['s1']};border-radius:10px;padding:6px;}}QMenu::item{{padding:7px 20px;border-radius:5px;}}QMenu::item:selected{{background:{C['s0']};}}QMenu::separator{{height:1px;background:{C['s0']};margin:4px 8px;}}"

# ─── Config ─────────────────────────────────────────────────────────────────
def load_cfg():
    try:
        with open(CFG_PATH) as f: return json.load(f)
    except: return {}
def save_cfg(c):
    with open(CFG_PATH,'w') as f: json.dump(c,f,indent=2)

# ─── Helpers ────────────────────────────────────────────────────────────────
def looks_like_domain(d): return bool(d and '.' in d and DOMAIN_RE.match(d) and not IPV4_RE.match(d) and d not in IGNORED)
def get_root(d):
    parts=d.lower().split('.')
    if len(parts)<=2: return d
    t2='.'.join(parts[-2:]); t3='.'.join(parts[-3:]) if len(parts)>=3 else None
    if t2 in MULTI_TLDS and len(parts)>=3: return '.'.join(parts[-3:])
    if t3 and t3 in MULTI_TLDS and len(parts)>=4: return '.'.join(parts[-4:])
    return t2
def norm_line(line,normalize=True):
    line=line.strip()
    if not line or line.startswith('#'): return None
    parts=line.split('#')[0].split()
    if len(parts)>=2 and (parts[0] in ('0.0.0.0','127.0.0.1','::','::1')): d=parts[1].lower().strip().rstrip('.')
    elif len(parts)==1: d=parts[0].lower().strip().rstrip('.')
    else: return None
    if d in ('0.0.0.0','127.0.0.1','255.255.255.255','::1','::','localhost','broadcasthost','local'): return None
    if not DOMAIN_RE.match(d) and not d.startswith('*'): return None
    return f"0.0.0.0 {d}" if normalize else d
def clean_hosts(lines,wl=None):
    wl=wl or set(); seen=set(); kept=[]; st={'total':0,'active':0,'dupes':0,'whitelist':0,'invalid':0}
    for l in lines:
        st['total']+=1; s=l.strip()
        if not s or s.startswith('#'): kept.append(l); continue
        n=norm_line(s)
        if not n: st['invalid']+=1; continue
        d=n.split()[-1]
        if d in wl: st['whitelist']+=1; continue
        if d in seen: st['dupes']+=1; continue
        seen.add(d); kept.append(n); st['active']+=1
    header=WINDOWS_HEADER+[f"# --- {len(seen)} entries managed by {APP} v{VER} ---"]
    return header+[l for l in kept if l not in WINDOWS_HEADER],st
def categorize(host,port=0):
    h=host.lower() if host else ""
    for cat,kws in _CAT.items():
        for kw in kws:
            if kw in h: return cat
    if PRIV_RE.match(h) or h in ('-','','*','...'): return 'LAN'
    p=int(port) if port else 0
    if p in (80,443,8080,8443): return 'Web'
    if p==53: return 'DNS'
    if p in (25,110,143,993,995,587): return 'Email'
    return ''
def open_research(d):
    r=get_root(d); m=QMenu(); m.setStyleSheet(CTX)
    for name,url in RESEARCH: a=m.addAction(f"  {name}"); a.setData(url.replace('{d}',r))
    m.addSeparator(); a2=m.addAction(f"  VirusTotal (exact)"); a2.setData(f"https://www.virustotal.com/gui/domain/{d}")
    ch=m.exec_(QCursor.pos())
    if ch and ch.data(): webbrowser.open(ch.data())
def _ps(cmd,t=20):
    try:
        r=subprocess.run(['powershell','-NoProfile','-Command',cmd],capture_output=True,text=True,timeout=t,creationflags=NOWIN)
        return r.returncode==0,r.stdout.strip()
    except: return False,""

# ─── LRU Cache ──────────────────────────────────────────────────────────────
class LRU:
    def __init__(s,cap=5000): s._d=OrderedDict(); s._cap=cap; s._lock=Lock()
    def get(s,k):
        with s._lock:
            if k in s._d: s._d.move_to_end(k); return s._d[k]
        return None
    def put(s,k,v):
        with s._lock:
            s._d[k]=v; s._d.move_to_end(k)
            while len(s._d)>s._cap: s._d.popitem(False)
    def __contains__(s,k):
        with s._lock: return k in s._d
    def clear(s):
        with s._lock: s._d.clear()
dns_c=LRU(); who_c=LRU(); geo_c=LRU(); proc_c=LRU(2000)

# ─── Data Structures ───────────────────────────────────────────────────────
@dataclass
class CI:
    key:str="";ts:str="";src:str="";dir:str="";proto:str=""
    la:str="";lp:str="";ra:str="";rp:str=""
    host:str="-";proc:str="?";pid:int=0;state:str=""
    path:str="";org:str="-";stat:str="-";country:str="-";cc:str="";category:str=""
@dataclass
class FWR:
    name:str="";direction:str="Out";action:str="Block";enabled:bool=True
    remote_addr:str="Any";protocol:str="Any";program:str="";source:str="system"

# ─── FaviconCache ───────────────────────────────────────────────────────────
class FaviconCache(QObject):
    ready=pyqtSignal(str)
    def __init__(s):
        super().__init__(); s._mem={}; s._pending=set(); s._lock=Lock()
    def get(s,domain):
        if domain in s._mem: return s._mem[domain]
        h=hashlib.md5(domain.encode()).hexdigest(); p=os.path.join(FAV_DIR,f"{h}.png")
        if os.path.exists(p):
            px=QPixmap(p)
            if not px.isNull(): s._mem[domain]=px; return px
        with s._lock:
            if domain not in s._pending: s._pending.add(domain); threading.Thread(target=s._fetch,args=(domain,h,p),daemon=True).start()
        return None
    def _fetch(s,domain,h,p):
        try:
            r=get_root(domain); url=f"https://www.google.com/s2/favicons?domain={r}&sz=32"
            req=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'})
            with urllib.request.urlopen(req,timeout=8) as resp:
                data=resp.read()
                if len(data)>100:
                    with open(p,'wb') as f: f.write(data)
                    px=QPixmap(); px.loadFromData(data)
                    if not px.isNull(): s._mem[domain]=px
        except: pass
        finally:
            with s._lock: s._pending.discard(domain)
            s.ready.emit(domain)
_fav=None
def _init_fav():
    global _fav
    if not _fav: _fav=FaviconCache()

# ─── Database (with schema versioning) ─────────────────────────────────────
class DB:
    def __init__(s):
        s.conn=sqlite3.connect(DB_PATH,check_same_thread=False); s.conn.execute("PRAGMA journal_mode=WAL")
        s.conn.execute("PRAGMA busy_timeout=5000"); s._lock=Lock(); s._migrate()
        s._blocked_cache=None; s._blocked_ts=0
    def _migrate(s):
        s.conn.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT)")
        try:
            v=int(s.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0])
        except: v=0
        if v<1:
            s.conn.execute("CREATE TABLE IF NOT EXISTS domains(domain TEXT PRIMARY KEY,status TEXT DEFAULT 'blocked',category TEXT,source TEXT,added TEXT,modified TEXT,hits INTEGER DEFAULT 0,notes TEXT)")
            s.conn.execute("CREATE TABLE IF NOT EXISTS feed(domain TEXT PRIMARY KEY,first_seen TEXT,last_seen TEXT,hits INTEGER DEFAULT 1,process TEXT,hidden INTEGER DEFAULT 0)")
            s.conn.execute("CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY,ts TEXT,domain TEXT,action TEXT,process TEXT,details TEXT)")
            s.conn.execute("CREATE INDEX IF NOT EXISTS idx_log_ts ON log(ts)")
            s.conn.execute("CREATE INDEX IF NOT EXISTS idx_feed_ls ON feed(last_seen)")
        if v<2:
            try: s.conn.execute("ALTER TABLE feed ADD COLUMN hidden INTEGER DEFAULT 0")
            except: pass
        if v<3:
            s.conn.execute("CREATE TABLE IF NOT EXISTS fw_state(name TEXT PRIMARY KEY,direction TEXT,action TEXT,remote_addr TEXT,protocol TEXT,program TEXT,created TEXT)")
        if v<4:
            s.conn.execute("CREATE TABLE IF NOT EXISTS hidden_roots(root TEXT PRIMARY KEY,added TEXT)")
        s.conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)",(str(SCHEMA_VER),))
        s.conn.commit()
    def _x(s,sql,p=(),many=False):
        with s._lock:
            try:
                if many: s.conn.executemany(sql,p)
                else: s.conn.execute(sql,p)
                s.conn.commit()
            except Exception as e: log.warning(f"DB: {e}")
    def _q(s,sql,p=()):
        with s._lock:
            try: return s.conn.execute(sql,p).fetchall()
            except Exception as e: log.warning(f"DB query: {e} | {sql[:80]}"); return []
    # Domains
    def add_domain(s,d,status='blocked',source='',cat=''):
        now=datetime.datetime.now().isoformat()
        s._x("INSERT OR REPLACE INTO domains(domain,status,category,source,added,modified,hits)VALUES(?,?,?,?,?,?,COALESCE((SELECT hits FROM domains WHERE domain=?),0))",(d,status,cat,source,now,now,d))
        s._blocked_cache=None
    def get_domains(s,status=None,search=None):
        q="SELECT domain,status,category,source,added,modified,hits,notes FROM domains WHERE 1=1"
        p=[]
        if status: q+=" AND status=?"; p.append(status)
        if search: q+=" AND domain LIKE ?"; p.append(f"%{search}%")
        return s._q(q+" ORDER BY modified DESC",p)
    def remove_domain(s,d): s._x("DELETE FROM domains WHERE domain=?",((d,))); s._blocked_cache=None
    def update_status(s,d,st):
        s._x("UPDATE domains SET status=?,modified=? WHERE domain=?",(st,datetime.datetime.now().isoformat(),d))
        s._blocked_cache=None
    def add_root(s,d,status,source):
        root=get_root(d); ct=0
        for r in s._q("SELECT domain FROM feed WHERE domain LIKE ?",(f"%{root}",)):
            s.add_domain(r[0],status,source); ct+=1
        s.add_domain(root,status,source); return ct
    def get_blocked_set(s):
        now=time.time()
        with s._lock:
            if s._blocked_cache and now-s._blocked_ts<5: return s._blocked_cache
            s._blocked_cache={r[0] for r in s.conn.execute("SELECT domain FROM domains WHERE status='blocked'").fetchall()}
            s._blocked_ts=now; return s._blocked_cache
    # Feed
    def feed_upsert(s,d,proc=''):
        now=datetime.datetime.now().isoformat()
        with s._lock:
            try:
                r=s.conn.execute("SELECT domain,hidden FROM feed WHERE domain=?",(d,)).fetchone()
                if r:
                    if r[1]==1: return False  # Hidden — don't bump, don't report as new
                    s.conn.execute("UPDATE feed SET last_seen=?,hits=hits+1,process=COALESCE(NULLIF(?,''),(SELECT process FROM feed WHERE domain=?)) WHERE domain=?",(now,proc,d,d))
                else:
                    # Check if this domain matches a hidden root
                    root=get_root(d)
                    hr=s.conn.execute("SELECT 1 FROM hidden_roots WHERE root=?",(root,)).fetchone()
                    if hr:
                        # Insert as pre-hidden so it never surfaces
                        s.conn.execute("INSERT INTO feed(domain,first_seen,last_seen,hits,process,hidden)VALUES(?,?,?,1,?,1)",(d,now,now,proc))
                        s.conn.commit(); return False
                    s.conn.execute("INSERT INTO feed(domain,first_seen,last_seen,hits,process)VALUES(?,?,?,1,?)",(d,now,now,proc))
                s.conn.commit(); return r is None
            except Exception as e: log.warning(f"feed_upsert {d}: {e}"); return False
    def feed_get(s,search=None,show_hidden=False,status_filter=None):
        q="""SELECT f.domain,f.first_seen,f.last_seen,f.hits,f.process,f.hidden,
            COALESCE(d.status,'unmanaged') FROM feed f LEFT JOIN domains d ON f.domain=d.domain WHERE 1=1"""
        p=[]
        if not show_hidden: q+=" AND f.hidden=0"
        else: q+=" AND f.hidden=1"
        if status_filter and status_filter!='hidden': q+=" AND COALESCE(d.status,'unmanaged')=?"; p.append(status_filter)
        if search: q+=" AND f.domain LIKE ?"; p.append(f"%{search}%")
        return s._q(q+" ORDER BY f.last_seen DESC LIMIT 2000",p)
    def feed_hide(s,d): s._x("UPDATE feed SET hidden=1 WHERE domain=?",(d,))
    def feed_unhide(s,d): s._x("UPDATE feed SET hidden=0 WHERE domain=?",(d,))
    def feed_delete(s,d): s._x("DELETE FROM feed WHERE domain=?",(d,))
    def feed_hide_bulk(s,ds): s._x("UPDATE feed SET hidden=1 WHERE domain=?",[(d,) for d in ds],many=True)
    def feed_hide_root(s,d):
        root=get_root(d); s._x("UPDATE feed SET hidden=1 WHERE domain LIKE ?",(f"%{root}",))
        now=datetime.datetime.now().isoformat()
        s._x("INSERT OR IGNORE INTO hidden_roots(root,added)VALUES(?,?)",(root,now))
    def feed_unhide_root(s,d):
        root=get_root(d); s._x("UPDATE feed SET hidden=0 WHERE domain LIKE ?",(f"%{root}",))
        s._x("DELETE FROM hidden_roots WHERE root=?",(root,))
    def get_hidden_roots(s):
        return {r[0] for r in s._q("SELECT root FROM hidden_roots")}
    def feed_count(s,hidden=False):
        r=s._q(f"SELECT COUNT(*) FROM feed WHERE hidden={'1' if hidden else '0'}"); return r[0][0] if r else 0
    def get_hidden_set(s):
        """All hidden domains — used to pre-populate DNSMonitor._seen."""
        return {r[0] for r in s._q("SELECT domain FROM feed WHERE hidden=1")}
    # FW State tracking
    def save_fw_rule(s,name,direction='',action='Block',remote_addr='',protocol='',program=''):
        now=datetime.datetime.now().isoformat()
        s._x("INSERT OR REPLACE INTO fw_state(name,direction,action,remote_addr,protocol,program,created)VALUES(?,?,?,?,?,?,?)",
            (name,direction,action,remote_addr,protocol,program,now))
    def remove_fw_rule(s,name): s._x("DELETE FROM fw_state WHERE name=?",(name,))
    def get_fw_state(s): return s._q("SELECT name,direction,action,remote_addr,protocol,program,created FROM fw_state ORDER BY created DESC")
    def clear_fw_state(s): s._x("DELETE FROM fw_state")
    # Hosts -> DB sync
    def sync_hosts_to_db(s,hm):
        """Ensure all hosts file blocked entries exist in domains table.
        Uses a single transaction for performance with large hosts files."""
        hosts_blocked=hm.get_blocked()
        if not hosts_blocked: return 0
        db_all={r[0] for r in s._q("SELECT domain FROM domains")}
        new_domains=[(d,'blocked','','hosts_file',datetime.datetime.now().isoformat()) for d in hosts_blocked if d not in db_all]
        if not new_domains:
            return 0
        with s._lock:
            try:
                s.conn.executemany(
                    "INSERT OR IGNORE INTO domains(domain,status,category,source,added,modified,hits)VALUES(?,?,?,?,?,?,0)",
                    [(d,st,cat,src,ts,ts) for d,st,cat,src,ts in new_domains])
                s.conn.commit()
            except Exception as e: log.warning(f"DB sync: {e}"); return 0
        s._blocked_cache=None
        return len(new_domains)
    # Log
    def log_event(s,d,action,proc='',det=''):
        s._x("INSERT INTO log(ts,domain,action,process,details)VALUES(?,?,?,?,?)",(datetime.datetime.now().isoformat(),d,action,proc,det))
    def get_log(s,limit=200,domain_filter=None,action_filter='all',since=None):
        q="SELECT id,ts,domain,action,process,details FROM log WHERE 1=1"; p=[]
        if domain_filter: q+=" AND domain LIKE ?"; p.append(f"%{domain_filter}%")
        if action_filter and action_filter!='all': q+=" AND action=?"; p.append(action_filter)
        if since: q+=" AND ts>=?"; p.append(since)
        return s._q(q+f" ORDER BY ts DESC LIMIT {limit}",p)
    def clear_log(s): s._x("DELETE FROM log")
    def get_stats(s):
        b=s._q("SELECT COUNT(*) FROM domains WHERE status='blocked'"); bl=b[0][0] if b else 0
        w=s._q("SELECT COUNT(*) FROM domains WHERE status='whitelisted'"); wl=w[0][0] if w else 0
        f=s._q("SELECT COUNT(*) FROM feed WHERE hidden=0"); ft=f[0][0] if f else 0
        today=datetime.datetime.now().strftime('%Y-%m-%d')
        t=s._q("SELECT COUNT(*) FROM log WHERE action='blocked' AND ts>=?",(today,)); th=t[0][0] if t else 0
        top=s._q("SELECT domain,COUNT(*) c FROM log WHERE action='blocked' GROUP BY domain ORDER BY c DESC LIMIT 10")
        return {'blocked':bl,'whitelisted':wl,'feed_total':ft,'today_hits':th,'top_blocked':top}

class ConnDB:
    def __init__(s):
        s.conn=sqlite3.connect(CONN_DB,check_same_thread=False); s.conn.execute("PRAGMA journal_mode=WAL")
        s.conn.execute("PRAGMA busy_timeout=5000"); s._lock=Lock()
        s.conn.execute("""CREATE TABLE IF NOT EXISTS conns(id INTEGER PRIMARY KEY,ts TEXT,proto TEXT,la TEXT,lp TEXT,
            ra TEXT,rp TEXT,host TEXT,proc TEXT,pid INTEGER,state TEXT,org TEXT,country TEXT,cc TEXT,category TEXT,
            UNIQUE(ts,proto,la,lp,ra,rp,pid))""")
        s.conn.execute("CREATE INDEX IF NOT EXISTS idx_cts ON conns(ts)"); s.conn.commit()
    def insert_batch(s,conns):
        with s._lock:
            for c in conns:
                try: s.conn.execute("INSERT OR IGNORE INTO conns(ts,proto,la,lp,ra,rp,host,proc,pid,state,org,country,cc,category)VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (c.ts,c.proto,c.la,c.lp,c.ra,c.rp,c.host,c.proc,c.pid,c.state,c.org,c.country,c.cc,c.category))
                except: pass
            s.conn.commit()
    def search(s,q='',limit=500,offset=0):
        with s._lock:
            sql="SELECT ts,proto,la,lp,ra,rp,host,proc,pid,state,org,country,cc,category FROM conns"
            p=[]
            if q: sql+=" WHERE host LIKE ? OR proc LIKE ? OR ra LIKE ?"; p=[f"%{q}%"]*3
            return s.conn.execute(sql+" ORDER BY ts DESC LIMIT ? OFFSET ?",[*p,limit,offset]).fetchall()
    def get_stats(s):
        with s._lock:
            t=s.conn.execute("SELECT COUNT(*) FROM conns").fetchone()[0]
            today=datetime.datetime.now().strftime('%Y-%m-%d')
            b=s.conn.execute("SELECT COUNT(*) FROM conns WHERE ts>=?",(today,)).fetchone()[0]
            return {'total':t,'blocked':b}
    def prune(s,days=30):
        cut=(datetime.datetime.now()-datetime.timedelta(days=days)).isoformat()
        with s._lock: s.conn.execute("DELETE FROM conns WHERE ts<?",(cut,)); s.conn.commit()
    def count(s):
        with s._lock: return s.conn.execute("SELECT COUNT(*) FROM conns").fetchone()[0]


# ─── Firewall Engine ────────────────────────────────────────────────────────

# ─── Persistent PowerShell Session ──────────────────────────────────────────
class PersistentPS:
    """Keep a single PowerShell process alive — send commands via stdin, read stdout.
    Eliminates ~200ms process-spawn overhead per command."""
    _DELIM="---HG_END---"
    def __init__(s):
        s._proc=None; s._lock=Lock(); s._alive=False
    def _ensure(s):
        if s._alive and s._proc and s._proc.poll() is None: return True
        try:
            s._proc=subprocess.Popen(
                ['powershell','-NoProfile','-NoLogo','-NonInteractive','-Command','-'],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                text=True,creationflags=NOWIN,bufsize=1)
            s._alive=True; return True
        except: s._alive=False; return False
    def run(s,cmd,timeout=20):
        with s._lock:
            if not s._ensure(): return False,""
            try:
                full=f"{cmd}\nWrite-Output '{s._DELIM}'\n"
                s._proc.stdin.write(full); s._proc.stdin.flush()
                lines=[]; deadline=time.time()+timeout
                while time.time()<deadline:
                    line=s._proc.stdout.readline()
                    if not line: break
                    line=line.rstrip('\n\r')
                    if line==s._DELIM: break
                    lines.append(line)
                return True,'\n'.join(lines)
            except:
                s._alive=False; return False,""
    def close(s):
        with s._lock:
            if s._proc:
                try: s._proc.stdin.write("exit\n"); s._proc.stdin.flush(); s._proc.wait(3)
                except:
                    try: s._proc.kill()
                    except: pass
            s._alive=False
_pps=PersistentPS()

def _ps(cmd,t=20):
    """Run PowerShell command — uses persistent session first, falls back to subprocess."""
    ok,out=_pps.run(cmd,t)
    if ok: return True,out.strip()
    try:
        r=subprocess.run(['powershell','-NoProfile','-Command',cmd],capture_output=True,text=True,timeout=t,creationflags=NOWIN)
        return r.returncode==0,r.stdout.strip()
    except: return False,""

# ─── Firewall Engine (background-loadable) ──────────────────────────────────
class FWEngine:
    def __init__(s): s._cache=[]; s._lock=Lock(); s._ts=0; s._ttl=180; s._loading=False; s._db=None
    def set_db(s,db): s._db=db
    def _inv(s):
        with s._lock: s._ts=0
    def _track(s,name,direction='',action='Block',remote_addr='',protocol='',program=''):
        if s._db and name.startswith(FW_PFX): s._db.save_fw_rule(name,direction,action,remote_addr,protocol,program)
    def _untrack(s,name):
        if s._db and name.startswith(FW_PFX): s._db.remove_fw_rule(name)
    @property
    def loading(s): return s._loading
    @property
    def cached(s):
        with s._lock: return bool(s._cache and time.time()-s._ts<s._ttl)
    def exists(s,name):
        with s._lock:
            if s._cache: return any(r.name==name for r in s._cache)
        ok,out=_ps(f'(Get-NetFirewallRule -DisplayName "{name}" -EA SilentlyContinue) -ne $null',8)
        return ok and out.strip().lower()=="true"
    def create(s,name,direction="Outbound",action="Block",remote_addr="",protocol="",program="",desc=""):
        p=[f'New-NetFirewallRule -DisplayName "{name}" -Direction {direction} -Action {action} -Enabled True -Profile Any']
        if remote_addr and remote_addr not in ("*","Any"): p.append(f'-RemoteAddress "{remote_addr}"')
        if protocol and protocol not in ("","Any"): p.append(f'-Protocol {protocol}')
        if program: p.append(f'-Program "{program}"')
        if desc: p.append(f'-Description "{desc}"')
        ok,_=_ps(' '.join(p),15); s._inv()
        if ok: s._track(name,direction,action,remote_addr,protocol,program)
        return ok
    def delete(s,name): ok,_=_ps(f'Remove-NetFirewallRule -DisplayName "{name}" -EA SilentlyContinue',10); s._inv(); s._untrack(name); return ok
    def enable(s,name,on=True): _ps(f'{"Enable" if on else "Disable"}-NetFirewallRule -DisplayName "{name}" -EA SilentlyContinue',10); s._inv()
    def set_action(s,name,action):
        """Change rule action to Block or Allow."""
        _ps(f'Set-NetFirewallRule -DisplayName "{name}" -Action {action} -EA SilentlyContinue',10); s._inv()
    def block_ip(s,ip,direction="Outbound"):
        name=f"{FW_PFX}Block_{ip.replace('.','_')}_{direction[:2]}"
        if not s.exists(name):
            s.create(name,direction,"Block",remote_addr=ip,desc=f"HostsGuard {datetime.datetime.now():%Y-%m-%d %H:%M}")
            return name
        return None
    def block_ip_both(s,ip):
        created=[]
        for d in ("Outbound","Inbound"):
            n=s.block_ip(ip,d)
            if n: created.append(n)
        return created
    def block_program(s,path,direction="Outbound"):
        sfx=f"_{direction[:2]}" if direction!="Outbound" else ""
        name=f"{FW_PFX}Block_{Path(path).stem}{sfx}"
        if not s.exists(name): s.create(name,direction,"Block",program=path,desc=f"HostsGuard {datetime.datetime.now():%Y-%m-%d %H:%M}"); return name
        return None
    def block_program_both(s,path):
        created=[]
        for d in ("Outbound","Inbound"):
            n=s.block_program(path,d)
            if n: created.append(n)
        return created
    def load_all(s):
        """Load all rules — designed to run in a background thread."""
        s._loading=True
        cmd=('Get-NetFirewallRule -EA SilentlyContinue|ForEach-Object{$af=$_|Get-NetFirewallAddressFilter -EA SilentlyContinue;$pf=$_|Get-NetFirewallPortFilter -EA SilentlyContinue;$ap=$_|Get-NetFirewallApplicationFilter -EA SilentlyContinue;'
            '[PSCustomObject]@{N=$_.DisplayName;Dir=[int]$_.Direction;Act=[int]$_.Action;En=[int]$_.Enabled;RA=$af.RemoteAddress;Proto=$pf.Protocol;Prog=$ap.Program}}|ConvertTo-Json -Compress')
        ok,out=_ps(cmd,120); rules=[]
        if ok and out:
            try:
                data=json.loads(out)
                if isinstance(data,dict): data=[data]
                def _j(v):
                    if v is None: return ""
                    if isinstance(v,list): return ",".join(str(x) for x in v)
                    return str(v)
                for r in data:
                    try:
                        n=_j(r.get('N',''))
                        rules.append(FWR(name=n,direction="In" if r.get('Dir') in (1,'1') else "Out",
                            action="Block" if r.get('Act') in (4,'4') else "Allow",
                            enabled=r.get('En') in (1,'1',True),remote_addr=_j(r.get('RA','')),
                            protocol=_j(r.get('Proto','Any')) or "Any",program=_j(r.get('Prog','')),
                            source="hostsguard" if n.startswith(FW_PFX) else "system"))
                    except: continue
            except Exception as e: log.warning(f"FW parse: {e}")
        with s._lock: s._cache=rules; s._ts=time.time()
        s._loading=False; return rules
    def get_all(s,force=False):
        with s._lock:
            if not force and s._cache and time.time()-s._ts<s._ttl: return list(s._cache)
        return s.load_all()
    def get_cached(s):
        with s._lock: return list(s._cache)
    def get_profiles(s):
        ok,out=_ps("Get-NetFirewallProfile|Select Name,Enabled|ConvertTo-Json -Compress",10)
        if ok and out:
            try:
                d=json.loads(out); 
                if isinstance(d,dict): d=[d]
                return {p['Name']:p['Enabled'] in (True,1,'1','True') for p in d}
            except: pass
        return {}
    def kill_conn(s,pid):
        try: psutil.Process(pid).kill(); return True
        except: return False
fw=FWEngine()

# ─── Hosts File Manager ────────────────────────────────────────────────────
class HostsMgr:
    def __init__(s):
        s._blocked=set(); s._lines=[]; s._lock=threading.RLock()  # RLock = reentrant, deadlock-proof
        s._suppress_watcher=False  # Flag to suppress HostsWatcher cascade during internal saves
        s.read()
    def read(s):
        with s._lock:
            try:
                with open(HOSTS_PATH,'r',encoding='utf-8',errors='replace') as f: s._lines=f.readlines()
                s._blocked=set()
                for l in s._lines:
                    n=norm_line(l,False)
                    if n: s._blocked.add(n)
            except Exception as e: log.warning(f"Hosts read: {e}"); s._lines=[]
    def get_blocked(s):
        with s._lock: return set(s._blocked)
    def get_lines(s):
        with s._lock: return list(s._lines)
    def block(s,d,flush=True):
        d=d.lower().strip()
        with s._lock:
            if d in s._blocked: return False
            try:
                with open(HOSTS_PATH,'a',encoding='utf-8') as f: f.write(f"0.0.0.0 {d}\n")
                s._blocked.add(d); s._lines.append(f"0.0.0.0 {d}\n")
            except Exception as e: log.warning(f"Hosts block {d}: {e}"); return False
        if flush: s._flush(); return True
    def block_bulk(s,domains,flush=True):
        new=[d.lower().strip() for d in domains if d.lower().strip() not in s._blocked and looks_like_domain(d.lower().strip())]
        if not new: return 0
        with s._lock:
            try:
                with open(HOSTS_PATH,'a',encoding='utf-8') as f:
                    for d in new: f.write(f"0.0.0.0 {d}\n"); s._blocked.add(d); s._lines.append(f"0.0.0.0 {d}\n")
            except Exception as e: log.warning(f"Hosts block_bulk: {e}"); return 0
        if flush: s._flush(); return len(new)
    def unblock(s,d,flush=True):
        d=d.lower().strip()
        with s._lock:
            new=[]
            for l in s._lines:
                line=l.strip()
                if not line or line.startswith('#'):
                    new.append(l); continue
                parts=line.split()
                if len(parts)>=2 and parts[1].lower().strip()==d:
                    continue
                new.append(l)
            try:
                with open(HOSTS_PATH,'w',encoding='utf-8') as f: f.writelines(new)
                s._blocked.discard(d); s._lines=new
            except Exception as e: log.warning(f"Hosts unblock {d}: {e}"); return False
        if flush: s._flush(); return True
    def save_raw(s,text):
        with s._lock:
            s._suppress_watcher=True
            try:
                with open(HOSTS_PATH,'w',encoding='utf-8') as f: f.write(text)
                # Re-parse in-memory (reentrant lock, so read() is safe here)
                s.read()
            except Exception as e: s._suppress_watcher=False; return str(e)
        s._flush(); return None
    def save_clean(s,wl=None):
        with s._lock:
            s._suppress_watcher=True
            try:
                cleaned,stats=clean_hosts(list(s._lines),wl)
                with open(HOSTS_PATH,'w',encoding='utf-8') as f: f.write('\n'.join(cleaned)+'\n')
                s.read()
            except Exception as e: s._suppress_watcher=False; return None,str(e)
        s._flush(); return stats,None
    def backup(s):
        ts=datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        dst=os.path.join(CONFIG_DIR,"backups",f"hosts_{ts}.bak")
        try: shutil.copy2(HOSTS_PATH,dst); return dst
        except: return None
    def restore(s,path=None):
        if not path:
            bk=sorted(Path(os.path.join(CONFIG_DIR,"backups")).glob("hosts_*.bak"))
            if not bk: return False
            path=str(bk[-1])
        with s._lock:
            s._suppress_watcher=True
            try:
                shutil.copy2(path,HOSTS_PATH)
                s.read()
            except: s._suppress_watcher=False; return False
        s._flush(); return True
    def _flush(s):
        if sys.platform=='win32': subprocess.Popen(['ipconfig','/flushdns'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=NOWIN)
    def emergency_unlock(s):
        with s._lock:
            s._suppress_watcher=True
            try:
                with open(HOSTS_PATH,'w',encoding='utf-8') as f: f.write('\n'.join(WINDOWS_HEADER)+'\n')
                s.read()
            except: s._suppress_watcher=False; return False
        s._flush(); return True

# ─── Bandwidth ──────────────────────────────────────────────────────────────
class BWTracker:
    def __init__(s): io=psutil.net_io_counters(); s._s,s._r,s._t=io.bytes_sent,io.bytes_recv,time.time(); s._us,s._ds=0,0
    def update(s):
        io=psutil.net_io_counters(); n=time.time(); dt=max(n-s._t,0.1)
        s._us=(io.bytes_sent-s._s)/dt; s._ds=(io.bytes_recv-s._r)/dt
        s._s,s._r,s._t=io.bytes_sent,io.bytes_recv,n
    def rates(s): return s._us,s._ds
    @staticmethod
    def fmt(r):
        if r<1024: return f"{r:.0f} B/s"
        if r<1048576: return f"{r/1024:.1f} KB/s"
        return f"{r/1048576:.1f} MB/s"
bw=BWTracker()

# ─── Workers ────────────────────────────────────────────────────────────────
class DNSResolveWorker(QThread):
    resolved=pyqtSignal(str,str)
    def __init__(s): super().__init__(); s._q=Queue(); s._stop=TEvent()
    def add(s,ip):
        if ip not in dns_c: s._q.put(ip)
    def run(s):
        while not s._stop.is_set():
            try:
                ip=s._q.get(timeout=1)
                if ip in dns_c: continue
                try: host=socket.gethostbyaddr(ip)[0]; dns_c.put(ip,host); s.resolved.emit(ip,host)
                except: dns_c.put(ip,'')
            except Empty: pass
    def stop(s): s._stop.set()

class GeoWorker(QThread):
    resolved=pyqtSignal(str,str,str)
    def __init__(s): super().__init__(); s._batch=[]; s._stop=TEvent(); s._lock=Lock()
    def add(s,ip):
        if ip not in geo_c:
            with s._lock:
                if ip not in s._batch: s._batch.append(ip)
    def run(s):
        while not s._stop.is_set():
            batch=[]
            with s._lock:
                if s._batch: batch,s._batch=s._batch[:100],s._batch[100:]
            if batch:
                try:
                    data=json.dumps([{"query":ip} for ip in batch]).encode()
                    req=urllib.request.Request("http://ip-api.com/batch?fields=query,country,countryCode",data=data,
                        headers={'Content-Type':'application/json','User-Agent':'HostsGuard/3.1'})
                    with urllib.request.urlopen(req,timeout=10) as resp:
                        for item in json.loads(resp.read()):
                            if item.get("countryCode"):
                                geo_c.put(item["query"],(item["countryCode"],item["country"]))
                                s.resolved.emit(item["query"],item["countryCode"],item["country"])
                except: pass
            s._stop.wait(2)
    def stop(s): s._stop.set()

class DNSMonitor(QThread):
    """Uses persistent PS session — no process spawn per scan."""
    dns_event=pyqtSignal(dict); blocked_event=pyqtSignal(dict)
    status=pyqtSignal(str); updated=pyqtSignal()
    CMD='Get-DnsClientCache -EA SilentlyContinue|Select Entry,RecordName|ConvertTo-Json -Compress'
    def __init__(s,hm,db):
        super().__init__(); s.hm,s.db=hm,db; s.running=False
        # Pre-populate _seen with hidden domains so they never resurface
        s._seen=s.db.get_hidden_set()
    def run(s):
        s.running=True; s.status.emit("Monitoring")
        if sys.platform!='win32': s.status.emit("Requires Windows"); return
        s._scan(); s.updated.emit()
        while s.running: s._scan(); time.sleep(3)
    def _scan(s):
        blocked=s.db.get_blocked_set()
        try:
            ok,out=_pps.run(s.CMD,12)
            if not ok or not out.strip(): return
            data=json.loads(out)
            if isinstance(data,dict): data=[data]
            ct=0
            for e in data:
                d=(e.get('Entry') or e.get('RecordName') or '').lower().strip().rstrip('.')
                if not d or d in IGNORED or '.' not in d: continue
                is_new=s.db.feed_upsert(d)
                if is_new: ct+=1
                if d not in s._seen:
                    s._seen.add(d)
                    if is_new:  # Only emit events for domains that were actually inserted as visible
                        ev={'domain':d,'ts':datetime.datetime.now().isoformat()}
                        s.dns_event.emit(ev)
                        if d in blocked:
                            s.db.log_event(d,'blocked','','Blocked by hosts')
                            s.blocked_event.emit(ev)
            if ct>0: s.updated.emit()
            if len(s._seen)>10000:
                hidden=s.db.get_hidden_set()  # Always preserve hidden
                trimmed=set(list(s._seen)[-2000:])
                s._seen=trimmed|hidden
        except Exception as e: log.debug(f"DNS scan: {e}")
    def manual_scan(s):
        if s.running: threading.Thread(target=s._scan,daemon=True).start()
    def stop(s): s.running=False

class ConnWorker(QThread):
    ready=pyqtSignal(list); need_dns=pyqtSignal(str); need_geo=pyqtSignal(str)
    def __init__(s,db): super().__init__(); s._stop=TEvent(); s._db=db
    def run(s):
        while not s._stop.is_set():
            try: conns=s._scan(); s.ready.emit(conns); bw.update()
            except Exception as e: log.debug(f"ConnWorker scan: {e}")
            s._stop.wait(2.0)
    def _scan(s):
        out=[]; now=datetime.datetime.now().strftime("%H:%M:%S")
        blocked=s._db.get_blocked_set()
        for c in psutil.net_connections(kind='all'):
            try:
                proto="TCP" if c.type==socket.SOCK_STREAM else "UDP"
                la=c.laddr.ip if c.laddr else ""; lp=str(c.laddr.port) if c.laddr else ""
                ra=c.raddr.ip if c.raddr else ""; rp=str(c.raddr.port) if c.raddr else ""
                if not ra or ra in ('','*','0.0.0.0','::','::1'): continue
                if PRIV_RE.match(ra): continue
                pname="?"; pid=c.pid or 0; ppath=""
                if pid:
                    cached=proc_c.get(pid)
                    if cached: pname,ppath=cached
                    else:
                        try:
                            p=psutil.Process(pid); pname=p.name(); ppath=p.exe()
                            proc_c.put(pid,(pname,ppath))
                        except: pass
                host=dns_c.get(ra) or "-"
                stat="-"
                if host!="-" and host in blocked: stat="BLOCKED"
                elif ra in blocked: stat="BLOCKED"
                state=c.status if hasattr(c,'status') else ""
                cat=categorize(host,rp); geo=geo_c.get(ra)
                country=geo[1] if geo else "-"; cc=geo[0] if geo else ""
                ci=CI(key=f"{proto}:{la}:{lp}-{ra}:{rp}",ts=now,dir="Out" if c.status!="LISTEN" else "Listen",
                    proto=proto,la=la,lp=lp,ra=ra,rp=rp,host=host,proc=pname,pid=pid,state=state,
                    path=ppath,stat=stat,country=country,cc=cc,category=cat)
                out.append(ci)
                if host=="-": s.need_dns.emit(ra)
                if not geo: s.need_geo.emit(ra)
            except: continue
        return out
    def stop(s): s._stop.set()

class RuleScanWorker(QThread):
    ready=pyqtSignal(list)
    def __init__(s,force=False): super().__init__(); s.force=force
    def run(s):
        try:
            if s.force or not fw.cached: rules=fw.load_all()
            else: rules=fw.get_cached()
            s.ready.emit(rules)
        except: s.ready.emit([])

class HostsWatcher(QThread):
    changed=pyqtSignal()
    def __init__(s): super().__init__(); s._stop=TEvent(); s._mtime=0
    def run(s):
        try: s._mtime=os.path.getmtime(HOSTS_PATH)
        except: pass
        while not s._stop.is_set():
            try:
                mt=os.path.getmtime(HOSTS_PATH)
                if mt!=s._mtime: s._mtime=mt; s.changed.emit()
            except: pass
            s._stop.wait(3)
    def stop(s): s._stop.set()

# ─── Startup Loader (parallel) ──────────────────────────────────────────────
class StartupLoader(QThread):
    """Fast startup: DB + Hosts + ConnDB only. FW loads post-UI via FWLoadWorker.
    DNS cache is NOT pre-loaded — DNSMonitor picks it up within 3s naturally.
    PersistentPS is warmed up in background so DNSMonitor's first scan is fast."""
    progress=pyqtSignal(str,int)
    finished=pyqtSignal(object)
    def __init__(s): super().__init__()
    def run(s):
        results={'db':None,'hm':None,'cdb':None}
        s.progress.emit("Database",15)
        results['db']=DB()
        s.progress.emit("Hosts file",40)
        results['hm']=HostsMgr()
        s.progress.emit("Connection history",65)
        results['cdb']=ConnDB()
        s.progress.emit("Warming up",85)
        # Warm persistent PS session so first DNSMonitor scan is fast
        _pps.run("$null",3)
        s.progress.emit("Ready",100)
        s.finished.emit(results)

class FWLoadWorker(QThread):
    """Loads firewall rules in background AFTER UI is visible.
    Uses dedicated subprocess (not PPS) so it never blocks the persistent session."""
    ready=pyqtSignal(list)
    def run(s):
        cmd=('Get-NetFirewallRule -EA SilentlyContinue|ForEach-Object{$af=$_|Get-NetFirewallAddressFilter -EA SilentlyContinue;$pf=$_|Get-NetFirewallPortFilter -EA SilentlyContinue;$ap=$_|Get-NetFirewallApplicationFilter -EA SilentlyContinue;'
            '[PSCustomObject]@{N=$_.DisplayName;Dir=[int]$_.Direction;Act=[int]$_.Action;En=[int]$_.Enabled;RA=$af.RemoteAddress;Proto=$pf.Protocol;Prog=$ap.Program}}|ConvertTo-Json -Compress')
        rules=[]
        try:
            r=subprocess.run(['powershell','-NoProfile','-Command',cmd],capture_output=True,text=True,timeout=120,creationflags=NOWIN)
            if r.returncode==0 and r.stdout.strip():
                data=json.loads(r.stdout)
                if isinstance(data,dict): data=[data]
                def _j(v):
                    if v is None: return ""
                    if isinstance(v,list): return ",".join(str(x) for x in v)
                    return str(v)
                for rec in data:
                    try:
                        n=_j(rec.get('N',''))
                        rules.append(FWR(name=n,direction="In" if rec.get('Dir') in (1,'1') else "Out",
                            action="Block" if rec.get('Act') in (4,'4') else "Allow",
                            enabled=rec.get('En') in (1,'1',True),remote_addr=_j(rec.get('RA','')),
                            protocol=_j(rec.get('Proto','Any')) or "Any",program=_j(rec.get('Prog','')),
                            source="hostsguard" if n.startswith(FW_PFX) else "system"))
                    except: continue
        except: pass
        # Update FW engine cache
        with fw._lock: fw._cache=rules; fw._ts=time.time()
        fw._loading=False
        # Track existing HG rules in DB (if DB wired)
        if fw._db:
            for r in rules:
                if r.source=="hostsguard":
                    fw._db.save_fw_rule(r.name,r.direction,r.action,r.remote_addr,r.protocol,r.program)
        s.ready.emit(rules)


# ─── Splash Screen ──────────────────────────────────────────────────────────
class Splash(QWidget):
    def __init__(s):
        super().__init__(); s.setWindowFlags(Qt.FramelessWindowHint|Qt.WindowStaysOnTopHint)
        s.setAttribute(Qt.WA_TranslucentBackground)
        s.setFixedSize(380,200)
        # Center on screen
        scr=QApplication.primaryScreen()
        if scr: g=scr.availableGeometry(); s.move(g.center()-s.rect().center())
    def paintEvent(s,e):
        p=QPainter(s); p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(QColor(C['base'])); p.setPen(QPen(QColor(C['s1']),1))
        p.drawRoundedRect(s.rect().adjusted(1,1,-1,-1),16,16); p.end()
    def setup(s):
        lo=QVBoxLayout(s); lo.setContentsMargins(30,24,30,20); lo.setSpacing(10)
        t=QLabel(f"\u25C6  {APP}"); t.setFont(QFont("Segoe UI Variable Display",18,QFont.Bold))
        t.setStyleSheet(f"color:{C['blue']};"); t.setAlignment(Qt.AlignCenter); lo.addWidget(t)
        s._step=QLabel("Initializing..."); s._step.setAlignment(Qt.AlignCenter)
        s._step.setStyleSheet(f"color:{C['sub']};font-size:11px;font-weight:600;"); lo.addWidget(s._step)
        s._bar=QProgressBar(); s._bar.setRange(0,100); s._bar.setValue(0); s._bar.setFixedHeight(6)
        s._bar.setTextVisible(False)
        s._bar.setStyleSheet(f"QProgressBar{{background:{C['s0']};border:none;border-radius:3px;}}QProgressBar::chunk{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #5b7ee5,stop:1 {C['teal']});border-radius:3px;}}")
        lo.addWidget(s._bar); lo.addStretch()
        v=QLabel(f"v{VER}"); v.setAlignment(Qt.AlignCenter); v.setStyleSheet(f"color:{C['dim']};font-size:9px;"); lo.addWidget(v)
    def update_progress(s,step,pct): s._step.setText(step); s._bar.setValue(pct)

# ─── Loading Overlay ────────────────────────────────────────────────────────
class LoadingOverlay(QWidget):
    """Semi-transparent overlay with spinner text. Attach to any widget."""
    def __init__(s,parent):
        super().__init__(parent); s.setVisible(False)
        s.setAttribute(Qt.WA_TransparentForMouseEvents,False)
        s._label=QLabel("Loading...",s); s._label.setAlignment(Qt.AlignCenter)
        s._label.setStyleSheet(f"color:{C['blue']};font-size:13px;font-weight:700;background:transparent;")
        s._dots=0; s._tmr=QTimer(s); s._tmr.timeout.connect(s._anim); s._tmr.setInterval(400)
    def show_loading(s,text="Loading"):
        s._text=text; s._dots=0; s.setVisible(True); s.raise_(); s._tmr.start(); s._update_geom()
    def hide_loading(s): s.setVisible(False); s._tmr.stop()
    def _anim(s): s._dots=(s._dots+1)%4; s._label.setText(f"{s._text}{'.'*s._dots}")
    def _update_geom(s):
        if s.parent(): s.setGeometry(s.parent().rect()); s._label.setGeometry(s.rect())
    def resizeEvent(s,e): super().resizeEvent(e); s._update_geom()
    def paintEvent(s,e):
        p=QPainter(s); p.fillRect(s.rect(),QColor(15,15,23,180)); p.end()

# ─── Learning Mode ──────────────────────────────────────────────────────────
class LearnDB:
    def __init__(s,db):
        s.db=db; s._trusted=set(); s._untrusted=set(); s._prompted=set(); s._enabled=False; s._load()
    def _load(s):
        cfg=load_cfg(); s._enabled=cfg.get('learning_mode',False)
        s._trusted=set(cfg.get('trusted_procs',[])); s._untrusted=set(cfg.get('untrusted_procs',[]))
    def save(s):
        cfg=load_cfg(); cfg['learning_mode']=s._enabled
        cfg['trusted_procs']=list(s._trusted); cfg['untrusted_procs']=list(s._untrusted); save_cfg(cfg)
    @property
    def enabled(s): return s._enabled
    def set_enabled(s,v): s._enabled=v; s.save()
    def is_trusted(s,proc): return proc.lower() in s._trusted
    def is_untrusted(s,proc): return proc.lower() in s._untrusted
    def trust(s,proc): s._trusted.add(proc.lower()); s._untrusted.discard(proc.lower()); s.save()
    def untrust(s,proc): s._untrusted.add(proc.lower()); s._trusted.discard(proc.lower()); s.save()
    def reset(s,proc): s._trusted.discard(proc.lower()); s._untrusted.discard(proc.lower()); s.save()
    def was_prompted(s,key): return key in s._prompted
    def mark_prompted(s,key): s._prompted.add(key)
    def clear_prompted(s): s._prompted.clear()

# ─── Toast ──────────────────────────────────────────────────────────────────
class Toast(QFrame):
    def __init__(s,text,color=C['blue'],parent=None):
        super().__init__(parent)
        s.setFixedHeight(_dp(34)); s.setMinimumWidth(_dp(220)); s.setMaximumWidth(_dp(420))
        s.setStyleSheet(f"QFrame{{background:{C['s0']};border:1px solid {color};border-radius:{_dp(8)}px;border-left:3px solid {color};}}")
        lo=QHBoxLayout(s); lo.setContentsMargins(_dp(12),0,_dp(12),0)
        lbl=QLabel(text); lbl.setStyleSheet(f"color:{C['text']};font-size:{_dp(11)}px;font-weight:600;"); lo.addWidget(lbl)
        s.setAttribute(Qt.WA_DeleteOnClose)
    def showEvent(s,e): super().showEvent(e); QTimer.singleShot(2500,s.close)

class ToastMgr:
    def __init__(s,parent): s._p=parent; s._q=[]
    def toast(s,text,color=C['blue']):
        t=Toast(text,color,s._p); s._q.append(t)
        t.destroyed.connect(lambda:s._rm(t)); s._place(); t.show()
    def _rm(s,t):
        if t in s._q: s._q.remove(t); s._place()
    def _place(s):
        p=s._p; y=p.height()-_dp(50)
        for t in reversed(s._q): t.move(p.width()-t.width()-_dp(16),y); y-=t.height()-_dp(4)

# ─── UI Helpers ─────────────────────────────────────────────────────────────
def _icon_item(tbl,r,c,text,domain=None):
    it=QTableWidgetItem(text)
    if domain and _fav:
        px=_fav.get(domain)
        if px and not px.isNull(): it.setIcon(QIcon(px))
    tbl.setItem(r,c,it)

def _btn(text,cls="dim",cb=None,tip=None):
    b=QPushButton(text); b.setProperty("class",cls); b.setCursor(Qt.PointingHandCursor)
    b.setFixedHeight(_dp(26)); b.setMinimumWidth(_dp(16))
    b.setSizePolicy(QSizePolicy.Preferred,QSizePolicy.Fixed)
    b.setStyleSheet(b.styleSheet()+f"font-size:{_dp(11)}px;padding:0 {_dp(8)}px;")
    if cb: b.clicked.connect(cb)
    if tip: b.setToolTip(tip)
    return b

def _tbtn(text,cls="dim",cb=None,w=None):
    b=QPushButton(text); b.setProperty("class",cls); b.setCursor(Qt.PointingHandCursor)
    b.setFixedHeight(_dp(30))
    if w: b.setFixedWidth(_dp(w))
    if cb: b.clicked.connect(cb)
    return b

def _pill(text,color):
    l=QLabel(text); l.setAlignment(Qt.AlignCenter)
    l.setStyleSheet(f"background:rgba({','.join(str(int(color.lstrip('#')[i:i+2],16)) for i in (0,2,4))},0.15);color:{color};font-size:{_dp(9)}px;font-weight:700;border-radius:{_dp(10)}px;padding:{_dp(2)}px {_dp(8)}px;letter-spacing:0.3px;")
    return l

def _stat(label,value="0",color=C['blue'],icon=""):
    f=QFrame(); f.setStyleSheet(f"QFrame{{background:rgba(24,24,36,0.85);border:1px solid rgba(51,51,85,0.4);border-radius:{_dp(12)}px;}}")
    f.setMinimumWidth(_dp(130)); f.setMinimumHeight(_dp(72)); f.setMaximumHeight(_dp(84))
    f.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Fixed)
    lo=QVBoxLayout(f); lo.setContentsMargins(_dp(14),_dp(8),_dp(14),_dp(8)); lo.setSpacing(_dp(1))
    top=QHBoxLayout(); top.setSpacing(_dp(4))
    v=QLabel(str(value)); v.setObjectName("val")
    v.setStyleSheet(f"font-size:{_dp(24)}px;font-weight:800;color:{color};letter-spacing:-0.5px;font-family:'Segoe UI Variable Display','Segoe UI',sans-serif;")
    top.addWidget(v); top.addStretch()
    if icon: ic=QLabel(icon); ic.setStyleSheet(f"font-size:{_dp(14)}px;color:{color};"); top.addWidget(ic)
    lo.addLayout(top)
    ll=QLabel(label.upper()); ll.setStyleSheet(f"font-size:{_dp(8)}px;color:{C['dim']};letter-spacing:1.2px;font-weight:700;")
    lo.addWidget(ll); return f

def _sv(card,v): card.findChild(QLabel,"val").setText(str(v))

def _tbl(cols,stretch=0,row_h=32):
    t=QTableWidget(0,len(cols)); t.setHorizontalHeaderLabels(cols)
    t.horizontalHeader().setSectionResizeMode(stretch,QHeaderView.Stretch)
    t.setAlternatingRowColors(True); t.setEditTriggers(QTableWidget.NoEditTriggers)
    t.verticalHeader().setVisible(False); t.setShowGrid(False)
    t.setSelectionBehavior(QTableWidget.SelectRows); t.setSelectionMode(QTableWidget.ExtendedSelection)
    t.setIconSize(QSize(_dp(16),_dp(16))); t.verticalHeader().setDefaultSectionSize(_dp(row_h))
    t.setSortingEnabled(True); t.setContextMenuPolicy(Qt.CustomContextMenu)
    return t

# ─── Connection Detail Dialog ───────────────────────────────────────────────
class ConnDetailDlg(QDialog):
    def __init__(s,ci,db,hm,learn,parent=None):
        super().__init__(parent); s.ci=ci; s.db=db; s.hm=hm; s.learn=learn; s.result_action=None
        s.setWindowTitle(f"Connection: {ci.proc} \u2192 {ci.host if ci.host not in ('-','') else ci.ra}")
        s.setFixedWidth(_dp(520)); s.setStyleSheet(f"QDialog{{background:{C['base']};}}")
        lo=QVBoxLayout(s); lo.setSpacing(_dp(10)); lo.setContentsMargins(_dp(20),_dp(14),_dp(20),_dp(14))
        hdr=QLabel(ci.proc); hdr.setStyleSheet(f"font-size:{_dp(16)}px;font-weight:800;color:{C['text']};"); lo.addWidget(hdr)
        if ci.path: pl=QLabel(ci.path); pl.setStyleSheet(f"color:{C['dim']};font-size:{_dp(9)}px;"); pl.setWordWrap(True); lo.addWidget(pl)
        grid=QFrame(); grid.setStyleSheet(f"QFrame{{background:{C['mantle']};border:1px solid {C['s0']};border-radius:{_dp(10)}px;}}")
        gl=QGridLayout(grid); gl.setContentsMargins(_dp(12),_dp(8),_dp(12),_dp(8)); gl.setSpacing(_dp(5))
        gl.setColumnStretch(1,1); gl.setColumnStretch(3,1)
        fields=[("Remote IP",ci.ra,0,0),("Port",f"{ci.rp} ({PORTS.get(int(ci.rp),'')})".rstrip('() ') if ci.rp.isdigit() else ci.rp,0,2),
            ("Hostname",ci.host if ci.host not in ('-','') else "(unresolved)",1,0),("Protocol",ci.proto,1,2),
            ("Direction",ci.dir,2,0),("State",ci.state,2,2),("Country",ci.country,3,0),("Category",ci.category or "Unknown",3,2)]
        for label,val,row,col in fields:
            ll=QLabel(label); ll.setStyleSheet(f"color:{C['dim']};font-size:{_dp(8)}px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;")
            vl=QLabel(str(val)); vl.setStyleSheet(f"color:{C['text']};font-size:{_dp(11)}px;font-weight:600;"); vl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            gl.addWidget(ll,row,col); gl.addWidget(vl,row,col+1)
        lo.addWidget(grid)
        # Action groups
        host_d=ci.host if ci.host not in ('-','','...') else None
        hg=QGroupBox("Hosts File"); hl=QHBoxLayout(hg); hl.setSpacing(_dp(5))
        if host_d:
            hl.addWidget(_btn(f"Block {host_d}","danger",lambda:s._do('hosts_block',host_d)))
            root=get_root(host_d)
            if root!=host_d: hl.addWidget(_btn(f"Block root ({root})","danger",lambda:s._do('hosts_block_root',host_d)))
            hl.addWidget(_btn(f"Allow","success",lambda:s._do('hosts_allow',host_d)))
        else: hl.addWidget(QLabel("No hostname resolved"))
        hl.addStretch(); lo.addWidget(hg)
        fg=QGroupBox("Firewall"); fl=QHBoxLayout(fg); fl.setSpacing(_dp(5))
        fl.addWidget(_btn(f"Block IP Out","danger",lambda:s._do('fw_block_ip',ci.ra)))
        fl.addWidget(_btn(f"Block IP In+Out","danger",lambda:s._do('fw_block_ip_both',ci.ra)))
        if ci.path:
            fl.addWidget(_btn(f"Block Program Out","danger",lambda:s._do('fw_block_prog',ci.path)))
            fl.addWidget(_btn(f"Block Program In+Out","danger",lambda:s._do('fw_block_prog_both',ci.path)))
        if ci.pid>0: fl.addWidget(_btn(f"Kill PID {ci.pid}","danger",lambda:s._do('kill',str(ci.pid))))
        fl.addStretch(); lo.addWidget(fg)
        lg=QGroupBox("Learning"); ll2=QHBoxLayout(lg); ll2.setSpacing(_dp(5))
        ll2.addWidget(_btn("Trust","success",lambda:s._do('trust',ci.proc)))
        ll2.addWidget(_btn("Untrust","danger",lambda:s._do('untrust',ci.proc)))
        ll2.addWidget(_btn("Reset","dim",lambda:s._do('reset_trust',ci.proc)))
        ll2.addStretch(); lo.addWidget(lg)
        br=QHBoxLayout(); br.addWidget(_btn("Research \u2192","dim",lambda:open_research(host_d or ci.ra)))
        br.addWidget(_btn("Copy IP","dim",lambda:QApplication.clipboard().setText(ci.ra)))
        br.addStretch(); br.addWidget(_btn("Close","dim",lambda:s.reject())); lo.addLayout(br)
    def _do(s,a,t): s.result_action=(a,t); s.accept()

class NewRuleDlg(QDialog):
    def __init__(s,parent=None,prefill=None):
        super().__init__(parent); s.setWindowTitle("New Firewall Rule"); s.setFixedWidth(_dp(440))
        s.setStyleSheet(f"QDialog{{background:{C['base']};}}")
        lo=QVBoxLayout(s); lo.setSpacing(_dp(8)); lo.setContentsMargins(_dp(20),_dp(14),_dp(20),_dp(14))
        pf=prefill or {}
        def _r(l,w): lo.addWidget(QLabel(l)); lo.addWidget(w)
        s.name=QLineEdit(pf.get('name',FW_PFX)); _r("Name",s.name)
        s.dir_c=QComboBox(); s.dir_c.addItems(["Outbound","Inbound"])
        if pf.get('dir'): s.dir_c.setCurrentText(pf['dir'])
        _r("Direction",s.dir_c)
        s.act_c=QComboBox(); s.act_c.addItems(["Block","Allow"])
        if pf.get('action'): s.act_c.setCurrentText(pf['action'])
        _r("Action",s.act_c)
        s.proto_c=QComboBox(); s.proto_c.addItems(["Any","TCP","UDP","ICMPv4"])
        if pf.get('proto') and pf['proto'] not in ('Any',''): s.proto_c.setCurrentText(pf['proto'])
        _r("Protocol",s.proto_c)
        s.addr=QLineEdit(pf.get('addr','')); s.addr.setPlaceholderText("IP / range / subnet (empty=any)"); _r("Remote Address",s.addr)
        pr=QHBoxLayout(); s.prog=QLineEdit(pf.get('prog',''))
        s.prog.setPlaceholderText("Path to .exe (optional)"); pr.addWidget(s.prog,1)
        pr.addWidget(_btn("\u2026","dim",s._browse)); lo.addWidget(QLabel("Program")); lo.addLayout(pr)
        lo.addSpacing(_dp(6))
        br=QHBoxLayout(); br.addStretch()
        br.addWidget(_btn("Cancel","dim",lambda:s.reject())); br.addWidget(_btn("Create","primary",lambda:s.accept())); lo.addLayout(br)
    def _browse(s):
        p,_=QFileDialog.getOpenFileName(s,"Select Program","","Executables (*.exe);;All (*)"); 
        if p: s.prog.setText(p)
    def data(s):
        n=s.name.text().strip()
        if not n.startswith(FW_PFX): n=FW_PFX+n
        return {'name':n,'dir':s.dir_c.currentText(),'action':s.act_c.currentText(),
            'proto':s.proto_c.currentText(),'addr':s.addr.text().strip(),'prog':s.prog.text().strip()}

class LearnPopup(QDialog):
    def __init__(s,ci,parent=None):
        super().__init__(parent); s.ci=ci; s.result_action=None
        s.setWindowFlags(Qt.Tool|Qt.WindowStaysOnTopHint|Qt.FramelessWindowHint)
        s.setAttribute(Qt.WA_DeleteOnClose); s.setFixedWidth(_dp(360))
        s.setStyleSheet(f"QDialog{{background:{C['base']};border:1px solid {C['s1']};border-radius:{_dp(12)}px;}}")
        lo=QVBoxLayout(s); lo.setContentsMargins(_dp(16),_dp(10),_dp(16),_dp(10)); lo.setSpacing(_dp(6))
        hl=QHBoxLayout()
        tag=QLabel("NEW CONNECTION"); tag.setStyleSheet(f"color:{C['peach']};font-size:{_dp(9)}px;font-weight:800;letter-spacing:1px;")
        hl.addWidget(tag); hl.addStretch()
        x=QPushButton("\u2715"); x.setFixedSize(_dp(20),_dp(20)); x.setCursor(Qt.PointingHandCursor)
        x.setStyleSheet(f"background:transparent;color:{C['dim']};border:none;font-size:{_dp(12)}px;")
        x.clicked.connect(s.close); hl.addWidget(x); lo.addLayout(hl)
        pl=QLabel(ci.proc); pl.setStyleSheet(f"font-size:{_dp(14)}px;font-weight:700;color:{C['text']};"); lo.addWidget(pl)
        dest=ci.host if ci.host not in ('-','','...') else ci.ra
        port_s=PORTS.get(int(ci.rp),ci.rp) if ci.rp.isdigit() else ci.rp
        dl=QLabel(f"\u2192 {dest}:{port_s}"); dl.setStyleSheet(f"color:{C['sub']};font-size:{_dp(11)}px;"); lo.addWidget(dl)
        br=QHBoxLayout(); br.setSpacing(_dp(5))
        br.addWidget(_btn("Allow","success",lambda:s._a('trust'))); br.addWidget(_btn("Block","danger",lambda:s._a('untrust')))
        br.addWidget(_btn("Details","dim",lambda:s._a('details'))); br.addWidget(_btn("Ignore","dim",lambda:s.close()))
        lo.addLayout(br)
        QTimer.singleShot(0,s._pos)
    def _pos(s):
        scr=QApplication.primaryScreen()
        if scr: g=scr.availableGeometry(); s.move(g.right()-s.width()-_dp(16),g.bottom()-s.height()-_dp(16))
    def _a(s,a): s.result_action=a; s.accept()

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 1A: HOSTS ACTIVITY — DNS monitoring, hosts blocking
# ═════════════════════════════════════════════════════════════════════════════
class HostsActivityTab(QWidget):
    def __init__(s,db,hm,learn):
        super().__init__(); s.db=db; s.hm=hm; s.learn=learn
        s._monitor=None; s._last_hash=0; s._first_load=True; s._build()
        s._tmr=QTimer(s); s._tmr.timeout.connect(s._auto_refresh); s._tmr.start(4000)
    def _build(s):
        lo=QVBoxLayout(s); lo.setContentsMargins(_dp(16),_dp(12),_dp(16),_dp(8)); lo.setSpacing(_dp(8))
        sr=QHBoxLayout(); sr.setSpacing(_dp(8))
        s.c_seen=_stat("Seen","0",C['blue'],"\u25C9"); s.c_blocked=_stat("Blocked","0",C['red'],"\u2718")
        s.c_wl=_stat("Allowed","0",C['green'],"\u2714"); s.c_hidden=_stat("Hidden","0",C['dim'],"\u25CC")
        for c in [s.c_seen,s.c_blocked,s.c_wl,s.c_hidden]: sr.addWidget(c)
        lo.addLayout(sr)
        tb=QHBoxLayout(); tb.setSpacing(_dp(5))
        s.search=QLineEdit(); s.search.setPlaceholderText("Search domains..."); s.search.setFixedHeight(_dp(30))
        s.search.textChanged.connect(s._on_search); tb.addWidget(s.search,1)
        s.filt=QComboBox(); s.filt.addItems(["All","Blocked","Allowed","Unmanaged","Hidden"])
        s.filt.currentIndexChanged.connect(s._on_search); tb.addWidget(s.filt)
        tb.addWidget(_tbtn("Scan","primary",s._scan,55)); lo.addLayout(tb)
        s.tbl=_tbl(["Domain","Status","Process","Hits","Last Seen"],0,row_h=30)
        s.tbl.setColumnWidth(1,_dp(90)); s.tbl.setColumnWidth(2,_dp(130)); s.tbl.setColumnWidth(3,_dp(50)); s.tbl.setColumnWidth(4,_dp(140))
        s.tbl.customContextMenuRequested.connect(s._ctx); s.tbl.doubleClicked.connect(s._dbl)
        lo.addWidget(s.tbl,1)
        s._overlay=LoadingOverlay(s.tbl)
        ib=QHBoxLayout()
        s.info=QLabel(""); s.info.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); ib.addWidget(s.info)
        ib.addStretch(); lo.addLayout(ib)
    def showEvent(s,e):
        super().showEvent(e)
        if s._first_load: s._overlay.show_loading("Loading activity"); s._first_load=False
    def set_monitor(s,mon): s._monitor=mon
    def _on_search(s): s._last_hash=0; s._refresh()
    def _scan(s):
        if s._monitor: s._monitor.manual_scan()
    def _auto_refresh(s): s._refresh()
    def _refresh(s):
        s._load_feed(); s._upd_stats()
    def _upd_stats(s):
        st=s.db.get_stats()
        _sv(s.c_seen,st['feed_total']); _sv(s.c_blocked,st['blocked']); _sv(s.c_wl,st['whitelisted'])
        _sv(s.c_hidden,s.db.feed_count(hidden=True))
    def _sel_domain(s):
        cur=s.tbl.currentRow()
        if cur>=0:
            it=s.tbl.item(cur,0)
            if it: return it.text()
        return None
    def _restore_sel(s,domain):
        if not domain: return
        for r in range(s.tbl.rowCount()):
            it=s.tbl.item(r,0)
            if it and it.text()==domain: s.tbl.setCurrentCell(r,0); return
    def _load_feed(s):
        q=s.search.text().strip() or None; f=s.filt.currentText()
        show_hidden=f=="Hidden"
        sf={'Blocked':'blocked','Allowed':'whitelisted','Unmanaged':'unmanaged'}.get(f,None)
        rows=s.db.feed_get(search=q,show_hidden=show_hidden,status_filter=sf)
        h=hash(tuple((m[0],m[3],m[6]) for m in rows[:300]))
        if h==s._last_hash: s._overlay.hide_loading(); return
        s._last_hash=h
        saved=s._sel_domain()
        s.tbl.setSortingEnabled(False); s.tbl.setRowCount(len(rows))
        for i,(domain,fs,ls,hits,proc,hidden,status) in enumerate(rows):
            _icon_item(s.tbl,i,0,domain,domain)
            hc={'blocked':C['red'],'whitelisted':C['green']}.get(status,C['dim'])
            ht={'blocked':'BLOCKED','whitelisted':'ALLOWED'}.get(status,'\u2014')
            s.tbl.setCellWidget(i,1,_pill(ht,hc))
            s.tbl.setItem(i,2,QTableWidgetItem(proc or ""))
            s.tbl.setItem(i,3,QTableWidgetItem(str(hits)))
            s.tbl.setItem(i,4,QTableWidgetItem((ls or "")[:19]))
            if status=='blocked':
                for col in [0,2,3,4]:
                    it=s.tbl.item(i,col)
                    if it: it.setBackground(QColor(247,118,142,10))
        s.tbl.setSortingEnabled(True); s._restore_sel(saved)
        hidden_ct=s.db.feed_count(hidden=True)
        s.info.setText(f"{len(rows)} domains \u00B7 {hidden_ct} hidden")
        s._overlay.hide_loading()
    def _ctx(s,pos):
        sel=s.tbl.selectionModel().selectedRows()
        if not sel: return
        domains=[s.tbl.item(r.row(),0).text() for r in sel if s.tbl.item(r.row(),0)]
        if not domains: return
        d=domains[0]; root=get_root(d); multi=len(domains)>1; f=s.filt.currentText()
        m=QMenu(s); m.setStyleSheet(CTX)
        if multi:
            hm=m.addMenu("Hosts File"); hm.setStyleSheet(CTX)
            hm.addAction(f"Block {len(domains)} domains").triggered.connect(lambda:[s._act_block(x) for x in domains])
            hm.addAction(f"Allow {len(domains)} domains").triggered.connect(lambda:[s._act_allow(x) for x in domains])
            m.addAction(f"Hide {len(domains)} domains").triggered.connect(lambda:[s._act_hide(x) for x in domains])
        else:
            hm=m.addMenu("Hosts File"); hm.setStyleSheet(CTX)
            hm.addAction(f"Block {d}").triggered.connect(lambda:s._act_block(d))
            hm.addAction(f"Block root ({root})").triggered.connect(lambda:s._act_block_root(d))
            hm.addSeparator()
            hm.addAction(f"Allow {d}").triggered.connect(lambda:s._act_allow(d))
            hm.addAction(f"Allow root ({root})").triggered.connect(lambda:s._act_allow_root(d))
            m.addSeparator()
            if f=="Hidden":
                m.addAction("Unhide").triggered.connect(lambda:(s.db.feed_unhide(d),setattr(s,'_last_hash',0),s._refresh()))
                m.addAction(f"Unhide root ({root})").triggered.connect(lambda:(s.db.feed_unhide_root(d),setattr(s,'_last_hash',0),s._refresh(),s._toast(f"Unhid *{root}",C['green'])))
            else:
                m.addAction("Hide").triggered.connect(lambda:s._act_hide(d))
                m.addAction(f"Hide root ({root})").triggered.connect(lambda:s._act_hide_root(d))
            m.addSeparator()
            m.addAction("Research \u2192").triggered.connect(lambda:open_research(d))
            m.addAction("Copy").triggered.connect(lambda:QApplication.clipboard().setText(d))
        m.exec_(s.tbl.viewport().mapToGlobal(pos))
    def _dbl(s,idx):
        it=s.tbl.item(idx.row(),0)
        if it: open_research(it.text())
    # Actions
    def _act_block(s,d):
        s.db.add_domain(d,'blocked','manual'); s.hm.block(d); s.db.log_event(d,'blocked','','Hosts block')
        s._last_hash=0; s._refresh(); s._toast(f"Blocked {d}",C['red'])
    def _act_block_root(s,d):
        root=get_root(d); s.db.add_root(d,'blocked','manual'); s.hm.block(root); s.db.log_event(root,'blocked','','Hosts block root')
        s._last_hash=0; s._refresh(); s._toast(f"Blocked {root}",C['red'])
    def _act_allow(s,d):
        s.db.add_domain(d,'whitelisted','manual'); s.hm.unblock(d); s.db.log_event(d,'whitelisted','','Allowed')
        s._last_hash=0; s._refresh(); s._toast(f"Allowed {d}",C['green'])
    def _act_allow_root(s,d):
        root=get_root(d); s.db.add_root(d,'whitelisted','manual'); s.hm.unblock(root)
        s._last_hash=0; s._refresh(); s._toast(f"Allowed {root}",C['green'])
    def _act_hide(s,d):
        s.db.feed_hide(d)
        w=s.window()
        if hasattr(w,'_dns_mon') and w._dns_mon: w._dns_mon._seen.add(d.lower())
        s.tbl.setRowCount(0); s._last_hash=0; s._refresh(); s._toast(f"Hidden {d}",C['dim'])
    def _act_hide_root(s,d):
        s.db.feed_hide_root(d); root=get_root(d)
        w=s.window()
        if hasattr(w,'_dns_mon') and w._dns_mon:
            for dom in s.db.get_hidden_set(): w._dns_mon._seen.add(dom)
        s.tbl.setRowCount(0); s._last_hash=0; s._refresh(); s._toast(f"Hidden *{root}",C['dim'])
    def resizeEvent(s,e): super().resizeEvent(e); s._overlay._update_geom()
    def _toast(s,msg,color):
        w=s.window()
        if hasattr(w,'_toasts'): w._toasts.toast(msg,color)

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 1B: FW ACTIVITY — Live connections, firewall monitoring
# ═════════════════════════════════════════════════════════════════════════════
class FWActivityTab(QWidget):
    def __init__(s,db,hm,cdb,learn):
        super().__init__(); s.db=db; s.hm=hm; s.cdb=cdb; s.learn=learn
        s._conns=[]; s._conn_map={}; s._fw_blocked_ips=set()
        s._last_hash=0; s._first_load=True; s._build()
        s._tmr=QTimer(s); s._tmr.timeout.connect(s._auto_refresh); s._tmr.start(3000)
    def _build(s):
        lo=QVBoxLayout(s); lo.setContentsMargins(_dp(16),_dp(12),_dp(16),_dp(8)); lo.setSpacing(_dp(8))
        sr=QHBoxLayout(); sr.setSpacing(_dp(8))
        s.c_live=_stat("Connections","0",C['sky'],"\u21C4"); s.c_fw=_stat("FW Rules","0",C['mauve'],"\u229B")
        s.c_fwb=_stat("FW Blocked","0",C['red'],"\u2718"); s.c_procs=_stat("Processes","0",C['teal'],"\u25A3")
        for c in [s.c_live,s.c_fw,s.c_fwb,s.c_procs]: sr.addWidget(c)
        lo.addLayout(sr)
        tb=QHBoxLayout(); tb.setSpacing(_dp(5))
        s.search=QLineEdit(); s.search.setPlaceholderText("Search connections, IPs, processes...")
        s.search.setFixedHeight(_dp(30)); s.search.textChanged.connect(s._on_search); tb.addWidget(s.search,1)
        s.filt=QComboBox(); s.filt.addItems(["All Connections","FW Blocked","Outbound","Inbound/Listen"])
        s.filt.currentIndexChanged.connect(s._on_search); tb.addWidget(s.filt)
        lo.addLayout(tb)
        s.tbl=_tbl(["Host / IP","Process","Port","FW Status","Country","Category"],0,row_h=30)
        s.tbl.setColumnWidth(1,_dp(130)); s.tbl.setColumnWidth(2,_dp(55)); s.tbl.setColumnWidth(3,_dp(90))
        s.tbl.setColumnWidth(4,_dp(55)); s.tbl.setColumnWidth(5,_dp(100))
        s.tbl.customContextMenuRequested.connect(s._ctx); s.tbl.doubleClicked.connect(s._dbl)
        lo.addWidget(s.tbl,1)
        s._overlay=LoadingOverlay(s.tbl)
        ib=QHBoxLayout()
        s.info=QLabel(""); s.info.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); ib.addWidget(s.info)
        ib.addStretch()
        s.learn_cb=QCheckBox("Learning Mode"); s.learn_cb.setChecked(s.learn.enabled)
        s.learn_cb.toggled.connect(lambda v:s.learn.set_enabled(v))
        s.learn_cb.setToolTip("Prompt when new processes connect"); ib.addWidget(s.learn_cb)
        lo.addLayout(ib)
    def showEvent(s,e):
        super().showEvent(e)
        if s._first_load: s._overlay.show_loading("Waiting for connections"); s._first_load=False
    def _on_search(s): s._last_hash=0; s._refresh()
    def _auto_refresh(s): s._refresh()
    def _rebuild_fw_cache(s):
        ips=set()
        for r in fw.get_cached():
            if r.action=="Block" and r.enabled and r.remote_addr and r.remote_addr not in ("Any","*",""):
                for addr in r.remote_addr.split(','): ips.add(addr.strip())
        s._fw_blocked_ips=ips
    def _refresh(s): s._load_conns(); s._upd_stats()
    def _upd_stats(s):
        _sv(s.c_live,len(s._conns)); _sv(s.c_fw,len(fw.get_cached()))
        _sv(s.c_fwb,sum(1 for c in s._conns if c.ra in s._fw_blocked_ips))
        procs=len({c.proc for c in s._conns if c.proc and c.proc!='?'})
        _sv(s.c_procs,procs)
    def _sel_domain(s):
        cur=s.tbl.currentRow()
        if cur>=0:
            it=s.tbl.item(cur,0)
            if it: return it.text()
        return None
    def _restore_sel(s,domain):
        if not domain: return
        for r in range(s.tbl.rowCount()):
            it=s.tbl.item(r,0)
            if it and it.text()==domain: s.tbl.setCurrentCell(r,0); return
    def _load_conns(s):
        q=s.search.text().strip().lower(); f=s.filt.currentText(); conns=list(s._conns)
        if q: conns=[c for c in conns if q in c.host.lower() or q in c.proc.lower() or q in c.ra.lower() or q in c.category.lower()]
        if f=="FW Blocked":
            s._rebuild_fw_cache(); conns=[c for c in conns if c.ra in s._fw_blocked_ips]
        elif f=="Outbound": conns=[c for c in conns if c.dir=="Out"]
        elif f=="Inbound/Listen": conns=[c for c in conns if c.dir!="Out"]
        h=hash(tuple(c.key for c in conns[:200]))
        if h==s._last_hash: s._overlay.hide_loading(); return
        s._last_hash=h
        saved=s._sel_domain()
        s._rebuild_fw_cache(); blocked_hosts=s.db.get_blocked_set()
        s.tbl.setSortingEnabled(False); s.tbl.setRowCount(len(conns))
        for i,c in enumerate(conns):
            host=c.host if c.host not in ('-','') else c.ra
            _icon_item(s.tbl,i,0,host,c.host if c.host not in ('-','') else None)
            s.tbl.setItem(i,1,QTableWidgetItem(f"{c.proc} ({c.pid})"))
            s.tbl.setItem(i,2,QTableWidgetItem(c.rp))
            f_blocked=c.ra in s._fw_blocked_ips
            h_blocked=c.host in blocked_hosts if c.host not in ('-','') else False
            if f_blocked: s.tbl.setCellWidget(i,3,_pill("FW BLOCK",C['mauve']))
            elif h_blocked: s.tbl.setCellWidget(i,3,_pill("HOSTS",C['red']))
            else: s.tbl.setCellWidget(i,3,_pill("\u2014",C['dim']))
            s.tbl.setItem(i,4,QTableWidgetItem(c.cc or ""))
            s.tbl.setItem(i,5,QTableWidgetItem(c.category))
            if f_blocked or h_blocked:
                for col in [0,1,2,4,5]:
                    it=s.tbl.item(i,col)
                    if it: it.setBackground(QColor(247,118,142,10))
        s.tbl.setSortingEnabled(True); s._restore_sel(saved)
        s.info.setText(f"{len(conns)} connections")
        s._overlay.hide_loading()
    def update_conns(s,conns):
        s._conns=conns
        s._conn_map={}
        for c in conns:
            if c.host and c.host not in ('-','','...'): s._conn_map[c.host]=c
        s._last_hash=0; s._load_conns()
        _sv(s.c_live,len(conns))
        if s.learn.enabled:
            for c in conns:
                if c.proc in ('?','System','svchost.exe'): continue
                key=f"{c.proc}:{c.ra}"
                if s.learn.is_trusted(c.proc.lower()) or s.learn.is_untrusted(c.proc.lower()): continue
                if s.learn.was_prompted(key): continue
                s.learn.mark_prompted(key); s._show_learn(c); break
    def _show_learn(s,ci):
        pop=LearnPopup(ci,s.window()); pop.finished.connect(lambda:s._on_learn(pop,ci)); pop.show()
    def _on_learn(s,pop,ci):
        a=pop.result_action
        if a=='trust': s.learn.trust(ci.proc); s._toast(f"Trusted {ci.proc}",C['green'])
        elif a=='untrust': s.learn.untrust(ci.proc); s._toast(f"Untrusted {ci.proc}",C['red'])
        elif a=='details': s._open_detail(ci)
    def _ctx(s,pos):
        q=s.search.text().strip().lower(); conns=list(s._conns)
        if q: conns=[c for c in conns if q in c.host.lower() or q in c.proc.lower() or q in c.ra.lower() or q in c.category.lower()]
        row=s.tbl.currentRow()
        if row<0 or row>=len(conns): return
        c=conns[row]; m=QMenu(s); m.setStyleSheet(CTX)
        m.addAction("\u2139 Connection Details...").triggered.connect(lambda:s._open_detail(c))
        m.addSeparator()
        hm=m.addMenu("Hosts File"); hm.setStyleSheet(CTX)
        if c.host and c.host not in ('-','','...'):
            hm.addAction(f"Block {c.host}").triggered.connect(lambda:s._act_block(c.host))
            r2=get_root(c.host)
            if r2!=c.host: hm.addAction(f"Block root ({r2})").triggered.connect(lambda:s._act_block_root(c.host))
            hm.addAction(f"Allow {c.host}").triggered.connect(lambda:s._act_allow(c.host))
        else: hm.addAction("(no hostname)").setEnabled(False)
        fm=m.addMenu("Firewall"); fm.setStyleSheet(CTX)
        fm.addAction(f"Block IP Out ({c.ra})").triggered.connect(lambda:s._fw_ip(c.ra))
        fm.addAction(f"Block IP In+Out ({c.ra})").triggered.connect(lambda:s._fw_ip_both(c.ra))
        if c.path:
            fm.addAction(f"Block {c.proc} Out").triggered.connect(lambda:s._fw_prog(c.path))
            fm.addAction(f"Block {c.proc} In+Out").triggered.connect(lambda:s._fw_prog_both(c.path))
        fm.addAction("Custom Rule \u2192").triggered.connect(lambda:s._fw_custom(c))
        lm=m.addMenu("Learning"); lm.setStyleSheet(CTX)
        lm.addAction(f"Trust {c.proc}").triggered.connect(lambda:(s.learn.trust(c.proc),s._toast(f"Trusted {c.proc}",C['green'])))
        lm.addAction(f"Untrust {c.proc}").triggered.connect(lambda:(s.learn.untrust(c.proc),s._toast(f"Untrusted {c.proc}",C['red'])))
        m.addSeparator()
        if c.pid>0: m.addAction(f"Kill (PID {c.pid})").triggered.connect(lambda:s._kill(c.pid,c.proc))
        m.addAction("Research \u2192").triggered.connect(lambda:open_research(c.host if c.host not in ('-','') else c.ra))
        m.addAction("Copy IP").triggered.connect(lambda:QApplication.clipboard().setText(c.ra))
        m.exec_(s.tbl.viewport().mapToGlobal(pos))
    def _dbl(s,idx):
        q=s.search.text().strip().lower(); conns=list(s._conns)
        if q: conns=[c for c in conns if q in c.host.lower() or q in c.proc.lower() or q in c.ra.lower() or q in c.category.lower()]
        if 0<=idx.row()<len(conns): s._open_detail(conns[idx.row()])
    def _open_detail(s,ci):
        dlg=ConnDetailDlg(ci,s.db,s.hm,s.learn,s)
        if dlg.exec_()==QDialog.Accepted and dlg.result_action:
            a,t=dlg.result_action
            {'hosts_block':s._act_block,'hosts_block_root':s._act_block_root,'hosts_allow':s._act_allow,
             'fw_block_ip':s._fw_ip,'fw_block_ip_both':s._fw_ip_both,
             'fw_block_prog':s._fw_prog,'fw_block_prog_both':s._fw_prog_both,
             'kill':lambda t:s._kill(int(t) if t.isdigit() else 0,ci.proc),
             'trust':lambda t:(s.learn.trust(t),s._toast(f"Trusted {t}",C['green'])),
             'untrust':lambda t:(s.learn.untrust(t),s._toast(f"Untrusted {t}",C['red'])),
             'reset_trust':lambda t:(s.learn.reset(t),s._toast(f"Reset {t}",C['dim']))}.get(a,lambda t:None)(t)
    # Actions — Hosts
    def _act_block(s,d):
        s.db.add_domain(d,'blocked','manual'); s.hm.block(d); s.db.log_event(d,'blocked','','Hosts block')
        s._last_hash=0; s._refresh(); s._toast(f"Blocked {d}",C['red'])
    def _act_block_root(s,d):
        root=get_root(d); s.db.add_root(d,'blocked','manual'); s.hm.block(root)
        s._last_hash=0; s._refresh(); s._toast(f"Blocked {root}",C['red'])
    def _act_allow(s,d):
        s.db.add_domain(d,'whitelisted','manual'); s.hm.unblock(d)
        s._last_hash=0; s._refresh(); s._toast(f"Allowed {d}",C['green'])
    # Actions — Firewall
    def _fw_ip(s,ip):
        n=fw.block_ip(ip); s._rebuild_fw_cache(); s._last_hash=0; s._refresh()
        s._toast(f"FW blocked {ip} out" if n else "Exists",C['red'] if n else C['dim'])
    def _fw_ip_both(s,ip):
        created=fw.block_ip_both(ip); s._rebuild_fw_cache(); s._last_hash=0; s._refresh()
        s._toast(f"Blocked {ip} in+out ({len(created)} rules)" if created else "Exists",C['red'] if created else C['dim'])
    def _fw_prog(s,path):
        n=fw.block_program(path); s._rebuild_fw_cache(); s._last_hash=0; s._refresh()
        s._toast(f"FW blocked {Path(path).name} out" if n else "Exists",C['red'] if n else C['dim'])
    def _fw_prog_both(s,path):
        created=fw.block_program_both(path); s._rebuild_fw_cache(); s._last_hash=0; s._refresh()
        s._toast(f"Blocked {Path(path).name} in+out ({len(created)} rules)" if created else "Exists",C['red'] if created else C['dim'])
    def _fw_custom(s,ci):
        pf={'addr':ci.ra,'prog':ci.path or '','proto':ci.proto,'name':f'{FW_PFX}Block_{ci.proc.replace(".exe","")}'}
        dlg=NewRuleDlg(s,pf)
        if dlg.exec_()==QDialog.Accepted:
            dd=dlg.data(); fw.create(dd['name'],dd['dir'],dd['action'],dd.get('addr',''),dd.get('proto',''),dd.get('prog',''))
            s._rebuild_fw_cache(); s._last_hash=0; s._refresh(); s._toast(f"Created {dd['name']}",C['green'])
    def _kill(s,pid,name):
        if pid>0 and fw.kill_conn(pid): s._toast(f"Killed {name}",C['peach'])
    def resizeEvent(s,e): super().resizeEvent(e); s._overlay._update_geom()
    def _toast(s,msg,color):
        w=s.window()
        if hasattr(w,'_toasts'): w._toasts.toast(msg,color)

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 2: HOSTS — Domains, Editor, Blocklists
# ═════════════════════════════════════════════════════════════════════════════
class HostsTab(QWidget):
    def __init__(s,db,hm):
        super().__init__(); s.db=db; s.hm=hm; s._first_load=True; s._build()
    def _build(s):
        lo=QVBoxLayout(s); lo.setContentsMargins(_dp(16),_dp(12),_dp(16),_dp(8)); lo.setSpacing(_dp(8))
        s._sub=QTabWidget(); s._sub.setDocumentMode(True)
        # Managed Domains
        dw=QWidget(); dl=QVBoxLayout(dw); dl.setContentsMargins(0,_dp(6),0,0); dl.setSpacing(_dp(6))
        desc=QLabel("Blocked domains are written to your hosts file as 0.0.0.0. Allowed domains are excluded from blocking.")
        desc.setWordWrap(True); desc.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); dl.addWidget(desc)
        tr=QHBoxLayout(); tr.setSpacing(_dp(5))
        s.d_search=QLineEdit(); s.d_search.setPlaceholderText("Search..."); s.d_search.setFixedHeight(_dp(30))
        s.d_search.textChanged.connect(s._load_d); tr.addWidget(s.d_search,1)
        s.d_filt=QComboBox(); s.d_filt.addItems(["All","Blocked","Allowed"]); s.d_filt.currentIndexChanged.connect(s._load_d); tr.addWidget(s.d_filt)
        tr.addWidget(_tbtn("Refresh","dim",s._sync_and_load,65))
        tr.addWidget(_tbtn("+ Add","primary",s._add,60)); tr.addWidget(_tbtn("Sync > Hosts","dim",s._sync,100))
        dl.addLayout(tr)
        s.d_tbl=_tbl(["Domain","Status","Source","Hits","Modified"],0)
        s.d_tbl.setColumnWidth(1,_dp(85)); s.d_tbl.setColumnWidth(2,_dp(90)); s.d_tbl.setColumnWidth(3,_dp(50)); s.d_tbl.setColumnWidth(4,_dp(140))
        s.d_tbl.customContextMenuRequested.connect(s._d_ctx); dl.addWidget(s.d_tbl,1)
        s.d_info=QLabel(""); s.d_info.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); dl.addWidget(s.d_info)
        s._d_overlay=LoadingOverlay(s.d_tbl)
        s._sub.addTab(dw,"Managed Domains")
        # Editor
        ew=QWidget(); el=QVBoxLayout(ew); el.setContentsMargins(0,_dp(6),0,0); el.setSpacing(_dp(6))
        ed=QLabel(f"Direct editing of {HOSTS_PATH}. Save writes immediately."); ed.setWordWrap(True)
        ed.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); el.addWidget(ed)
        eb=QHBoxLayout(); eb.setSpacing(_dp(5))
        eb.addWidget(_tbtn("\u21BB Reload","dim",s._reload,75)); eb.addWidget(_tbtn("Save","primary",s._save,55))
        eb.addWidget(_tbtn("Clean & Save","success",s._clean,100)); eb.addWidget(_tbtn("Backup","dim",s._backup,65))
        eb.addWidget(_tbtn("Restore","dim",s._restore,65)); eb.addWidget(_tbtn("\u26A0 Reset","danger",s._unlock,65))
        eb.addStretch()
        s.e_info=QLabel(""); s.e_info.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); eb.addWidget(s.e_info)
        el.addLayout(eb)
        s.editor=QPlainTextEdit(); s.editor.setFont(QFont("Cascadia Code,Consolas",_dp(10)))
        s.editor.setLineWrapMode(QPlainTextEdit.NoWrap); el.addWidget(s.editor,1)
        s._sub.addTab(ew,"Raw Hosts File")
        # Blocklists
        bw=QWidget(); bl=QVBoxLayout(bw); bl.setContentsMargins(0,_dp(6),0,0); bl.setSpacing(_dp(6))
        bd=QLabel("Import community blocklists. Each adds 0.0.0.0 entries for ad/tracking/malware domains.")
        bd.setWordWrap(True); bd.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); bl.addWidget(bd)
        btb=QHBoxLayout(); btb.setSpacing(_dp(5))
        btb.addWidget(_tbtn("Import Selected","primary",s._imp_sel,115)); btb.addWidget(_tbtn("All","dim",s._sel_all,40))
        btb.addWidget(_tbtn("None","dim",s._clr_all,45)); btb.addStretch()
        s.bl_prog=QProgressBar(); s.bl_prog.setFixedHeight(_dp(8)); s.bl_prog.setVisible(False); btb.addWidget(s.bl_prog,1)
        s.bl_st=QLabel(""); s.bl_st.setStyleSheet(f"color:{C['sub']};font-size:{_dp(10)}px;"); btb.addWidget(s.bl_st)
        bl.addLayout(btb)
        scroll=QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame)
        inner=QWidget(); s._slo=QVBoxLayout(inner); s._slo.setContentsMargins(0,0,0,0); s._slo.setSpacing(_dp(2))
        s._chk={}
        for cat,sources in SOURCES.items():
            lbl=QLabel(cat.upper()); lbl.setStyleSheet(f"color:{C['blue']};font-size:{_dp(10)}px;font-weight:800;letter-spacing:1.5px;padding:{_dp(6)}px 0 {_dp(2)}px {_dp(4)}px;")
            s._slo.addWidget(lbl)
            for name,url in sources:
                row=QWidget(); rl=QHBoxLayout(row); rl.setContentsMargins(_dp(4),0,_dp(4),0); rl.setSpacing(_dp(6))
                cb=QCheckBox(name); cb.setStyleSheet(f"font-size:{_dp(11)}px;"); rl.addWidget(cb,1)
                st=QLabel(""); st.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;min-width:{_dp(45)}px;"); rl.addWidget(st)
                rl.addWidget(_btn("Import","dim",lambda _=None,n=name,u=url:s._imp_one(n,u),tip=url))
                s._slo.addWidget(row); s._chk[name]=(cb,url,st)
        s._slo.addStretch()
        scroll.setWidget(inner); bl.addWidget(scroll,1)
        mg=QGroupBox("Paste Domains"); mgl=QVBoxLayout(mg)
        s.paste=QPlainTextEdit(); s.paste.setPlaceholderText("Paste domains (one per line)..."); s.paste.setMaximumHeight(_dp(60)); mgl.addWidget(s.paste)
        mr=QHBoxLayout(); mr.addWidget(_tbtn("Add to Hosts","primary",s._paste_h,100)); mr.addWidget(_tbtn("DB Only","dim",s._paste_db,70)); mr.addStretch()
        mgl.addLayout(mr); bl.addWidget(mg)
        s._sub.addTab(bw,"Blocklists")
        lo.addWidget(s._sub)
        s._sub.currentChanged.connect(lambda i: s._sync_and_load() if i==0 else s._reload() if i==1 else None)

    def showEvent(s,e):
        super().showEvent(e)
        if s._first_load:
            s._first_load=False; s._d_overlay.show_loading("Syncing hosts file")
            threading.Thread(target=s._bg_sync_and_load,daemon=True).start()
        elif s._sub.currentIndex()==0:
            s._load_d()

    def _bg_sync_and_load(s):
        """Run hosts sync in background, then load table on UI thread."""
        try:
            s.hm.read()
            s.db.sync_hosts_to_db(s.hm)
        except Exception as e: log.warning(f"Hosts sync: {e}")
        QTimer.singleShot(0,s._load_d)
        QTimer.singleShot(0,s._d_overlay.hide_loading)

    def _sync_and_load(s):
        """Manual refresh — re-read hosts file, sync to DB, reload table."""
        s._d_overlay.show_loading("Syncing hosts file")
        threading.Thread(target=s._bg_sync_and_load,daemon=True).start()

    def _load_d(s):
        q=s.d_search.text().strip() or None; f=s.d_filt.currentText().lower()
        st=None if f=='all' else f.replace('allowed','whitelisted')
        rows=s.db.get_domains(status=st,search=q)
        s.d_tbl.setSortingEnabled(False); s.d_tbl.setRowCount(len(rows))
        for i,(domain,status,cat,source,added,mod,hits,notes) in enumerate(rows):
            _icon_item(s.d_tbl,i,0,domain,domain)
            s.d_tbl.setCellWidget(i,1,_pill(status.upper(),C['red'] if status=='blocked' else C['green']))
            s.d_tbl.setItem(i,2,QTableWidgetItem((source or "")[:20]))
            s.d_tbl.setItem(i,3,QTableWidgetItem(str(hits))); s.d_tbl.setItem(i,4,QTableWidgetItem((mod or "")[:19]))
        s.d_tbl.setSortingEnabled(True)
        bl=sum(1 for r in rows if r[1]=='blocked'); wl=sum(1 for r in rows if r[1]=='whitelisted')
        s.d_info.setText(f"{len(rows)} domains \u00B7 {bl} blocked \u00B7 {wl} allowed")

    def _d_ctx(s,pos):
        sel=s.d_tbl.selectionModel().selectedRows()
        if not sel: return
        ds=[s.d_tbl.item(r.row(),0).text() for r in sel if s.d_tbl.item(r.row(),0)]
        if not ds: return
        d=ds[0]; root=get_root(d); m=QMenu(s); m.setStyleSheet(CTX)
        if len(ds)>1:
            m.addAction(f"Toggle {len(ds)}").triggered.connect(lambda:s._tog_multi(ds))
            m.addAction(f"Delete {len(ds)}").triggered.connect(lambda:s._del_multi(ds))
        else:
            cur=s.db.get_domains(search=d); st=cur[0][1] if cur else 'blocked'
            m.addAction("Allow" if st=='blocked' else "Block").triggered.connect(lambda:s._tog(d,st))
            m.addAction(f"Block root ({root})").triggered.connect(lambda:(s.db.add_root(d,'blocked','manual'),s.hm.block(root),s._load_d()))
            m.addSeparator(); m.addAction("Delete").triggered.connect(lambda:s._del(d))
            m.addSeparator(); m.addAction("Research \u2192").triggered.connect(lambda:open_research(d))
            m.addAction("Copy").triggered.connect(lambda:QApplication.clipboard().setText(d))
        m.exec_(s.d_tbl.viewport().mapToGlobal(pos))

    def _tog(s,d,cur):
        new='whitelisted' if cur=='blocked' else 'blocked'; s.db.update_status(d,new)
        (s.hm.block if new=='blocked' else s.hm.unblock)(d); s._load_d(); s._toast(f"{'Blocked' if new=='blocked' else 'Allowed'} {d}",C['red'] if new=='blocked' else C['green'])
    def _tog_multi(s,ds):
        for d in ds:
            cur=s.db.get_domains(search=d); st=cur[0][1] if cur else 'blocked'; s._tog(d,st)
    def _del(s,d): s.db.remove_domain(d); s.hm.unblock(d); s._load_d()
    def _del_multi(s,ds):
        for d in ds: s.db.remove_domain(d); s.hm.unblock(d)
        s._load_d()
    def _add(s):
        d,ok=QInputDialog.getText(s,"Add Domain","Domain:"); d=d.strip().lower()
        if ok and d:
            if not looks_like_domain(d): s._toast(f"Invalid: {d}",C['peach']); return
            s.db.add_domain(d,'blocked','manual'); s.hm.block(d); s._load_d(); s._toast(f"Blocked {d}",C['red'])
    def _sync(s):
        blocked=s.db.get_domains(status='blocked')
        hg_domains=set(r[0] for r in blocked)
        # Preserve existing non-HG entries
        existing=s.hm.get_lines(); preserved=[]
        in_hg_block=False
        for l in existing:
            line=l.strip()
            if f'managed by {APP}' in line or f'entries by {APP}' in line:
                in_hg_block=True; continue  # Skip old HG header
            if in_hg_block:
                # Skip old HG entries (lines that are just "0.0.0.0 domain" for HG domains)
                if line and not line.startswith('#'):
                    parts=line.split()
                    if len(parts)>=2 and parts[1].lower() in hg_domains: continue
                in_hg_block=False  # Non-matching line ends HG block
            preserved.append(l)
        # Append HG block
        hg_lines=[f"# --- {len(blocked)} entries managed by {APP} v{VER} ---\n"]
        for r in blocked: hg_lines.append(f"0.0.0.0 {r[0]}\n")
        text=''.join(preserved).rstrip('\n')+'\n'+'\n'.join(hg_lines)
        err=s.hm.save_raw(text)
        s._toast(f"Synced {len(blocked)} domains (preserved existing)" if not err else f"Error: {err}",C['green'] if not err else C['red'])
    def _reload(s):
        """Reload editor from hosts file. Always does a fresh read."""
        s.hm.read(); s._update_editor()
    def _update_editor(s):
        """Update editor widget from current in-memory hosts data (no file read)."""
        lines=s.hm.get_lines(); s.editor.setPlainText(''.join(lines))
        active=sum(1 for l in lines if l.strip() and not l.strip().startswith('#') and norm_line(l))
        s.e_info.setText(f"{len(lines)} lines \u00B7 {active} entries")
    def _save(s):
        err=s.hm.save_raw(s.editor.toPlainText())
        if err: s._toast(f"Error: {err}",C['red']); return
        s._toast("Saved",C['green'])
        # save_raw already re-read the file, just update editor from memory
        s._update_editor()
        # Sync to DB in background so Managed Domains reflects the save
        threading.Thread(target=lambda:s.db.sync_hosts_to_db(s.hm),daemon=True).start()
    def _clean(s):
        result=s.hm.save_clean()
        if result[1]: s._toast(f"Error: {result[1]}",C['red']); return
        st=result[0]
        s._toast(f"Cleaned: {st['active']} active",C['green'])
        s._update_editor()
        threading.Thread(target=lambda:s.db.sync_hosts_to_db(s.hm),daemon=True).start()
    def _backup(s):
        p=s.hm.backup(); s._toast(f"Backed up: {Path(p).name}" if p else "Failed",C['green'] if p else C['red'])
    def _restore(s):
        if s.hm.restore(): s._toast("Restored",C['green']); s._reload()
        else: s._toast("No backup",C['peach'])
    def _unlock(s):
        if s.hm.emergency_unlock(): s._toast("Reset to defaults",C['green']); s._reload()
    # Blocklists
    def _sel_all(s):
        for cb,_,_ in s._chk.values(): cb.setChecked(True)
    def _clr_all(s):
        for cb,_,_ in s._chk.values(): cb.setChecked(False)
    def _imp_sel(s):
        sel=[(n,u) for n,(cb,u,_) in s._chk.items() if cb.isChecked()]
        if not sel: s._toast("Select sources",C['peach']); return
        s._run_imp(sel)
    def _imp_one(s,n,u): s._run_imp([(n,u)])
    def _run_imp(s,sources):
        s.bl_prog.setVisible(True); s.bl_prog.setRange(0,len(sources)); s.bl_prog.setValue(0)
        s._iq=list(sources); s._ii=0; s._it=0; s._do_next()
    def _do_next(s):
        if s._ii>=len(s._iq):
            s.bl_prog.setVisible(False); s.bl_st.setText(f"Done! {s._it} domains")
            s._toast(f"Imported {s._it} from {len(s._iq)} sources",C['green']); return
        name,url=s._iq[s._ii]; s.bl_st.setText(f"{name}...")
        if name in s._chk: s._chk[name][2].setText("\u2026")
        s._cw=ImpWorker(name,url,s.hm,s.db); s._cw.done.connect(s._on_imp); s._cw.start()
    def _on_imp(s,name,ct,err):
        if name in s._chk:
            s._chk[name][2].setText(f"\u2713 {ct}" if not err else "\u2717")
            s._chk[name][2].setStyleSheet(f"color:{C['green'] if not err else C['red']};font-size:{_dp(10)}px;min-width:{_dp(45)}px;")
        s._it+=ct; s._ii+=1; s.bl_prog.setValue(s._ii); s._do_next()
    def _paste_h(s):
        ds=[d.strip().lower() for d in s.paste.toPlainText().splitlines() if looks_like_domain(d.strip().lower())]
        if not ds: return
        ct=s.hm.block_bulk(ds)
        for d in ds: s.db.add_domain(d,'blocked','paste')
        s._toast(f"Added {ct}",C['green']); s.paste.clear()
    def _paste_db(s):
        ds=[d.strip().lower() for d in s.paste.toPlainText().splitlines() if looks_like_domain(d.strip().lower())]
        for d in ds: s.db.add_domain(d,'blocked','paste')
        s._toast(f"DB: {len(ds)}",C['green']); s.paste.clear()
    def _toast(s,msg,color):
        w=s.window()
        if hasattr(w,'_toasts'): w._toasts.toast(msg,color)

class ImpWorker(QThread):
    done=pyqtSignal(str,int,str)
    def __init__(s,name,url,hm,db): super().__init__(); s.name,s.url,s.hm,s.db=name,url,hm,db
    def run(s):
        try:
            req=urllib.request.Request(s.url,headers={'User-Agent':'HostsGuard/3.1'})
            with urllib.request.urlopen(req,timeout=30) as resp:
                lines=resp.read().decode('utf-8',errors='replace').splitlines()
            domains=[d for l in lines if (d:=norm_line(l,False)) and looks_like_domain(d)]
            ct=s.hm.block_bulk(domains,flush=False)
            for d in domains: s.db.add_domain(d,'blocked',f'list:{s.name}')
            s.hm._flush(); s.done.emit(s.name,ct,"")
        except Exception as e: s.done.emit(s.name,0,str(e)[:40])

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 3: FIREWALL — with loading overlay
# ═════════════════════════════════════════════════════════════════════════════
class FirewallTab(QWidget):
    def __init__(s):
        super().__init__(); s._rules=[]; s._loaded=False; s._build()
        s._overlay=LoadingOverlay(s)
    def _build(s):
        lo=QVBoxLayout(s); lo.setContentsMargins(_dp(16),_dp(12),_dp(16),_dp(8)); lo.setSpacing(_dp(8))
        desc=QLabel("Windows Firewall rules. HostsGuard rules use the HG_ prefix."); desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); lo.addWidget(desc)
        tb=QHBoxLayout(); tb.setSpacing(_dp(5))
        s.fw_s=QLineEdit(); s.fw_s.setPlaceholderText("Search rules..."); s.fw_s.setFixedHeight(_dp(30))
        s.fw_s.textChanged.connect(s._apply); tb.addWidget(s.fw_s,1)
        s.fw_f=QComboBox(); s.fw_f.addItems(["All","HG Only","Block","Allow","Inbound","Outbound"])
        s.fw_f.currentIndexChanged.connect(s._apply); tb.addWidget(s.fw_f)
        tb.addWidget(_tbtn("\u21BB Refresh","primary",s._refresh,75))
        tb.addWidget(_tbtn("+ Rule","dim",s._new,60)); lo.addLayout(tb)
        qa=QHBoxLayout(); qa.setSpacing(_dp(5))
        qa.addWidget(_tbtn("Block IP Out","danger",s._qblock_ip,85))
        qa.addWidget(_tbtn("Block IP In+Out","danger",s._qblock_ip_both,105))
        qa.addWidget(_tbtn("Block Program","danger",s._qblock_prog,110))
        qa.addWidget(_tbtn("Enable Profiles","dim",s._profiles,110)); qa.addStretch()
        qa.addWidget(_tbtn("Delete All HG","danger",s._del_all_hg,115)); lo.addLayout(qa)
        s.tbl=_tbl(["","Name","Dir","Action","Proto","Remote","Program","Src"],1,row_h=28)
        s.tbl.setColumnWidth(0,_dp(28)); s.tbl.setColumnWidth(2,_dp(38)); s.tbl.setColumnWidth(3,_dp(48))
        s.tbl.setColumnWidth(4,_dp(50)); s.tbl.setColumnWidth(5,_dp(135)); s.tbl.setColumnWidth(6,_dp(135)); s.tbl.setColumnWidth(7,_dp(65))
        s.tbl.customContextMenuRequested.connect(s._ctx); s.tbl.doubleClicked.connect(s._dbl)
        lo.addWidget(s.tbl,1)
        bi=QHBoxLayout()
        s.info=QLabel(""); s.info.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); bi.addWidget(s.info)
        bi.addStretch()
        s.prof=QLabel(""); s.prof.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); bi.addWidget(s.prof)
        lo.addLayout(bi)

    def showEvent(s,e):
        super().showEvent(e)
        # Don't trigger if already loaded or currently loading
        if not s._loaded and not hasattr(s,'_fw_w'):
            s._loaded=True; s._refresh()

    def set_rules(s,rules):
        """Called after FWLoadWorker finishes."""
        s._rules=rules or []; s._loaded=True; s._apply(); s._overlay.hide_loading()
        threading.Thread(target=s._load_prof,daemon=True).start()

    def _refresh(s):
        s._overlay.show_loading("Loading firewall rules"); s.info.setText("Loading...")
        s._fw_w=FWLoadWorker(); s._fw_w.ready.connect(s.set_rules); s._fw_w.start()
    def _load_prof(s):
        profs=fw.get_profiles()
        parts=[f"{n}: {'ON' if e else 'OFF'}" for n,e in profs.items()]
        QTimer.singleShot(0,lambda:s.prof.setText("Profiles: "+' \u00B7 '.join(parts)))
    def _apply(s):
        try:
            q=s.fw_s.text().strip().lower(); f=s.fw_f.currentText(); rules=list(s._rules)
            if q: rules=[r for r in rules if q in (r.name or "").lower() or q in (r.program or "").lower() or q in (r.remote_addr or "").lower()]
            if "HG" in f: rules=[r for r in rules if r.source=="hostsguard"]
            elif f=="Block": rules=[r for r in rules if r.action=="Block"]
            elif f=="Allow": rules=[r for r in rules if r.action=="Allow"]
            elif f=="Inbound": rules=[r for r in rules if r.direction=="In"]
            elif f=="Outbound": rules=[r for r in rules if r.direction=="Out"]
            s.tbl.setSortingEnabled(False); s.tbl.setRowCount(len(rules))
            for i,r in enumerate(rules):
                ei=QTableWidgetItem("\u2713" if r.enabled else "\u2717"); ei.setForeground(QColor(C['green'] if r.enabled else C['red'])); s.tbl.setItem(i,0,ei)
                ni=QTableWidgetItem(r.name or "")
                if r.source=="hostsguard": ni.setForeground(QColor(C['blue']))
                s.tbl.setItem(i,1,ni)
                s.tbl.setItem(i,2,QTableWidgetItem(r.direction or ""))
                ai=QTableWidgetItem(r.action or ""); ai.setForeground(QColor(C['red'] if r.action=="Block" else C['green'])); s.tbl.setItem(i,3,ai)
                s.tbl.setItem(i,4,QTableWidgetItem(r.protocol or ""))
                addr=r.remote_addr if r.remote_addr not in ("Any","*","") else "Any"; s.tbl.setItem(i,5,QTableWidgetItem(addr[:60]))
                try: prog=Path(r.program).name if r.program else ""
                except: prog=r.program or ""
                s.tbl.setItem(i,6,QTableWidgetItem(prog))
                si=QTableWidgetItem(r.source or ""); si.setForeground(QColor(C['blue'] if r.source=="hostsguard" else C['dim'])); s.tbl.setItem(i,7,si)
            s.tbl.setSortingEnabled(True)
            hg=sum(1 for r in s._rules if r.source=="hostsguard")
            s.info.setText(f"{len(rules)} shown \u00B7 {len(s._rules)} total \u00B7 {hg} HG")
        except Exception as e: s.info.setText(f"Error: {e}")

    def _ctx(s,pos):
        row=s.tbl.currentRow()
        if row<0: return
        ni=s.tbl.item(row,1)
        if not ni: return
        name=ni.text(); rule=next((r for r in s._rules if r.name==name),None)
        ei=s.tbl.item(row,0); is_on=ei and ei.text()=="\u2713"
        m=QMenu(s); m.setStyleSheet(CTX)
        m.addAction("Disable" if is_on else "Enable").triggered.connect(lambda:(fw.enable(name,not is_on),s._toggle_local(name,not is_on),s._apply()))
        cur_act=rule.action if rule else "Allow"
        new_act="Allow" if cur_act=="Block" else "Block"
        m.addAction(f"Set to {new_act}").triggered.connect(lambda:(fw.set_action(name,new_act),s._set_action_local(name,new_act),s._apply(),s._toast(f"{name} \u2192 {new_act}",C['red'] if new_act=='Block' else C['green'])))
        m.addAction("Delete").triggered.connect(lambda:(fw.delete(name),s._remove_local(name),s._toast(f"Deleted {name}",C['dim'])))
        m.addSeparator()
        if rule:
            m.addAction("Duplicate / Edit").triggered.connect(lambda:s._dup(rule))
            if rule.program:
                m.addAction(f"Block {Path(rule.program).name} Inbound").triggered.connect(lambda:s._block_in(rule.program))
                m.addAction(f"Block {Path(rule.program).name} In+Out").triggered.connect(lambda:s._block_both(rule.program))
        m.addSeparator()
        m.addAction("Copy Name").triggered.connect(lambda:QApplication.clipboard().setText(name))
        m.exec_(s.tbl.viewport().mapToGlobal(pos))

    def _dbl(s,idx):
        ni=s.tbl.item(idx.row(),1)
        if ni:
            rule=next((r for r in s._rules if r.name==ni.text()),None)
            if rule: s._dup(rule)

    def _dup(s,r):
        pf={'name':r.name,'dir':{'In':'Inbound','Out':'Outbound'}.get(r.direction,'Outbound'),
            'action':r.action,'proto':r.protocol,'addr':r.remote_addr if r.remote_addr!='Any' else '','prog':r.program}
        dlg=NewRuleDlg(s,pf)
        if dlg.exec_()==QDialog.Accepted:
            d=dlg.data(); fw.create(d['name'],d['dir'],d['action'],d.get('addr',''),d.get('proto',''),d.get('prog',''))
            dr="In" if d['dir']=="Inbound" else "Out"
            s._inject_rule(d['name'],dr,d['action'],d.get('addr',''),d.get('prog','')); s._toast(f"Created {d['name']}",C['green'])

    def _new(s):
        dlg=NewRuleDlg(s)
        if dlg.exec_()==QDialog.Accepted:
            d=dlg.data(); fw.create(d['name'],d['dir'],d['action'],d.get('addr',''),d.get('proto',''),d.get('prog',''))
            dr="In" if d['dir']=="Inbound" else "Out"
            s._inject_rule(d['name'],dr,d['action'],d.get('addr',''),d.get('prog','')); s._toast(f"Created {d['name']}",C['green'])

    def _qblock_ip(s):
        ip,ok=QInputDialog.getText(s,"Block IP","IP address or range:")
        if ok and ip.strip():
            n=fw.block_ip(ip.strip())
            if n: s._inject_rule(n,"Out","Block",remote_addr=ip.strip()); s._toast(f"Blocked {ip.strip()} outbound",C['red'])
            else: s._toast("Rule already exists",C['dim'])
    def _qblock_ip_both(s):
        ip,ok=QInputDialog.getText(s,"Block IP In+Out","IP address or range:")
        if ok and ip.strip():
            created=fw.block_ip_both(ip.strip())
            if created:
                for n in created:
                    d="In" if "_In" in n else "Out"
                    s._inject_rule(n,d,"Block",remote_addr=ip.strip())
                s._toast(f"Blocked {ip.strip()} in+out ({len(created)} rules)",C['red'])
            else: s._toast("Rules already exist",C['dim'])
    def _qblock_prog(s):
        p,_=QFileDialog.getOpenFileName(s,"Block Program","","Executables (*.exe);;All (*)")
        if p:
            n=fw.block_program(p)
            if n: s._inject_rule(n,"Out","Block",program=p); s._toast(f"Blocked {Path(p).name} outbound",C['red'])
            else: s._toast("Rule already exists",C['dim'])
    def _inject_rule(s,name,direction,action,remote_addr="",program=""):
        """Add rule to local cache immediately for instant table update."""
        r=FWR(name=name,direction=direction,action=action,enabled=True,
            remote_addr=remote_addr,protocol="Any",program=program,source="hostsguard")
        s._rules.append(r)
        with fw._lock: fw._cache.append(r); fw._ts=time.time()
        s._apply()
    def _profiles(s): _ps("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",10); s._toast("Enabled all profiles",C['green'])
    def _del_all_hg(s):
        hg=[r.name for r in s._rules if r.source=="hostsguard" and r.name]
        for n in hg:
            try: fw.delete(n)
            except: pass
        s._rules=[r for r in s._rules if r.source!="hostsguard"]
        with fw._lock: fw._cache=[r for r in fw._cache if r.source!="hostsguard"]; fw._ts=time.time()
        s._apply(); s._toast(f"Deleted {len(hg)} HG rules",C['red'])
    def _toggle_local(s,name,enabled):
        for r in s._rules:
            if r.name==name: r.enabled=enabled; break
        with fw._lock:
            for r in fw._cache:
                if r.name==name: r.enabled=enabled; break
    def _set_action_local(s,name,action):
        for r in s._rules:
            if r.name==name: r.action=action; break
        with fw._lock:
            for r in fw._cache:
                if r.name==name: r.action=action; break
    def _remove_local(s,name):
        s._rules=[r for r in s._rules if r.name!=name]
        with fw._lock: fw._cache=[r for r in fw._cache if r.name!=name]
        s._apply()
    def _block_in(s,prog):
        name=f"{FW_PFX}Block_{Path(prog).stem}_In"; fw.create(name,"Inbound","Block",program=prog)
        s._inject_rule(name,"In","Block",program=prog); s._toast(f"Blocked {Path(prog).name} inbound",C['red'])
    def _block_both(s,prog):
        created=fw.block_program_both(prog)
        if created:
            for n in created:
                d="In" if "_In" in n else "Out"
                s._inject_rule(n,d,"Block",program=prog)
            s._toast(f"Blocked {Path(prog).name} in+out ({len(created)} rules)",C['red'])
    def resizeEvent(s,e): super().resizeEvent(e); s._overlay._update_geom()
    def _toast(s,msg,color):
        w=s.window()
        if hasattr(w,'_toasts'): w._toasts.toast(msg,color)

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 4: TOOLS
# ═════════════════════════════════════════════════════════════════════════════
class ToolsTab(QWidget):
    def __init__(s,db,hm,cdb,learn):
        super().__init__(); s.db=db; s.hm=hm; s.cdb=cdb; s.learn=learn; s._build()
    def _build(s):
        lo=QVBoxLayout(s); lo.setContentsMargins(_dp(16),_dp(12),_dp(16),_dp(8)); lo.setSpacing(_dp(10))
        grid=QHBoxLayout(); grid.setSpacing(_dp(10))
        g1=QGroupBox("DNS & Network"); l1=QVBoxLayout(g1); l1.setSpacing(_dp(4))
        l1.addWidget(_tbtn("Flush DNS","primary",s._flush)); l1.addWidget(_tbtn("Winsock Reset","dim",s._winsock))
        l1.addWidget(_tbtn("DHCP Renew","dim",s._renew)); l1.addStretch(); grid.addWidget(g1)
        g2=QGroupBox("Config & Data"); l2=QVBoxLayout(g2); l2.setSpacing(_dp(4))
        l2.addWidget(_tbtn("Export Config","primary",s._export)); l2.addWidget(_tbtn("Import Config","dim",s._import))
        l2.addWidget(_tbtn("Prune History (30d)","dim",s._prune)); l2.addWidget(_tbtn("Clear Favicons","dim",s._clear_fav))
        l2.addWidget(_tbtn("Open Config Folder","dim",s._open)); l2.addStretch(); grid.addWidget(g2)
        g3=QGroupBox("Learning Mode"); l3=QVBoxLayout(g3); l3.setSpacing(_dp(4))
        s.learn_st=QLabel(""); l3.addWidget(s.learn_st)
        l3.addWidget(_tbtn("View Trusted","dim",s._show_t)); l3.addWidget(_tbtn("View Untrusted","dim",s._show_u))
        l3.addWidget(_tbtn("Clear All Trust","danger",s._clear_t)); l3.addStretch(); grid.addWidget(g3)
        # Recovery section
        g4=QGroupBox("Backup & Recovery"); l4=QVBoxLayout(g4); l4.setSpacing(_dp(4))
        s.rec_st=QLabel(""); s.rec_st.setWordWrap(True); s.rec_st.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); l4.addWidget(s.rec_st)
        l4.addWidget(_tbtn("Restore Hosts from DB","primary",s._restore_hosts))
        l4.addWidget(_tbtn("Restore FW Rules from DB","primary",s._restore_fw))
        l4.addWidget(_tbtn("Sync Hosts File to DB","dim",s._sync_hosts_db))
        l4.addWidget(_tbtn("Backup Hosts Now","dim",lambda:(s.hm.backup(),s._toast("Backed up",C['green']))))
        l4.addStretch(); grid.addWidget(g4)
        lo.addLayout(grid)
        lg=QGroupBox("Event Log"); ll=QVBoxLayout(lg)
        lr=QHBoxLayout(); lr.setSpacing(_dp(5))
        s.log_s=QLineEdit(); s.log_s.setPlaceholderText("Search..."); s.log_s.setFixedHeight(_dp(28))
        s.log_s.textChanged.connect(s._log); lr.addWidget(s.log_s,1)
        s.log_f=QComboBox(); s.log_f.addItems(["All","blocked","whitelisted","fw_blocked"])
        s.log_f.currentIndexChanged.connect(s._log); lr.addWidget(s.log_f)
        lr.addWidget(_tbtn("Clear","danger",lambda:(s.db.clear_log(),s._log()),65)); ll.addLayout(lr)
        s.log_tbl=_tbl(["Time","Domain","Action","Process","Details"],1,row_h=26)
        s.log_tbl.setColumnWidth(0,_dp(140)); s.log_tbl.setColumnWidth(2,_dp(75)); s.log_tbl.setColumnWidth(3,_dp(95)); s.log_tbl.setColumnWidth(4,_dp(170))
        ll.addWidget(s.log_tbl,1); lo.addWidget(lg,1)

    def showEvent(s,e):
        super().showEvent(e); s._log(); s._upd_learn(); s._upd_rec()
    def _upd_learn(s):
        t=len(s.learn._trusted); u=len(s.learn._untrusted)
        s.learn_st.setText(f"{'ON' if s.learn.enabled else 'OFF'} \u00B7 {t} trusted \u00B7 {u} untrusted")
        s.learn_st.setStyleSheet(f"color:{C['green'] if s.learn.enabled else C['dim']};font-size:{_dp(11)}px;font-weight:700;")
    def _upd_rec(s):
        db_blocked=len(s.db.get_domains(status='blocked'))
        db_allowed=len(s.db.get_domains(status='whitelisted'))
        fw_tracked=len(s.db.get_fw_state())
        hosts_blocked=len(s.hm.get_blocked())
        s.rec_st.setText(f"DB: {db_blocked} blocked, {db_allowed} allowed\nFW tracked: {fw_tracked} rules\nHosts file: {hosts_blocked} entries")
    def _log(s):
        q=s.log_s.text().strip() or None; f=s.log_f.currentText(); af='all' if f=='All' else f
        rows=s.db.get_log(limit=500,domain_filter=q,action_filter=af)
        s.log_tbl.setSortingEnabled(False); s.log_tbl.setRowCount(len(rows))
        for i,(_id,ts,domain,action,proc,det) in enumerate(rows):
            s.log_tbl.setItem(i,0,QTableWidgetItem((ts or "")[:19]))
            _icon_item(s.log_tbl,i,1,domain or "",domain)
            ai=QTableWidgetItem(action or ""); ai.setForeground(QColor({'blocked':C['red'],'whitelisted':C['green'],'fw_blocked':C['mauve']}.get(action,C['dim'])))
            s.log_tbl.setItem(i,2,ai); s.log_tbl.setItem(i,3,QTableWidgetItem(proc or "")); s.log_tbl.setItem(i,4,QTableWidgetItem(det or ""))
        s.log_tbl.setSortingEnabled(True)
    def _flush(s): subprocess.Popen(['ipconfig','/flushdns'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=NOWIN); s._toast("DNS flushed",C['green'])
    def _winsock(s): threading.Thread(target=lambda:_ps("netsh winsock reset",10),daemon=True).start(); s._toast("Winsock reset (reboot needed)",C['green'])
    def _renew(s): threading.Thread(target=lambda:_ps("ipconfig /release && ipconfig /renew",15),daemon=True).start(); s._toast("Renewing...",C['blue'])
    def _export(s):
        data={'version':VER,'schema':SCHEMA_VER,'domains':[{'domain':r[0],'status':r[1],'source':r[3]} for r in s.db.get_domains()],
            'fw_rules':[r.name for r in fw.get_cached() if r.source=='hostsguard'],
            'fw_state':[{'name':r[0],'direction':r[1],'action':r[2],'remote_addr':r[3],'protocol':r[4],'program':r[5]} for r in s.db.get_fw_state()],
            'trusted':list(s.learn._trusted),'untrusted':list(s.learn._untrusted)}
        p=os.path.join(CONFIG_DIR,f"hg_export_{datetime.datetime.now():%Y%m%d_%H%M}.json")
        with open(p,'w') as f: json.dump(data,f,indent=2); s._toast(f"Exported: {Path(p).name}",C['green'])
    def _import(s):
        p,_=QFileDialog.getOpenFileName(s,"Import","","JSON (*.json)")
        if not p: return
        try:
            with open(p) as f: data=json.load(f)
            ct=0
            for d in data.get('domains',[]): s.db.add_domain(d['domain'],d.get('status','blocked'),d.get('source','import')); ct+=1
            for r in data.get('fw_state',[]):
                s.db.save_fw_rule(r.get('name',''),r.get('direction',''),r.get('action','Block'),r.get('remote_addr',''),r.get('protocol',''),r.get('program',''))
            for proc in data.get('trusted',[]): s.learn.trust(proc)
            for proc in data.get('untrusted',[]): s.learn.untrust(proc)
            fwct=len(data.get('fw_state',[]))
            s._toast(f"Imported {ct} domains, {fwct} FW rules",C['green']); s._upd_learn()
        except Exception as e: s._toast(f"Error: {e}",C['red'])
    def _prune(s): s.cdb.prune(30); s._toast("Pruned",C['green'])
    def _clear_fav(s):
        ct=sum(1 for f in Path(FAV_DIR).glob("*.png") if (f.unlink() or True))
        if _fav: _fav._mem.clear(); s._toast(f"Cleared {ct}",C['green'])
    def _open(s):
        if sys.platform=='win32': os.startfile(CONFIG_DIR)
    def _show_t(s): QMessageBox.information(s,"Trusted",'\n'.join(sorted(s.learn._trusted) or ["(none)"]))
    def _show_u(s): QMessageBox.information(s,"Untrusted",'\n'.join(sorted(s.learn._untrusted) or ["(none)"]))
    def _clear_t(s): s.learn._trusted.clear(); s.learn._untrusted.clear(); s.learn.save(); s._upd_learn()
    def _restore_hosts(s):
        """Re-add all DB blocked domains to hosts file."""
        blocked=s.db.get_domains(status='blocked')
        added=0
        for r in blocked:
            if s.hm.block(r[0],flush=False): added+=1
        if added>0: s.hm._flush()
        s._toast(f"Restored {added} entries to hosts file ({len(blocked)} total in DB)",C['green']); s._upd_rec()
    def _restore_fw(s):
        """Re-create all tracked FW rules from DB."""
        rules=s.db.get_fw_state(); created=0
        for name,direction,action,remote_addr,protocol,program,_ in rules:
            if not fw.exists(name):
                fw.create(name,direction or "Outbound",action or "Block",remote_addr=remote_addr or "",
                    protocol=protocol or "",program=program or "",desc=f"Restored by {APP}")
                created+=1
        s._toast(f"Restored {created} FW rules ({len(rules)} tracked)",C['green']); s._upd_rec()
    def _sync_hosts_db(s):
        """Read hosts file and add all entries to DB."""
        s.hm.read()  # Fresh read
        added=s.db.sync_hosts_to_db(s.hm)
        s._toast(f"Synced {added} new entries from hosts file to DB",C['green']); s._upd_rec()
    def _toast(s,msg,color):
        w=s.window()
        if hasattr(w,'_toasts'): w._toasts.toast(msg,color)

# ═════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW — splash-driven parallel startup
# ═════════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(s,results):
        super().__init__(); s.setWindowTitle(f"{APP} v{VER}")
        s.setMinimumSize(_dp(1200),_dp(720)); s.resize(_dp(1440),_dp(860))
        s._launch_time=time.time(); s._notif_cd={}
        s._monitoring=False; s._conn_on=False
        # Use pre-loaded data from StartupLoader
        s.db=results['db']; s.hm=results['hm']; s.cdb=results['cdb']
        s.learn=LearnDB(s.db)
        # Wire FW engine to DB for persistent rule tracking
        fw.set_db(s.db)
        # Startup backup + sync (non-blocking)
        threading.Thread(target=s._startup_sync,daemon=True).start()
        # Background workers
        s._dns_w=DNSResolveWorker(); s._dns_w.start()
        s._geo_w=GeoWorker(); s._geo_w.start()
        s._conn_w=None; s._dns_mon=None
        s._build_ui()
        s._build_tray()
        # Launch FW rule loading in background (dedicated subprocess, not PPS)
        s._fw_tab._overlay.show_loading("Loading firewall rules")
        s._fw_loader=FWLoadWorker(); s._fw_loader.ready.connect(s._fw_tab.set_rules); s._fw_loader.start()
        # Hosts watcher
        s._watcher=HostsWatcher(); s._watcher.changed.connect(s._on_hosts_changed); s._watcher.start()
        # Start monitors — no delay needed, data already loaded
        QTimer.singleShot(100,s._start_dns)
        QTimer.singleShot(200,s._start_conns)
        # Lazy-load favicons after UI is visible
        QTimer.singleShot(500,_init_fav)

    def _startup_sync(s):
        """Run at startup: backup hosts, sync hosts entries to DB."""
        try: s.hm.backup()
        except: pass
        try: s.db.sync_hosts_to_db(s.hm)
        except: pass

    def _build_ui(s):
        cw=QWidget(); cw.setStyleSheet(f"background:{C['bg']};"); s.setCentralWidget(cw)
        root=QVBoxLayout(cw); root.setContentsMargins(0,0,0,0); root.setSpacing(0)
        # Top bar
        top=QWidget(); top.setFixedHeight(_dp(44))
        top.setStyleSheet(f"QWidget{{background:{C['crust']};border-bottom:1px solid {C['s0']};}}")
        tb=QHBoxLayout(top); tb.setContentsMargins(_dp(16),0,_dp(16),0); tb.setSpacing(_dp(8))
        logo=QLabel(f"\u25C6  {APP}"); logo.setFont(QFont("Segoe UI Variable Display",_dp(12),QFont.Bold))
        logo.setStyleSheet(f"color:{C['blue']};letter-spacing:-0.3px;"); tb.addWidget(logo)
        vl=QLabel(f"v{VER}"); vl.setStyleSheet(f"color:{C['dim']};font-size:{_dp(9)}px;padding-top:1px;"); tb.addWidget(vl)
        sep=QFrame(); sep.setFixedSize(1,_dp(20)); sep.setStyleSheet(f"background:{C['s0']};"); tb.addWidget(sep)
        s._dot=QLabel(); s._dot.setFixedSize(_dp(7),_dp(7)); s._dot.setStyleSheet(f"background:{C['dim']};border-radius:{_dp(3)}px;"); tb.addWidget(s._dot)
        s._status=QLabel("STARTING"); s._status.setStyleSheet(f"color:{C['dim']};font-size:{_dp(9)}px;font-weight:700;letter-spacing:0.5px;"); tb.addWidget(s._status)
        try: adm=ctypes.windll.shell32.IsUserAnAdmin()!=0
        except: adm=False
        ac=C['green'] if adm else C['peach']
        rgb=','.join(str(int(ac.lstrip('#')[i:i+2],16)) for i in (0,2,4))
        ab=QLabel("ADMIN" if adm else "USER"); ab.setStyleSheet(f"color:{ac};font-size:{_dp(8)}px;font-weight:700;background:rgba({rgb},0.12);border-radius:{_dp(3)}px;padding:1px 5px;"); tb.addWidget(ab)
        tb.addStretch()
        s._bw_up=QLabel("\u25B2 --"); s._bw_up.setStyleSheet(f"color:{C['blue']};font-size:{_dp(9)}px;font-weight:600;font-family:'Cascadia Code','Consolas',monospace;"); tb.addWidget(s._bw_up)
        s._bw_dn=QLabel("\u25BC --"); s._bw_dn.setStyleSheet(f"color:{C['teal']};font-size:{_dp(9)}px;font-weight:600;font-family:'Cascadia Code','Consolas',monospace;"); tb.addWidget(s._bw_dn)
        sep2=QFrame(); sep2.setFixedSize(1,_dp(20)); sep2.setStyleSheet(f"background:{C['s0']};"); tb.addWidget(sep2)
        s._cbtn=QPushButton("CONNECTIONS: OFF"); s._cbtn.setCursor(Qt.PointingHandCursor); s._cbtn.setFixedHeight(_dp(24))
        s._cbtn.setStyleSheet(f"background:{C['s0']};color:{C['dim']};padding:2px 12px;border-radius:{_dp(5)}px;font-weight:700;font-size:{_dp(8)}px;border:none;letter-spacing:0.5px;")
        s._cbtn.clicked.connect(s._toggle_conns); tb.addWidget(s._cbtn)
        # Notification mute toggle
        s._notif_muted=load_cfg().get('notif_muted',False)
        s._mbtn=QPushButton("NOTIF: OFF" if s._notif_muted else "NOTIF: ON")
        s._mbtn.setCursor(Qt.PointingHandCursor); s._mbtn.setFixedHeight(_dp(24))
        s._mbtn.setToolTip("Toggle desktop notifications for blocked domains")
        s._upd_mute_btn(); s._mbtn.clicked.connect(s._toggle_mute); tb.addWidget(s._mbtn)
        root.addWidget(top)
        # Tabs
        s._tabs=QTabWidget(); s._tabs.setDocumentMode(True)
        s._hosts_act=HostsActivityTab(s.db,s.hm,s.learn); s._tabs.addTab(s._hosts_act,"Hosts Activity")
        s._fw_act=FWActivityTab(s.db,s.hm,s.cdb,s.learn); s._tabs.addTab(s._fw_act,"FW Activity")
        s._hosts_tab=HostsTab(s.db,s.hm); s._tabs.addTab(s._hosts_tab,"Hosts File")
        s._fw_tab=FirewallTab(); s._tabs.addTab(s._fw_tab,"FW Rules")
        s._tools=ToolsTab(s.db,s.hm,s.cdb,s.learn); s._tabs.addTab(s._tools,"Tools")
        root.addWidget(s._tabs)
        s._toasts=ToastMgr(s)
        s._bw_tmr=QTimer(s); s._bw_tmr.timeout.connect(s._upd_bw); s._bw_tmr.start(2000)

    def _start_dns(s):
        s._dns_mon=DNSMonitor(s.hm,s.db)
        s._dns_mon.status.connect(lambda m:s._set_st(m))
        s._dns_mon.blocked_event.connect(s._on_blocked)
        s._dns_mon.updated.connect(s._hosts_act._refresh)
        s._hosts_act.set_monitor(s._dns_mon)
        s._dns_mon.start(); s._monitoring=True; s._set_st("DNS Active")

    def _on_blocked(s,ev):
        if not s._tray or s._notif_muted: return
        if time.time()-s._launch_time<15: return
        d=ev.get('domain',''); now=time.time()
        if d in s._notif_cd and now-s._notif_cd[d]<60: return
        s._notif_cd[d]=now
        s._tray.showMessage(APP,f"Blocked: {d}",QSystemTrayIcon.Warning,2000)

    def _toggle_mute(s):
        s._notif_muted=not s._notif_muted; s._upd_mute_btn()
        cfg=load_cfg(); cfg['notif_muted']=s._notif_muted; save_cfg(cfg)
        s._toasts.toast("Notifications OFF" if s._notif_muted else "Notifications ON",C['dim'] if s._notif_muted else C['green'])
    def _upd_mute_btn(s):
        on=not s._notif_muted
        s._mbtn.setText("NOTIF: ON" if on else "NOTIF: OFF")
        if on: s._mbtn.setStyleSheet(f"background:{C['s0']};color:{C['green']};padding:2px 10px;border-radius:{_dp(5)}px;font-weight:700;font-size:{_dp(8)}px;border:none;letter-spacing:0.5px;")
        else: s._mbtn.setStyleSheet(f"background:{C['s0']};color:{C['dim']};padding:2px 10px;border-radius:{_dp(5)}px;font-weight:700;font-size:{_dp(8)}px;border:none;letter-spacing:0.5px;")

    def _start_conns(s):
        s._conn_w=ConnWorker(s.db)
        s._conn_w.ready.connect(s._on_conns)
        s._conn_w.need_dns.connect(s._dns_w.add); s._conn_w.need_geo.connect(s._geo_w.add)
        s._conn_w.start(); s._conn_on=True; s._set_st("All Active")
        s._cbtn.setText("CONNECTIONS: ON")
        s._cbtn.setStyleSheet(f"background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #5b7ee5,stop:1 {C['blue']});color:#fff;padding:2px 12px;border-radius:{_dp(5)}px;font-weight:700;font-size:{_dp(8)}px;border:none;letter-spacing:0.5px;")

    def _stop_conns(s):
        if s._conn_w: s._conn_w.stop()
        s._conn_on=False; s._set_st("DNS Only")
        s._cbtn.setText("CONNECTIONS: OFF")
        s._cbtn.setStyleSheet(f"background:{C['s0']};color:{C['dim']};padding:2px 12px;border-radius:{_dp(5)}px;font-weight:700;font-size:{_dp(8)}px;border:none;letter-spacing:0.5px;")

    def _toggle_conns(s):
        if s._conn_on: s._stop_conns()
        else: s._start_conns()

    def _on_conns(s,conns):
        s._fw_act.update_conns(conns)
        live=[c for c in conns if c.ra and c.ra!="*" and c.dir!="Listen"]
        if live: s.cdb.insert_batch(live)

    def _on_hosts_changed(s):
        if s.hm._suppress_watcher:
            s.hm._suppress_watcher=False; return  # Internal save, already up to date
        s.hm.read()
        threading.Thread(target=lambda:s.db.sync_hosts_to_db(s.hm),daemon=True).start()
        s._toasts.toast("Hosts file changed externally",C['peach'])
    def _set_st(s,msg):
        on=s._monitoring or s._conn_on; c=C['green'] if on else C['red']
        s._dot.setStyleSheet(f"background:{c};border-radius:{_dp(3)}px;")
        s._status.setText(msg.upper()[:25]); s._status.setStyleSheet(f"color:{c};font-size:{_dp(9)}px;font-weight:700;letter-spacing:0.5px;")
    def _upd_bw(s):
        up,dn=bw.rates(); s._bw_up.setText(f"\u25B2 {bw.fmt(up)}"); s._bw_dn.setText(f"\u25BC {bw.fmt(dn)}")

    def _build_tray(s):
        s._tray=None
        if not QSystemTrayIcon.isSystemTrayAvailable(): return
        s._tray=QSystemTrayIcon(s.style().standardIcon(QStyle.SP_ComputerIcon),s)
        m=QMenu(); m.setStyleSheet(CTX)
        m.addAction("Show").triggered.connect(lambda:(s.show(),s.raise_(),s.activateWindow()))
        m.addSeparator()
        m.addAction("Hosts Activity").triggered.connect(lambda:(s.show(),s._tabs.setCurrentWidget(s._hosts_act)))
        m.addAction("FW Activity").triggered.connect(lambda:(s.show(),s._tabs.setCurrentWidget(s._fw_act)))
        m.addAction("Hosts File").triggered.connect(lambda:(s.show(),s._tabs.setCurrentWidget(s._hosts_tab)))
        m.addAction("FW Rules").triggered.connect(lambda:(s.show(),s._tabs.setCurrentWidget(s._fw_tab)))
        m.addSeparator()
        m.addAction("Quit").triggered.connect(s._quit)
        s._tray.setContextMenu(m)
        s._tray.activated.connect(lambda r:s.show() if r==QSystemTrayIcon.DoubleClick else None)
        s._tray.show()

    def closeEvent(s,e):
        if s._tray: e.ignore(); s.hide()
        else: s._quit()

    def _quit(s):
        try:
            if s._dns_mon: s._dns_mon.stop()
            if s._conn_w: s._conn_w.stop()
            if s._watcher: s._watcher.stop()
            s._dns_w.stop(); s._geo_w.stop()
            _pps.close()
        except: pass
        QApplication.quit()

    def resizeEvent(s,e): super().resizeEvent(e); s._toasts._place()

# ═════════════════════════════════════════════════════════════════════════════
#  ENTRY — Splash -> StartupLoader -> MainWindow
# ═════════════════════════════════════════════════════════════════════════════
def main():
    # Hide console
    if sys.platform=='win32':
        try:
            hwnd=ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                pid=ctypes.c_ulong(); ctypes.windll.user32.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
                if pid.value==os.getpid(): ctypes.windll.user32.ShowWindow(hwnd,0)
        except: pass
    try:
        app=QApplication(sys.argv)
        app.setStyle("Fusion"); app.setApplicationName(APP); app.setStyleSheet(STYLE)

        # Show splash immediately
        splash=Splash(); splash.setup(); splash.show()
        app.processEvents()

        # Run startup loader in background thread
        main_win=[None]
        loader=StartupLoader()

        def on_progress(step,pct):
            splash.update_progress(step,pct)

        def on_loaded(results):
            splash.close()
            main_win[0]=MainWindow(results)
            main_win[0].show()

        loader.progress.connect(on_progress)
        loader.finished.connect(on_loaded)
        loader.start()

        sys.exit(app.exec_())
    except Exception as e:
        import traceback; tb=traceback.format_exc()
        crash=os.path.join(CONFIG_DIR,"crash.log")
        try:
            os.makedirs(CONFIG_DIR,exist_ok=True)
            with open(crash,'a') as f: f.write(f"\n{'='*60}\n{datetime.datetime.now()}\n{tb}\n")
        except: pass
        try:
            from PyQt5.QtWidgets import QMessageBox as MB,QApplication as Q2
            if not Q2.instance(): Q2(sys.argv)
            MB.critical(None,f"{APP} Crash",f"{e}\n\nSee: {crash}")
        except: pass
        print(f"CRASH: {e}\n{tb}",file=sys.stderr); sys.exit(1)

if __name__=="__main__": main()
