#!/usr/bin/env python3
"""
HostsGuard v3.13.0 — Network Privacy Manager
See what connects. Block what you don't want. Simple.
"""
import sys,os,subprocess,json,sqlite3,re,shutil,time,threading,hashlib,csv,io
import tempfile,webbrowser,socket,datetime,logging,multiprocessing,ipaddress,uuid
from pathlib import Path
from collections import OrderedDict,defaultdict
from dataclasses import dataclass,field
from queue import Queue,Empty
from threading import Lock,Event as TEvent
import urllib.request,urllib.error


def _branding_icon_path() -> Path:
    candidates = []
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        candidates.append(exe_dir / "icon.png")
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / "icon.png")
    current = Path(__file__).resolve()
    candidates.extend([current.parent / "icon.png", current.parent.parent / "icon.png", current.parent.parent.parent / "icon.png"])
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return Path("icon.png")


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
                elif 'powershell' in n and 'hostsguard' in cl: p.kill()
            except: continue
    except: pass

CLI_CMDS=('block','allow','unblock','status','export','help')
def _is_cli_invocation():
    args=[a for a in sys.argv[1:] if not a.startswith('--')]
    return bool(args and args[0] in CLI_CMDS)

def _bootstrap():
    is_cli=_is_cli_invocation()
    # CLI commands never auto-elevate (elevation would spawn a new console and
    # lose both arguments and output) and never kill a running GUI instance.
    if sys.platform=='win32' and not is_cli:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            try:
                h=ctypes.windll.kernel32.GetConsoleWindow()
                if h:
                    # Only hide the console if this process owns it — never the user's terminal
                    pid=ctypes.c_ulong(); ctypes.windll.user32.GetWindowThreadProcessId(h,ctypes.byref(pid))
                    if pid.value==os.getpid(): ctypes.windll.user32.ShowWindow(h,0)
            except: pass
            # Preserve argv on relaunch — dropping it silently lost --portable/--service
            params=([] if getattr(sys,'frozen',False) else [os.path.abspath(__file__)])+list(sys.argv[1:])
            args=' '.join(f'"{a}"' for a in params)
            ctypes.windll.shell32.ShellExecuteW(None,"runas",sys.executable,args,None,1)
            os._exit(0)
    if not is_cli and '--service' not in sys.argv: _kill_remnants()
    if sys.version_info<(3,8): print("Python 3.8+ required"); sys.exit(1)
    _cf={'creationflags':NOWIN} if sys.platform=='win32' else {}
    for pkg in ['PySide6','psutil','maxminddb']:
        try: __import__(pkg)
        except ImportError:
            for f in [[],['--user']]:
                try: subprocess.check_call([sys.executable,'-m','pip','install',pkg,'-q']+f,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,**_cf); break
                except: continue
_bootstrap()

import psutil
from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtGui import *
# Qt6 enables HiDPI scaling automatically; these attributes are deprecated no-ops
# (kept for older Qt, guarded so a future removal can't crash, with the Qt6
# deprecation warning suppressed so it doesn't spam stderr on every launch/CLI run).
import warnings as _warnings
with _warnings.catch_warnings():
    _warnings.simplefilter("ignore",DeprecationWarning)
    for _attr in ("AA_EnableHighDpiScaling","AA_UseHighDpiPixmaps"):
        try: QApplication.setAttribute(getattr(Qt,_attr),True)
        except Exception: pass

# ─── Constants ──────────────────────────────────────────────────────────────
APP="HostsGuard"; VER="3.13.0"; FW_PFX="HG_"
HOSTS_PATH=r"C:\Windows\System32\drivers\etc\hosts" if sys.platform=='win32' else "/etc/hosts"
_PORTABLE='--portable' in sys.argv
if _PORTABLE:
    _base=Path(sys.executable).resolve().parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parent
    CONFIG_DIR=str(_base / "data")
else:
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
SCHEMA_VER=6
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
DOH_IPS={'1.1.1.1','1.0.0.1','8.8.8.8','8.8.4.4','9.9.9.9','149.112.112.112',
    '94.140.14.14','94.140.15.15','45.90.28.0','45.90.30.0','208.67.222.222','208.67.220.220',
    '185.228.168.168','185.228.169.168','76.76.2.0','76.76.10.0',
    '2606:4700:4700::1111','2606:4700:4700::1001','2001:4860:4860::8888','2001:4860:4860::8844'}
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
_DEFENDER_WARN={"Windows/Office","HaGezi Ultimate","StevenBlack Unified","Windows Spy Blocker"}

# One-click "block this service" domain sets (apex + primary sub/CDN domains).
# Hosts blocking matches exact hostnames (no wildcards), so this is best-effort for
# the common browser/app case — it will not catch every rotating subdomain, and DoH
# can bypass it (use the "Block Encrypted DNS" toggle alongside).
BLOCK_SERVICES={
    "YouTube":["youtube.com","www.youtube.com","m.youtube.com","youtu.be","youtubei.googleapis.com","youtube-nocookie.com","yt3.ggpht.com","googlevideo.com"],
    "TikTok":["tiktok.com","www.tiktok.com","tiktokcdn.com","tiktokv.com","byteoversea.com","ibytedtos.com","musical.ly"],
    "Facebook":["facebook.com","www.facebook.com","m.facebook.com","fbcdn.net","fb.com","fbsbx.com","facebook.net"],
    "Instagram":["instagram.com","www.instagram.com","cdninstagram.com","ig.me"],
    "X (Twitter)":["twitter.com","www.twitter.com","x.com","www.x.com","twimg.com","t.co"],
    "Reddit":["reddit.com","www.reddit.com","old.reddit.com","redd.it","redditstatic.com","redditmedia.com"],
    "Discord":["discord.com","discord.gg","discordapp.com","discordapp.net","discord.media"],
    "Snapchat":["snapchat.com","www.snapchat.com","sc-cdn.net","snap.com"],
    "Netflix":["netflix.com","www.netflix.com","nflxvideo.net","nflximg.net","nflxext.com","nflxso.net"],
    "Twitch":["twitch.tv","www.twitch.tv","ttvnw.net","jtvnw.net","twitchcdn.net"],
    "WhatsApp":["whatsapp.com","www.whatsapp.com","whatsapp.net","wa.me"],
    "Telegram":["telegram.org","telegram.me","t.me","tdesktop.com","telegra.ph"],
    "LinkedIn":["linkedin.com","www.linkedin.com","licdn.com","lnkd.in"],
    "Pinterest":["pinterest.com","www.pinterest.com","pinimg.com"],
}

# Curated Microsoft telemetry endpoints for a one-click privacy preset. Blocking
# these will trip Defender's SettingsModifier:Win32/HostsFileHijack (that's the
# whole telemetry-block scenario) — the toggle warns before applying.
MS_TELEMETRY=[
    "vortex.data.microsoft.com","vortex-win.data.microsoft.com","telecommand.telemetry.microsoft.com",
    "telemetry.microsoft.com","watson.telemetry.microsoft.com","watson.microsoft.com",
    "settings-win.data.microsoft.com","v10.vortex-win.data.microsoft.com","v10.events.data.microsoft.com",
    "v20.events.data.microsoft.com","functional.events.data.microsoft.com","self.events.data.microsoft.com",
    "browser.events.data.msn.com","oca.telemetry.microsoft.com","sqm.telemetry.microsoft.com",
    "df.telemetry.microsoft.com","reports.wes.df.telemetry.microsoft.com","services.wes.df.telemetry.microsoft.com",
    "redir.metaservices.microsoft.com","choice.microsoft.com","statsfe2.ws.microsoft.com","statsfe1.ws.microsoft.com",
    "diagnostics.support.microsoft.com","feedback.windows.com","feedback.search.microsoft.com",
    "feedback.microsoft-hohm.com","corp.sts.microsoft.com","compatexchange.cloudapp.net",
]
# Lists large enough to bloat the hosts file to the point the Windows DNS Client
# (svchost) spikes CPU and resolution slows. Warn before importing these.
_LARGE_LISTS={"HaGezi Ultimate","OISD Full","StevenBlack Unified","HOSTShield Combined"}
LARGE_HOSTS_WARN=100_000  # hosts-file entry count above which we surface a CPU warning

# ─── Config ─────────────────────────────────────────────────────────────────
# Defined before the Theme section: _load_theme() runs at import time and
# reads the config — v3.7.0..v3.11.0 crashed at import (NameError) because
# load_cfg was defined further down the module.
def load_cfg():
    try:
        with open(CFG_PATH) as f: return json.load(f)
    except: return {}
def save_cfg(c):
    tmp=CFG_PATH+'.tmp'
    with open(tmp,'w') as f: json.dump(c,f,indent=2)
    os.replace(tmp,CFG_PATH)

# ─── Theme ──────────────────────────────────────────────────────────────────
_DARK={"bg":"#0b0d12","base":"#141821","mantle":"#10141c","crust":"#090b10","s0":"#242b38","s1":"#354052","s2":"#4a5870",
   "text":"#edf1f7","sub":"#b8c1d1","dim":"#8490a3","blue":"#77a7ff","green":"#8bd17c","red":"#ff7f9a","danger2":"#c84b69","danger_hover":"#ff9aac","on_danger":"#ffffff",
   "peach":"#ffb16c","yellow":"#e7c36f","mauve":"#c4a3ff","teal":"#66d9cf","sky":"#78d5ff","focus":"#a8c7ff",
   "sel":"rgba(119,167,255,0.16)","onsel":"#071019"}
_LIGHT={"bg":"#f4f7fb","base":"#ffffff","mantle":"#eef3f8","crust":"#e2e9f2","s0":"#cfd9e6","s1":"#b9c6d6","s2":"#93a4ba",
   "text":"#273142","sub":"#455368","dim":"#68778d","blue":"#1f68e5","green":"#207a36","red":"#c91d42","danger2":"#941332","danger_hover":"#a71435","on_danger":"#ffffff",
   "peach":"#c95c17","yellow":"#9a6700","mauve":"#7b3bd8","teal":"#087d79","sky":"#147bb6","focus":"#1f68e5",
   "sel":"rgba(31,104,229,0.12)","onsel":"#ffffff"}
_IS_LIGHT=load_cfg().get('theme')=='light'
def _load_theme():
    return dict(_LIGHT) if _IS_LIGHT else dict(_DARK)
C=_load_theme()
def _rgb(hexc):
    """'#rrggbb' -> 'r,g,b' for rgba() in stylesheets."""
    return ','.join(str(int(hexc.lstrip('#')[i:i+2],16)) for i in (0,2,4))

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
QPushButton{{background:{C['s0']};color:{C['sub']};border:1px solid {C['s1']};padding:7px 16px;border-radius:8px;font-weight:650;}}
QPushButton:hover{{background:{C['s1']};color:{C['text']};border-color:{C['s2']};}}
QPushButton:focus{{border:1px solid {C['focus']};color:{C['text']};}}
QPushButton:pressed{{background:{C['mantle']};padding-top:8px;padding-bottom:6px;}}
QPushButton:disabled{{color:{C['dim']};background:{C['mantle']};border-color:{C['s0']};}}
QPushButton[class="primary"]{{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 {C['blue']},stop:1 {C['teal']});color:{C['onsel']};border:1px solid rgba({_rgb(C['blue'])},0.55);font-weight:800;}}
QPushButton[class="primary"]:hover{{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 {C['sky']},stop:1 {C['teal']});}}
QPushButton[class="primary"]:focus{{border:1px solid {C['focus']};}}
QPushButton[class="danger"]{{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 {C['red']},stop:1 {C['danger2']});color:{C['on_danger']};border:1px solid rgba({_rgb(C['red'])},0.55);font-weight:800;}}
QPushButton[class="danger"]:hover{{background:{C['danger_hover']};}}
QPushButton[class="success"]{{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 {C['green']},stop:1 {C['teal']});color:{C['onsel']};border:1px solid rgba({_rgb(C['green'])},0.55);font-weight:800;}}
QPushButton[class="dim"]{{background:{C['s0']};color:{C['dim']};border:1px solid {C['s1']};}}
QPushButton[class="dim"]:hover{{color:{C['text']};background:{C['s1']};}}
QLineEdit,QTextEdit,QPlainTextEdit{{background:{C['mantle']};color:{C['text']};border:1px solid {C['s0']};border-radius:8px;padding:8px 12px;selection-background-color:{C['blue']};selection-color:{C['onsel']};}}
QLineEdit:hover,QTextEdit:hover,QPlainTextEdit:hover{{border-color:{C['s1']};}}
QLineEdit:focus,QTextEdit:focus,QPlainTextEdit:focus{{border-color:{C['focus']};background:{C['base']};}}
QComboBox{{background:{C['mantle']};color:{C['text']};border:1px solid {C['s0']};border-radius:8px;padding:7px 12px;min-width:80px;}}
QComboBox:hover{{border-color:{C['s1']};}}
QComboBox:focus{{border-color:{C['focus']};background:{C['base']};}}
QComboBox::drop-down{{border:none;width:24px;}}QComboBox::down-arrow{{image:none;border-left:4px solid transparent;border-right:4px solid transparent;border-top:5px solid {C['sub']};margin-right:8px;}}
QComboBox QAbstractItemView{{background:{C['base']};color:{C['text']};border:1px solid {C['s1']};selection-background-color:{C['sel']};selection-color:{C['text']};outline:none;border-radius:6px;padding:4px;}}
QTabWidget::pane{{border:none;background:{C['base']};}}
QTabBar{{background:{C['crust']};qproperty-drawBase:0;}}
QTabBar::tab{{background:transparent;color:{C['dim']};padding:12px 24px;border:none;border-bottom:2px solid transparent;font-weight:750;font-size:12px;}}
QTabBar::tab:selected{{color:{C['blue']};border-bottom-color:{C['blue']};background:rgba({_rgb(C['blue'])},0.08);}}
QTabBar::tab:hover:!selected{{color:{C['text']};}}
QTabBar::tab:focus{{color:{C['text']};border-bottom-color:{C['focus']};}}
QTabBar::tab:first{{margin-left:12px;}}
QTableWidget{{background:{C['mantle']};alternate-background-color:rgba({_rgb(C['base'])},0.42);color:{C['text']};border:1px solid {C['s0']};border-radius:10px;gridline-color:rgba({_rgb(C['s1'])},0.28);selection-background-color:{C['sel']};selection-color:{C['text']};outline:none;}}
QTableWidget::item{{padding:5px 10px;border:none;}}
QTableWidget::item:hover{{background:rgba({_rgb(C['blue'])},0.06);}}
QTableWidget::item:selected{{background:{C['sel']};}}
QHeaderView{{background:transparent;}}
QHeaderView::section{{background:{C['crust']};color:{C['sub']};border:none;border-bottom:1px solid {C['s0']};border-right:1px solid rgba({_rgb(C['s1'])},0.2);padding:8px 12px;font-weight:800;font-size:10px;text-transform:uppercase;letter-spacing:0.8px;}}
QScrollBar:vertical{{background:transparent;width:10px;margin:4px 1px;}}QScrollBar::handle:vertical{{background:{C['s1']};border-radius:4px;min-height:40px;}}
QScrollBar::handle:vertical:hover{{background:{C['s2']};}}QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}
QScrollBar:horizontal{{background:transparent;height:10px;margin:1px 4px;}}QScrollBar::handle:horizontal{{background:{C['s1']};border-radius:4px;}}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{{width:0;}}
QGroupBox{{border:1px solid {C['s0']};border-radius:12px;margin-top:1.5em;padding:16px 12px 12px;background:{C['mantle']};}}
QGroupBox::title{{subcontrol-origin:margin;left:14px;padding:0 8px;color:{C['blue']};font-size:11px;font-weight:800;background:{C['base']};}}
QProgressBar{{background:{C['s0']};border:none;border-radius:6px;text-align:center;color:#fff;font-weight:700;min-height:10px;}}
QProgressBar::chunk{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {C['blue']},stop:1 {C['teal']});border-radius:6px;}}
QCheckBox{{color:{C['text']};spacing:8px;}}
QCheckBox:hover{{color:{C['sub']};}}
QCheckBox:focus{{color:{C['text']};}}
QCheckBox::indicator{{width:18px;height:18px;border:2px solid {C['s1']};border-radius:4px;background:{C['mantle']};}}
QCheckBox::indicator:hover{{border-color:{C['focus']};}}
QCheckBox::indicator:checked{{background:{C['blue']};border-color:{C['blue']};}}
QToolTip{{background:{C['s0']};color:{C['text']};border:1px solid {C['s1']};padding:6px 10px;border-radius:8px;}}
QSplitter::handle{{background:{C['s0']};width:2px;}}QLabel{{color:{C['text']};background:transparent;}}
QScrollArea{{background:transparent;border:none;}}
QTableWidget:focus{{border:1px solid {C['blue']};}}
QMessageBox{{background:{C['base']};}}
QMessageBox QLabel{{color:{C['text']};font-size:12px;line-height:18px;}}
QMessageBox QPushButton{{min-width:86px;min-height:28px;}}
"""
CTX=f"QMenu{{background:{C['base']};color:{C['text']};border:1px solid {C['s1']};border-radius:10px;padding:6px;}}QMenu::item{{padding:8px 20px;border-radius:6px;}}QMenu::item:selected{{background:{C['sel']};color:{C['text']};}}QMenu::item:disabled{{color:{C['dim']};}}QMenu::separator{{height:1px;background:{C['s0']};margin:5px 8px;}}"

# ─── Thread-safe UI dispatch ────────────────────────────────────────────────
class _UiBridge(QObject):
    """QTimer.singleShot(0,...) from a plain threading.Thread never fires (no
    event dispatcher in that thread). Signals ARE thread-safe, so route
    callables through a queued signal onto the GUI thread instead."""
    call=Signal(object)
_ui_bridge=None
def _init_ui_bridge():
    global _ui_bridge
    _ui_bridge=_UiBridge()
    _ui_bridge.call.connect(lambda f:f(),Qt.QueuedConnection)
def ui_call(f):
    if _ui_bridge: _ui_bridge.call.emit(f)
    else: QTimer.singleShot(0,f)

def _post_webhook(event,data):
    """Best-effort JSON POST of an event to config['webhook_url'] (fire-and-forget).
    Used for blocked-domain and tamper alerts so external systems can react."""
    url=load_cfg().get('webhook_url','').strip()
    if not url or not url.startswith(('http://','https://')): return
    def _bg():
        try:
            body=json.dumps({'app':APP,'ver':VER,'event':event,'ts':datetime.datetime.now().isoformat(),**data}).encode()
            req=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json','User-Agent':f'HostsGuard/{VER}'})
            urllib.request.urlopen(req,timeout=5).close()
        except Exception as e: log.debug(f"webhook: {e}")
    threading.Thread(target=_bg,daemon=True).start()

_evt_src_ok=False
def _evt_log(msg,level='Warning'):
    """Write structured event to Windows Application event log."""
    global _evt_src_ok
    if sys.platform!='win32': return
    try:
        evt_json=json.dumps({'app':APP,'ver':VER,'ts':datetime.datetime.now().isoformat(),'msg':msg},ensure_ascii=False)
        esc_msg="'"+evt_json.replace("'","''")+"'"
        esc_src="'"+APP.replace("'","''")+"'"
        # Write-EventLog fails silently if the source was never registered — create it once.
        pre="" if _evt_src_ok else f"try{{if(-not [System.Diagnostics.EventLog]::SourceExists({esc_src})){{New-EventLog -LogName Application -Source {esc_src}}}}}catch{{}};"
        cmd=pre+f"Write-EventLog -LogName Application -Source {esc_src} -EventId 1000 -EntryType {level} -Message {esc_msg}"
        subprocess.run(['powershell','-NoProfile','-Command',cmd],capture_output=True,timeout=5,creationflags=NOWIN)
        _evt_src_ok=True
    except Exception: pass

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
    hdr=set(WINDOWS_HEADER)
    for l in lines:
        st['total']+=1; s=l.strip()
        if not s or s.startswith('#'):
            # Strip line endings so output joins cleanly; drop stale copies of the
            # Windows header and old managed-by markers so repeated cleans are idempotent.
            c=l.rstrip('\r\n')
            if c.strip() and c not in hdr and f'managed by {APP}' not in c: kept.append(c)
            continue
        n=norm_line(s)
        if not n: st['invalid']+=1; continue
        d=n.split()[-1]
        if d in wl: st['whitelist']+=1; continue
        if d in seen: st['dupes']+=1; continue
        seen.add(d); kept.append(n); st['active']+=1
    header=WINDOWS_HEADER+[f"# --- {len(seen)} entries managed by {APP} v{VER} ---"]
    return header+kept,st
def categorize(host,port=0):
    h=host.lower() if host else ""
    # Placeholder hosts ('-' = unresolved) are NOT LAN — public connections without
    # reverse DNS were all mislabeled LAN. Fall through to port classification.
    if h and h not in ('-','*','...'):
        for cat,kws in _CAT.items():
            for kw in kws:
                if kw in h: return cat
        if PRIV_RE.match(h): return 'LAN'
    p=int(port) if port else 0
    if p in (80,443,8080,8443): return 'Web'
    if p==53: return 'DNS'
    if p in (25,110,143,993,995,587): return 'Email'
    return ''
_WEEKDAYS=["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
def _in_window(now_hhmm,start,end):
    """True if HH:MM `now` falls in [start,end). Handles overnight windows (end<=start)."""
    if start==end: return False
    if start<end: return start<=now_hhmm<end
    return now_hhmm>=start or now_hhmm<end
def open_research(d):
    r=get_root(d); m=QMenu(); m.setStyleSheet(CTX)
    for name,url in RESEARCH: a=m.addAction(f"  {name}"); a.setData(url.replace('{d}',r))
    m.addSeparator(); a2=m.addAction(f"  VirusTotal (exact)"); a2.setData(f"https://www.virustotal.com/gui/domain/{d}")
    ch=m.exec_(QCursor.pos())
    if ch and ch.data(): webbrowser.open(ch.data())
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
dns_c=LRU(); who_c=LRU(); geo_c=LRU(); proc_c=LRU(2000); sig_c=LRU(500)
_threat_ips=set(); _threat_domains=set(); _threat_lock=Lock()
THREAT_FEEDS=[
    ("URLhaus","https://urlhaus.abuse.ch/downloads/hostfile/"),
    ("Feodo","https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
]
def _load_threat_intel():
    global _threat_ips,_threat_domains
    ips=set(); doms=set()
    for name,url in THREAT_FEEDS:
        try:
            req=urllib.request.Request(url,headers={'User-Agent':f'HostsGuard/{VER}'})
            with urllib.request.urlopen(req,timeout=30) as resp:
                for line in resp.read().decode('utf-8',errors='replace').splitlines():
                    line=line.strip()
                    if not line or line.startswith('#'): continue
                    parts=line.split()
                    if len(parts)>=2 and parts[0] in ('0.0.0.0','127.0.0.1'):
                        doms.add(parts[1].lower())
                    elif IPV4_RE.match(line): ips.add(line)
        except Exception as e: log.warning(f"Threat feed {name}: {e}")
    with _threat_lock: _threat_ips=ips; _threat_domains=doms
    log.info(f"Threat intel loaded: {len(ips)} IPs, {len(doms)} domains")

# ─── Data Structures ───────────────────────────────────────────────────────
@dataclass
class CI:
    key:str="";ts:str="";src:str="";dir:str="";proto:str=""
    la:str="";lp:str="";ra:str="";rp:str=""
    host:str="-";proc:str="?";pid:int=0;state:str=""
    path:str="";org:str="-";stat:str="-";country:str="-";cc:str="";category:str="";sig:str="";ppid:int=0;pproc:str=""
@dataclass
class FWR:
    name:str="";direction:str="Out";action:str="Block";enabled:bool=True
    remote_addr:str="Any";protocol:str="Any";program:str="";source:str="system"

# ─── FaviconCache ───────────────────────────────────────────────────────────
class FaviconCache(QObject):
    ready=Signal(str)
    _img_ready=Signal(str,bytes)
    def __init__(s):
        super().__init__(); s._mem={}; s._pending=set(); s._lock=Lock()
        s._img_ready.connect(s._on_img)
    def _on_img(s,domain,data):
        px=QPixmap(); px.loadFromData(data)
        with s._lock: s._mem[domain]=px  # null pixmap = negative cache, stops refetch loops
        s.ready.emit(domain)
    def get(s,domain):
        with s._lock:
            if domain in s._mem: return s._mem[domain]
        h=hashlib.md5(domain.encode()).hexdigest(); p=os.path.join(FAV_DIR,f"{h}.png")
        if os.path.exists(p):
            px=QPixmap(p)
            with s._lock: s._mem[domain]=px
            return px if not px.isNull() else None
        with s._lock:
            if domain not in s._pending: s._pending.add(domain); threading.Thread(target=s._fetch,args=(domain,h,p),daemon=True).start()
        return None
    def _fetch(s,domain,h,p):
        got=False
        try:
            r=get_root(domain)
            url=f"https://{r}/favicon.ico"
            req=urllib.request.Request(url,headers={'User-Agent':f'HostsGuard/{VER}'})
            with urllib.request.urlopen(req,timeout=5) as resp:
                data=resp.read()
                if len(data)>100:
                    with open(p,'wb') as f: f.write(data)
                    s._img_ready.emit(domain,data); got=True
        except Exception as e: log.debug(f"Favicon {domain}: {e}")
        finally:
            with s._lock:
                s._pending.discard(domain)
                # Negative-cache failures (blocked/offline domains) — every table
                # refresh used to spawn a fresh fetch thread per unfetchable domain.
                if not got: s._mem.setdefault(domain,QPixmap())
_fav=None
def _init_fav():
    global _fav
    if not _fav: _fav=FaviconCache()

# ─── Database (with schema versioning) ─────────────────────────────────────
class DB:
    def __init__(s):
        s.conn=sqlite3.connect(DB_PATH,check_same_thread=False); s.conn.execute("PRAGMA journal_mode=WAL")
        s.conn.execute("PRAGMA busy_timeout=5000"); s._lock=Lock()
        try:
            r=s.conn.execute("PRAGMA integrity_check").fetchone()
            if r and r[0]!='ok': log.warning(f"DB integrity issue: {r[0]}")
        except Exception as e: log.warning(f"DB integrity check failed: {e}")
        s._migrate(); s._blocked_cache=None; s._blocked_ts=0
    def _rename_legacy(s):
        """Pre-versioning DBs used date_added/date_modified/hit_count (domains) and
        timestamp/process_name (log). CREATE TABLE IF NOT EXISTS silently kept those
        shapes while schema_version was stamped current, so every domains/log query
        failed and returned empty. Rename in place — data is preserved."""
        def cols(t):
            try: return {r[1] for r in s.conn.execute(f"PRAGMA table_info({t})").fetchall()}
            except Exception: return set()
        renames={'domains':(('date_added','added'),('date_modified','modified'),('hit_count','hits')),
                 'log':(('timestamp','ts'),('process_name','process'))}
        for table,pairs in renames.items():
            have=cols(table)
            if not have: continue
            for old,new in pairs:
                if old in have and new not in have:
                    try: s.conn.execute(f'ALTER TABLE {table} RENAME COLUMN "{old}" TO "{new}"')
                    except Exception as e: log.warning(f"Legacy rename {table}.{old}: {e}")
        try: s.conn.execute("CREATE INDEX IF NOT EXISTS idx_log_ts ON log(ts)")
        except Exception: pass
        s.conn.commit()
    def _migrate(s):
        s.conn.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT)")
        s._rename_legacy()
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
        if v<5:
            s.conn.execute("CREATE TABLE IF NOT EXISTS proc_rules(id INTEGER PRIMARY KEY,process TEXT,domain TEXT,action TEXT DEFAULT 'block',added TEXT)")
            s.conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_proc_rules ON proc_rules(process,domain)")
        if v<6:
            s.conn.execute("CREATE TABLE IF NOT EXISTS profiles(name TEXT PRIMARY KEY,created TEXT)")
            s.conn.execute("CREATE TABLE IF NOT EXISTS profile_rules(id INTEGER PRIMARY KEY,profile TEXT,domain TEXT,status TEXT DEFAULT 'blocked',source TEXT)")
            s.conn.execute("INSERT OR IGNORE INTO profiles(name,created)VALUES('Default',?)",(datetime.datetime.now().isoformat(),))
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
        # UPSERT that preserves original added-date, hits, notes, and existing
        # category — the old INSERT OR REPLACE reset added and wiped notes/category
        # on every re-block.
        s._x("""INSERT INTO domains(domain,status,category,source,added,modified,hits)VALUES(?,?,?,?,?,?,0)
                ON CONFLICT(domain) DO UPDATE SET status=excluded.status,modified=excluded.modified,
                source=CASE WHEN excluded.source!='' THEN excluded.source ELSE domains.source END,
                category=CASE WHEN excluded.category!='' THEN excluded.category ELSE domains.category END""",
              (d,status,cat,source,now,now))
        s._blocked_cache=None
    def add_domains_bulk(s,rows):
        """Bulk UPSERT (domain,status,source) tuples in ONE transaction. Blocklist
        imports of 100k+ domains previously committed once per domain. A
        whitelisted domain is NOT downgraded to blocked by a bulk block import, so
        allowlist entries win over blocklists."""
        if not rows: return 0
        now=datetime.datetime.now().isoformat()
        with s._lock:
            try:
                s.conn.executemany(
                    """INSERT INTO domains(domain,status,category,source,added,modified,hits)VALUES(?,?,'',?,?,?,0)
                       ON CONFLICT(domain) DO UPDATE SET
                       status=CASE WHEN domains.status='whitelisted' AND excluded.status='blocked' THEN 'whitelisted' ELSE excluded.status END,
                       modified=excluded.modified,
                       source=CASE WHEN excluded.source!='' THEN excluded.source ELSE domains.source END""",
                    [(d,st,src,now,now) for d,st,src in rows])
                s.conn.commit()
            except Exception as e: log.warning(f"add_domains_bulk: {e}"); return 0
        s._blocked_cache=None
        return len(rows)
    def get_domains(s,status=None,search=None,source=None):
        q="SELECT domain,status,category,source,added,modified,hits,notes FROM domains WHERE 1=1"
        p=[]
        if status: q+=" AND status=?"; p.append(status)
        if source: q+=" AND source=?"; p.append(source)
        if search: q+=" AND domain LIKE ?"; p.append(f"%{search}%")
        return s._q(q+" ORDER BY modified DESC",p)
    def get_sources(s):
        return [r[0] for r in s._q("SELECT DISTINCT source FROM domains WHERE source!='' ORDER BY source")]
    def toggle_source(s,source,new_status):
        now=datetime.datetime.now().isoformat()
        s._x("UPDATE domains SET status=?,modified=? WHERE source=?",(new_status,now,source))
        s._blocked_cache=None
    def remove_domain(s,d): s._x("DELETE FROM domains WHERE domain=?",((d,))); s._blocked_cache=None
    def update_status(s,d,st):
        s._x("UPDATE domains SET status=?,modified=? WHERE domain=?",(st,datetime.datetime.now().isoformat(),d))
        s._blocked_cache=None
    def add_root(s,d,status,source):
        root=get_root(d); now=datetime.datetime.now().isoformat()
        with s._lock:
            try:
                rows=s.conn.execute("SELECT domain FROM feed WHERE domain=? OR domain LIKE ?",(root,f"%.{root}")).fetchall()
                for r in rows:
                    s.conn.execute("INSERT OR REPLACE INTO domains(domain,status,category,source,added,modified,hits)VALUES(?,?,?,?,?,?,COALESCE((SELECT hits FROM domains WHERE domain=?),0))",(r[0],status,'',source,now,now,r[0]))
                s.conn.execute("INSERT OR REPLACE INTO domains(domain,status,category,source,added,modified,hits)VALUES(?,?,?,?,?,?,COALESCE((SELECT hits FROM domains WHERE domain=?),0))",(root,status,'',source,now,now,root))
                s.conn.commit(); s._blocked_cache=None
            except Exception as e: log.warning(f"add_root: {e}"); return 0
        return len(rows)+1
    def get_blocked_set(s):
        now=time.time()
        with s._lock:
            # 'is not None' — an empty blocked set is valid and cacheable; the old
            # truthiness test re-ran this per-connection query on all-allowed setups.
            if s._blocked_cache is not None and now-s._blocked_ts<5: return s._blocked_cache
            s._blocked_cache={r[0] for r in s.conn.execute("SELECT domain FROM domains WHERE status='blocked'").fetchall()}
            s._blocked_ts=now; return s._blocked_cache
    def close(s):
        try:
            with s._lock: s.conn.close()
        except Exception: pass
    # Per-process rules
    def add_proc_rule(s,process,domain,action='block'):
        now=datetime.datetime.now().isoformat()
        s._x("INSERT OR REPLACE INTO proc_rules(process,domain,action,added)VALUES(?,?,?,?)",(process.lower(),domain.lower(),action,now))
    def get_proc_rules(s,process=None):
        if process: return s._q("SELECT process,domain,action FROM proc_rules WHERE process=?",(process.lower(),))
        return s._q("SELECT process,domain,action FROM proc_rules ORDER BY process,domain")
    def remove_proc_rule(s,process,domain):
        s._x("DELETE FROM proc_rules WHERE process=? AND domain=?",(process.lower(),domain.lower()))
    def check_proc_rule(s,process,domain):
        r=s._q("SELECT action FROM proc_rules WHERE process=? AND domain=?",(process.lower(),domain.lower()))
        return r[0][0] if r else None
    # Profiles
    def get_profiles(s): return [r[0] for r in s._q("SELECT name FROM profiles ORDER BY name")]
    def create_profile(s,name):
        s._x("INSERT OR IGNORE INTO profiles(name,created)VALUES(?,?)",(name,datetime.datetime.now().isoformat()))
    def delete_profile(s,name):
        if name=='Default': return
        s._x("DELETE FROM profile_rules WHERE profile=?",(name,))
        s._x("DELETE FROM profiles WHERE name=?",(name,))
    def save_profile_snapshot(s,name):
        """Save current domains table state as a profile snapshot."""
        s._x("DELETE FROM profile_rules WHERE profile=?",(name,))
        rows=s._q("SELECT domain,status,source FROM domains")
        s._x("INSERT INTO profile_rules(profile,domain,status,source)VALUES(?,?,?,?)",
            [(name,r[0],r[1],r[2]) for r in rows],many=True)
    def load_profile(s,name):
        """Restore domains table from a profile snapshot. An empty snapshot is a
        valid profile (block nothing) — it must still clear the domains table, or
        switching to it silently leaves the previous profile applied."""
        rows=s._q("SELECT domain,status,source FROM profile_rules WHERE profile=?",(name,))
        now=datetime.datetime.now().isoformat()
        with s._lock:
            s.conn.execute("DELETE FROM domains")
            if rows:
                s.conn.executemany("INSERT INTO domains(domain,status,source,added,modified,hits)VALUES(?,?,?,?,?,0)",
                    [(r[0],r[1],r[2] or '',now,now) for r in rows])
            s.conn.commit()
        s._blocked_cache=None; return len(rows)
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
    def feed_upsert_batch(s,domains):
        """Upsert a whole DNS-cache scan in ONE transaction (a scan can carry
        hundreds of entries; per-domain commits caused constant WAL fsync churn).
        Returns the list of brand-new, non-hidden domains."""
        if not domains: return []
        now=datetime.datetime.now().isoformat(); new=[]
        with s._lock:
            try:
                hidden_roots={r[0] for r in s.conn.execute("SELECT root FROM hidden_roots").fetchall()}
                for d in domains:
                    r=s.conn.execute("SELECT hidden FROM feed WHERE domain=?",(d,)).fetchone()
                    if r:
                        if r[0]==1: continue
                        s.conn.execute("UPDATE feed SET last_seen=?,hits=hits+1 WHERE domain=?",(now,d))
                    elif get_root(d) in hidden_roots:
                        s.conn.execute("INSERT INTO feed(domain,first_seen,last_seen,hits,process,hidden)VALUES(?,?,?,1,'',1)",(d,now,now))
                    else:
                        s.conn.execute("INSERT INTO feed(domain,first_seen,last_seen,hits,process)VALUES(?,?,?,1,'')",(d,now,now))
                        new.append(d)
                s.conn.commit()
            except Exception as e: log.warning(f"feed_upsert_batch: {e}")
        return new
    def feed_get(s,search=None,show_hidden=False,status_filter=None):
        q="""SELECT f.domain,f.first_seen,f.last_seen,f.hits,f.process,f.hidden,
            COALESCE(d.status,'unmanaged'),d.source FROM feed f LEFT JOIN domains d ON f.domain=d.domain WHERE 1=1"""
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
        root=get_root(d); s._x("UPDATE feed SET hidden=1 WHERE domain=? OR domain LIKE ?",(root,f"%.{root}"))
        now=datetime.datetime.now().isoformat()
        s._x("INSERT OR IGNORE INTO hidden_roots(root,added)VALUES(?,?)",(root,now))
    def feed_unhide_root(s,d):
        root=get_root(d); s._x("UPDATE feed SET hidden=0 WHERE domain=? OR domain LIKE ?",(root,f"%.{root}"))
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
        p.append(limit); return s._q(q+" ORDER BY ts DESC LIMIT ?",p)
    def clear_log(s): s._x("DELETE FROM log")
    def prune_log(s,keep=20000):
        s._x("DELETE FROM log WHERE id NOT IN (SELECT id FROM log ORDER BY id DESC LIMIT ?)",(keep,))
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
        try:
            r=s.conn.execute("PRAGMA integrity_check").fetchone()
            if r and r[0]!='ok': log.warning(f"ConnDB integrity issue: {r[0]}")
        except Exception as e: log.warning(f"ConnDB integrity check failed: {e}")
        s.conn.execute("""CREATE TABLE IF NOT EXISTS conns(id INTEGER PRIMARY KEY,ts TEXT,proto TEXT,la TEXT,lp TEXT,
            ra TEXT,rp TEXT,host TEXT,proc TEXT,pid INTEGER,state TEXT,org TEXT,country TEXT,cc TEXT,category TEXT,
            UNIQUE(ts,proto,la,lp,ra,rp,pid))""")
        s.conn.execute("CREATE INDEX IF NOT EXISTS idx_cts ON conns(ts)"); s.conn.commit()
    def insert_batch(s,conns):
        with s._lock:
            for c in conns:
                try: s.conn.execute("INSERT OR IGNORE INTO conns(ts,proto,la,lp,ra,rp,host,proc,pid,state,org,country,cc,category)VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (c.ts,c.proto,c.la,c.lp,c.ra,c.rp,c.host,c.proc,c.pid,c.state,c.org,c.country,c.cc,c.category))
                except Exception as e: log.debug(f"ConnDB insert: {e}")
            try: s.conn.commit()
            except Exception as e: log.warning(f"ConnDB commit: {e}")
    def search(s,q='',limit=500,offset=0):
        with s._lock:
            sql="SELECT ts,proto,la,lp,ra,rp,host,proc,pid,state,org,country,cc,category FROM conns"
            p=[]
            if q: sql+=" WHERE host LIKE ? OR proc LIKE ? OR ra LIKE ?"; p=[f"%{q}%"]*3
            return s.conn.execute(sql+" ORDER BY ts DESC LIMIT ? OFFSET ?",[*p,limit,offset]).fetchall()
    def prune(s,days=30):
        cut=(datetime.datetime.now()-datetime.timedelta(days=days)).isoformat()
        with s._lock: s.conn.execute("DELETE FROM conns WHERE ts<?",(cut,)); s.conn.commit()
    def count(s):
        with s._lock:
            try: return s.conn.execute("SELECT COUNT(*) FROM conns").fetchone()[0]
            except Exception: return 0
    def close(s):
        try:
            with s._lock: s.conn.close()
        except Exception: pass


# ─── Firewall Engine ────────────────────────────────────────────────────────

# ─── Persistent PowerShell Session ──────────────────────────────────────────
class PersistentPS:
    """Keep a single PowerShell process alive — send commands via stdin, read stdout.
    Eliminates ~200ms process-spawn overhead per command."""
    def __init__(s):
        s._proc=None; s._lock=Lock(); s._alive=False
    def _ensure(s):
        if s._alive and s._proc and s._proc.poll() is None: return True
        try:
            s._proc=subprocess.Popen(
                ['powershell','-NoProfile','-NoLogo','-NonInteractive','-Command','-'],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                text=True,creationflags=NOWIN,bufsize=1)
            s._alive=True; return True
        except Exception as e: log.warning(f"PS session start failed: {e}"); s._alive=False; return False
    def run(s,cmd,timeout=20):
        delim=f"---HG_END_{uuid.uuid4().hex[:8]}---"
        with s._lock:
            if not s._ensure(): return False,""
            try:
                full=f"{cmd}\nWrite-Output '{delim}'\n"
                s._proc.stdin.write(full); s._proc.stdin.flush()
                lines=[]; matched=False; result=[None]
                def _reader():
                    try:
                        while True:
                            line=s._proc.stdout.readline()
                            if not line: break
                            line=line.rstrip('\n\r')
                            if line==delim: result[0]=True; break
                            lines.append(line)
                    except Exception: pass
                t=threading.Thread(target=_reader,daemon=True); t.start(); t.join(timeout)
                if result[0]:
                    return True,'\n'.join(lines)
                s._alive=False
                try: s._proc.kill()
                except OSError: pass
                return False,'\n'.join(lines)
            except Exception as e:
                log.debug(f"PS run failed: {e}"); s._alive=False; return False,""
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

def _ps_esc(v):
    """Escape a value for safe PowerShell single-quote interpolation."""
    return "'" + str(v).replace("'","''") + "'"

def _system_dns_servers():
    """The IPs currently configured as the machine's DNS resolvers — exempted from
    DoH blocking so the user's own encrypted-DNS choice keeps working."""
    ok,out=_ps("(Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 -EA SilentlyContinue|"
               "Select-Object -ExpandProperty ServerAddresses) -join ','",8)
    if ok and out:
        return {x.strip() for x in out.split(',') if x.strip()}
    return set()

def valid_fw_addr(v):
    """Accept the address forms New-NetFirewallRule takes: single IP, CIDR subnet,
    or dash range. The Block IP dialogs advertise ranges but block_ip previously
    rejected everything except a bare IP."""
    v=(v or "").strip()
    if not v: return False
    try:
        if '/' in v: ipaddress.ip_network(v,strict=False); return True
        if '-' in v:
            a,b=v.split('-',1); ipaddress.ip_address(a.strip()); ipaddress.ip_address(b.strip()); return True
        ipaddress.ip_address(v); return True
    except ValueError: return False

def _parse_fw_rules(text):
    """Parse the Get-NetFirewallRule JSON dump into FWR records (shared by the
    engine and the background loader — previously duplicated)."""
    rules=[]
    if not text: return rules
    try:
        data=json.loads(text)
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
            except Exception: continue
    except Exception as e: log.warning(f"FW parse: {e}")
    return rules
_FW_DUMP_CMD=('Get-NetFirewallRule -EA SilentlyContinue|ForEach-Object{$af=$_|Get-NetFirewallAddressFilter -EA SilentlyContinue;$pf=$_|Get-NetFirewallPortFilter -EA SilentlyContinue;$ap=$_|Get-NetFirewallApplicationFilter -EA SilentlyContinue;'
    '[PSCustomObject]@{N=$_.DisplayName;Dir=[int]$_.Direction;Act=[int]$_.Action;En=[int]$_.Enabled;RA=$af.RemoteAddress;Proto=$pf.Protocol;Prog=$ap.Program}}|ConvertTo-Json -Compress')

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
        ok,out=_ps(f'(Get-NetFirewallRule -DisplayName {_ps_esc(name)} -EA SilentlyContinue) -ne $null',8)
        return ok and out.strip().lower()=="true"
    def create(s,name,direction="Outbound",action="Block",remote_addr="",protocol="",program="",desc=""):
        if direction not in ("Outbound","Inbound"): direction="Outbound"
        if action not in ("Block","Allow"): action="Block"
        p=[f'New-NetFirewallRule -DisplayName {_ps_esc(name)} -Direction {direction} -Action {action} -Enabled True -Profile Any']
        if remote_addr and remote_addr not in ("*","Any"): p.append(f'-RemoteAddress {_ps_esc(remote_addr)}')
        if protocol and protocol not in ("","Any"): p.append(f'-Protocol {_ps_esc(protocol)}')
        if program: p.append(f'-Program {_ps_esc(program)}')
        if desc: p.append(f'-Description {_ps_esc(desc)}')
        ok,_=_ps(' '.join(p),15); s._inv()
        if ok: s._track(name,direction,action,remote_addr,protocol,program)
        return ok
    def delete(s,name): ok,_=_ps(f'Remove-NetFirewallRule -DisplayName {_ps_esc(name)} -EA SilentlyContinue',10); s._inv(); s._untrack(name); return ok
    def enable(s,name,on=True): _ps(f'{"Enable" if on else "Disable"}-NetFirewallRule -DisplayName {_ps_esc(name)} -EA SilentlyContinue',10); s._inv()
    def set_action(s,name,action):
        if action not in ("Block","Allow"): return
        _ps(f'Set-NetFirewallRule -DisplayName {_ps_esc(name)} -Action {action} -EA SilentlyContinue',10); s._inv()
    def block_ip(s,ip,direction="Outbound"):
        ip=ip.strip()
        if not valid_fw_addr(ip): log.warning(f"Invalid address for FW rule: {ip}"); return None
        safe=re.sub(r'[^0-9A-Za-z]','_',ip)
        name=f"{FW_PFX}Block_{safe}_{direction[:2]}"
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
    # ── Encrypted-DNS (DoH/DoT/DoQ) blocking ──────────────────────────────────
    DOH_RULES=("HG_DoH_IPs","HG_DoT_TCP","HG_DoT_UDP")
    def block_doh(s,exempt=None):
        """Block known DoH resolver IPs and DoT/DoQ port 853 outbound so apps and
        browsers can't tunnel DNS past hosts-file blocking. `exempt` (the user's own
        configured resolver IPs) is never blocked so their chosen DNS keeps working."""
        exempt={str(e).strip() for e in (exempt or set())}
        ips=[ip for ip in sorted(DOH_IPS) if ip not in exempt]
        created=[]
        if ips:
            addr=",".join(_ps_esc(ip) for ip in ips)  # PowerShell string array: 'a','b',...
            ok,_=_ps(f"New-NetFirewallRule -DisplayName {_ps_esc('HG_DoH_IPs')} -Direction Outbound "
                     f"-Action Block -Enabled True -Profile Any -RemoteAddress {addr} "
                     f"-Description {_ps_esc('HostsGuard: block DoH resolver IPs')}",20)
            if ok: s._track('HG_DoH_IPs','Out','Block',','.join(ips)); created.append('HG_DoH_IPs')
        for proto,name in (("TCP","HG_DoT_TCP"),("UDP","HG_DoT_UDP")):
            ok,_=_ps(f"New-NetFirewallRule -DisplayName {_ps_esc(name)} -Direction Outbound "
                     f"-Action Block -Enabled True -Profile Any -Protocol {proto} -RemotePort 853 "
                     f"-Description {_ps_esc('HostsGuard: block DoT/DoQ (port 853)')}",15)
            if ok: s._track(name,'Out','Block',protocol=proto); created.append(name)
        s._inv()
        return created
    def unblock_doh(s):
        for name in s.DOH_RULES:
            _ps(f"Remove-NetFirewallRule -DisplayName {_ps_esc(name)} -EA SilentlyContinue",10)
            s._untrack(name)
        s._inv()
    def doh_blocked(s):
        """True if the DoH IP block rule currently exists."""
        return s.exists('HG_DoH_IPs')
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
        ok,out=_ps(_FW_DUMP_CMD,120)
        rules=_parse_fw_rules(out) if ok else []
        with s._lock: s._cache=rules; s._ts=time.time()
        s._loading=False; return rules
    def get_cached(s):
        with s._lock: return list(s._cache)
    def set_cache(s,rules):
        with s._lock: s._cache=rules; s._ts=time.time()
        s._loading=False
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
        s._blocked=set(); s._lines=[]; s._lock=threading.RLock()
        s._self_hashes={}  # sha512 digest -> True for content we wrote ourselves
        s.read()
    def _record_self(s,content):
        """Remember the hash of content we wrote so the tamper watcher can tell
        our own writes apart from external modifications."""
        h=hashlib.sha512(content.encode('utf-8') if isinstance(content,str) else content).digest()
        with s._lock:
            s._self_hashes[h]=True
            while len(s._self_hashes)>16: del s._self_hashes[next(iter(s._self_hashes))]
    def is_self_change(s,h):
        """Consume a pending self-write hash. Returns True if h matches content this
        process wrote (i.e. the watcher-detected change was not external tampering)."""
        if not h: return False
        with s._lock:
            if h in s._self_hashes: del s._self_hashes[h]; return True
        return False
    def _atomic_write(s,content):
        """Write hosts file via temp-file + os.replace() to prevent TOCTOU data loss."""
        hosts_dir=os.path.dirname(HOSTS_PATH)
        fd,tmp=tempfile.mkstemp(dir=hosts_dir,prefix='hosts_',suffix='.tmp')
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(content)
            # Hash the on-disk bytes (text mode translates \n -> \r\n on Windows,
            # so hashing the in-memory string would never match the watcher's hash).
            with open(tmp,'rb') as f: s._record_self(f.read())
            os.replace(tmp,HOSTS_PATH)
        except:
            try: os.unlink(tmp)
            except OSError: pass
            raise
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
        if not looks_like_domain(d): return False
        with s._lock:
            if d in s._blocked: return False
            try:
                new_lines=list(s._lines)+[f"0.0.0.0 {d}\n"]
                s._atomic_write(''.join(new_lines))
                s._blocked.add(d); s._lines=new_lines
            except Exception as e: log.warning(f"Hosts block {d}: {e}"); return False
        if flush: s._flush()
        return True
    def block_bulk(s,domains,flush=True):
        with s._lock:
            new=[d.lower().strip() for d in domains if d.lower().strip() not in s._blocked and looks_like_domain(d.lower().strip())]
            if not new: return 0
            try:
                new_lines=list(s._lines)+[f"0.0.0.0 {d}\n" for d in new]
                s._atomic_write(''.join(new_lines))
                for d in new: s._blocked.add(d)
                s._lines=new_lines
            except Exception as e: log.warning(f"Hosts block_bulk: {e}"); return 0
        if flush: s._flush()
        return len(new)
    def reconcile(s,target_blocked,flush=True):
        """Rewrite the hosts file so exactly `target_blocked` are 0.0.0.0-blocked,
        preserving all comment/non-0.0.0.0 lines. Used when switching profiles so
        domains dropped by the new profile are actually unblocked (not just left in
        place). Returns (added, removed)."""
        target={d.lower().strip() for d in target_blocked if looks_like_domain(d.lower().strip())}
        with s._lock:
            kept=[]; present=set()
            for l in s._lines:
                line=l.strip()
                if not line or line.startswith('#'): kept.append(l); continue
                parts=line.split()
                if len(parts)>=2 and parts[0] in ('0.0.0.0','127.0.0.1','::','::1'):
                    d=parts[1].lower().rstrip('.')
                    if looks_like_domain(d):
                        if d in target: present.add(d); kept.append(l)  # keep wanted block
                        # else: drop — domain no longer blocked by active profile
                        continue
                kept.append(l)
            additions=[f"0.0.0.0 {d}\n" for d in sorted(target-present)]
            new_lines=kept+additions
            try:
                s._atomic_write(''.join(new_lines))
                s.read()
            except Exception as e: log.warning(f"Hosts reconcile: {e}"); return 0,0
        if flush: s._flush()
        return len(additions),len(target)  # (newly added, total target)
    def unblock(s,d,flush=True):
        d=d.lower().strip()
        with s._lock:
            new=[]
            for l in s._lines:
                line=l.strip()
                if not line or line.startswith('#'):
                    new.append(l); continue
                parts=line.split()
                if len(parts)>=2 and d in [p.lower().strip() for p in parts[1:]]:
                    continue
                new.append(l)
            try:
                s._atomic_write(''.join(new))
                s._blocked.discard(d); s._lines=new
            except Exception as e: log.warning(f"Hosts unblock {d}: {e}"); return False
        if flush: s._flush()
        return True
    def save_raw(s,text):
        s.backup()
        with s._lock:
            try:
                s._atomic_write(text)
                s.read()
            except Exception as e: return str(e)
        s._flush(); return None
    def save_clean(s,wl=None):
        with s._lock:
            try:
                cleaned,stats=clean_hosts(list(s._lines),wl)
                s._atomic_write('\n'.join(cleaned)+'\n')
                s.read()
            except Exception as e: return None,str(e)
        s._flush(); return stats,None
    def backup(s):
        ts=datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        dst=os.path.join(CONFIG_DIR,"backups",f"hosts_{ts}.bak")
        try: shutil.copy2(HOSTS_PATH,dst); return dst
        except Exception as e: log.warning(f"Hosts backup failed: {e}"); return None
    def restore(s,path=None):
        if not path:
            bk=sorted(Path(os.path.join(CONFIG_DIR,"backups")).glob("hosts_*.bak"))
            if not bk: return False
            path=str(bk[-1])
        with s._lock:
            try:
                with open(path,'rb') as f: s._record_self(f.read())
                shutil.copy2(path,HOSTS_PATH)
                s.read()
            except Exception as e: log.warning(f"Hosts restore failed: {e}"); return False
        s._flush(); return True
    def _flush(s):
        if sys.platform=='win32': subprocess.Popen(['ipconfig','/flushdns'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=NOWIN)
    def emergency_unlock(s):
        s.backup()
        with s._lock:
            try:
                s._atomic_write('\n'.join(WINDOWS_HEADER)+'\n')
                s.read()
            except Exception as e: log.warning(f"Emergency reset failed: {e}"); return False
        s._flush(); return True

# ─── Bandwidth ──────────────────────────────────────────────────────────────
class BWTracker:
    def __init__(s): io=psutil.net_io_counters(); s._s,s._r,s._t=io.bytes_sent,io.bytes_recv,time.time(); s._us,s._ds=0,0; s._lock=Lock()
    def update(s):
        io=psutil.net_io_counters(); n=time.time(); dt=max(n-s._t,0.1)
        with s._lock:
            s._us=(io.bytes_sent-s._s)/dt; s._ds=(io.bytes_recv-s._r)/dt
            s._s,s._r,s._t=io.bytes_sent,io.bytes_recv,n
    def rates(s):
        with s._lock: return s._us,s._ds
    @staticmethod
    def fmt(r):
        if r<1024: return f"{r:.0f} B/s"
        if r<1048576: return f"{r/1024:.1f} KB/s"
        return f"{r/1048576:.1f} MB/s"
bw=BWTracker()

# ─── Workers ────────────────────────────────────────────────────────────────
class DNSResolveWorker(QThread):
    resolved=Signal(str,str)
    def __init__(s): super().__init__(); s._q=Queue(); s._stop=TEvent()
    def add(s,ip):
        if ip not in dns_c: s._q.put(ip)
    def run(s):
        while not s._stop.is_set():
            try:
                ip=s._q.get(timeout=1)
                if ip in dns_c: continue
                try: host=socket.gethostbyaddr(ip)[0]; dns_c.put(ip,host); s.resolved.emit(ip,host)
                except (socket.herror,socket.gaierror,OSError): dns_c.put(ip,'')
            except Empty: pass
    def stop(s): s._stop.set()

GEOIP_PATH=os.path.join(CONFIG_DIR,"geoip.mmdb")
GEOASN_PATH=os.path.join(CONFIG_DIR,"geoasn.mmdb")

def _ensure_geoip():
    """Download DB-IP Lite MMDB files if not present (CC BY 4.0, no account needed)."""
    import gzip
    now=datetime.datetime.now()
    months=[now.strftime('%Y-%m'),(now.replace(day=1)-datetime.timedelta(days=1)).strftime('%Y-%m')]
    for path,slug in [(GEOIP_PATH,'dbip-country-lite'),(GEOASN_PATH,'dbip-asn-lite')]:
        if os.path.exists(path): continue
        for month in months:  # current month may not be published yet on the 1st
            try:
                url=f"https://download.db-ip.com/free/{slug}-{month}.mmdb.gz"
                req=urllib.request.Request(url,headers={'User-Agent':f'HostsGuard/{VER}'})
                with urllib.request.urlopen(req,timeout=60) as resp:
                    with open(path,'wb') as f: f.write(gzip.decompress(resp.read()))
                log.info(f"Downloaded {slug} to {path}")
                break
            except Exception as e: log.warning(f"GeoIP download failed ({slug}-{month}): {e}")
    return os.path.exists(GEOIP_PATH)

class GeoWorker(QThread):
    resolved=Signal(str,str,str)
    def __init__(s): super().__init__(); s._batch=[]; s._stop=TEvent(); s._lock=Lock(); s._backoff=2; s._mmdb=None; s._asndb=None
    def add(s,ip):
        if ip not in geo_c:
            with s._lock:
                if ip not in s._batch: s._batch.append(ip)
    def _open_mmdb(s):
        if s._mmdb: return True
        try:
            import maxminddb
            if _ensure_geoip():
                s._mmdb=maxminddb.open_database(GEOIP_PATH)
                if os.path.exists(GEOASN_PATH):
                    try: s._asndb=maxminddb.open_database(GEOASN_PATH)
                    except Exception: pass
                return True
        except ImportError: log.debug("maxminddb not installed, using API fallback")
        except Exception as e: log.warning(f"MMDB open failed: {e}")
        return False
    def _lookup_local(s,ip):
        if not s._mmdb: return None
        try:
            r=s._mmdb.get(ip)
            if r:
                cc=r.get('country',{}).get('iso_code','')
                cn=r.get('country',{}).get('names',{}).get('en','')
                if s._asndb:
                    ar=s._asndb.get(ip)
                    if ar:
                        asn=ar.get('autonomous_system_number','')
                        asorg=ar.get('autonomous_system_organization','')
                        if asn: cn=f"{cn} (AS{asn})" if cn else f"AS{asn}"
                if cc: return (cc,cn)
        except Exception: pass
        return None
    def run(s):
        s._open_mmdb()
        while not s._stop.is_set():
            batch=[]
            with s._lock:
                if s._batch: batch,s._batch=s._batch[:100],s._batch[100:]
            if batch:
                if s._mmdb:
                    for ip in batch:
                        result=s._lookup_local(ip)
                        # Cache misses too — otherwise every scan re-queues unknown IPs forever
                        geo_c.put(ip,result or ('',''))
                        if result: s.resolved.emit(ip,result[0],result[1])
                else:
                    batch_set=set(batch)
                    try:
                        data=json.dumps([{"query":ip} for ip in batch]).encode()
                        req=urllib.request.Request("http://ip-api.com/batch?fields=query,country,countryCode",data=data,
                            headers={'Content-Type':'application/json','User-Agent':f'HostsGuard/{VER}'})
                        with urllib.request.urlopen(req,timeout=10) as resp:
                            got=set()
                            for item in json.loads(resp.read()):
                                q=item.get("query","")
                                if q in batch_set and item.get("countryCode"):
                                    got.add(q)
                                    geo_c.put(q,(item["countryCode"],item["country"]))
                                    s.resolved.emit(q,item["countryCode"],item["country"])
                            for q in batch_set-got: geo_c.put(q,('',''))  # negative cache
                        s._backoff=2
                    except urllib.error.HTTPError as e:
                        if e.code==429:
                            s._backoff=min(s._backoff*2,60)
                            log.warning(f"GeoIP rate-limited, backing off {s._backoff}s")
                        with s._lock: s._batch=batch+s._batch
                    except Exception:
                        with s._lock: s._batch=batch+s._batch
            s._stop.wait(s._backoff if not s._mmdb else 0.5)
    def stop(s):
        s._stop.set()
        if s._mmdb:
            try: s._mmdb.close()
            except: pass
        if s._asndb:
            try: s._asndb.close()
            except: pass

class DNSMonitor(QThread):
    """ETW-based DNS monitoring with PowerShell polling fallback."""
    dns_event=Signal(dict); blocked_event=Signal(dict)
    status=Signal(str); updated=Signal()
    CMD='Get-DnsClientCache -EA SilentlyContinue|Select Entry,RecordName|ConvertTo-Json -Compress'
    def __init__(s,hm,db):
        super().__init__(); s.hm,s.db=hm,db; s.running=False; s._scan_lock=Lock()
        s._seen_lock=Lock()
        s._seen=OrderedDict.fromkeys(s.db.get_hidden_set()); s._etw_sess=None; s._use_etw=False
    def _try_etw(s):
        try:
            from pyetwkit._core import EtwProvider, EtwSession
            sess=EtwSession('HostsGuardDNS')
            prov=EtwProvider.dns_client()
            sess.add_provider(prov)
            sess.start()
            s._etw_sess=sess; s._use_etw=True
            log.info("DNS monitoring via ETW (real-time)")
            return True
        except ImportError: log.debug("pyetwkit not installed, using PowerShell polling")
        except Exception as e: log.warning(f"ETW DNS init failed (using PS fallback): {e}")
        return False
    def run(s):
        s.running=True
        if sys.platform!='win32': s.status.emit("Requires Windows"); return
        if s._try_etw(): s.status.emit("ETW Active"); s._run_etw()
        else: s.status.emit("Monitoring"); s._run_poll()
    def _run_etw(s):
        """Real-time ETW event loop — sub-second DNS event delivery."""
        while s.running:
            try:
                ev=s._etw_sess.try_next_event()
                if ev:
                    props=dict(ev.properties) if hasattr(ev,'properties') else {}
                    d=(props.get('QueryName','') or '').lower().strip().rstrip('.')
                    if not d or d in IGNORED or '.' not in d: continue
                    proc=''
                    try:
                        pid=ev.process_id
                        if pid:
                            cached=proc_c.get(pid)
                            if cached: proc=cached[0]
                            else:
                                import psutil as _ps2
                                proc=_ps2.Process(pid).name(); proc_c.put(pid,(proc,''))
                    except: pass
                    s._process_domain(d,proc)
                else:
                    time.sleep(0.1)
            except Exception as e: log.debug(f"ETW event: {e}"); time.sleep(0.5)
    def _run_poll(s):
        """PowerShell polling fallback — 3s interval."""
        s._scan(); s.updated.emit()
        while s.running: s._scan(); time.sleep(3)
    def mark_seen(s,d):
        """Suppression marker set from the GUI thread when a domain is hidden.
        _seen is shared with the monitor thread, so guard every access with a lock."""
        with s._seen_lock: s._seen[d]=True
    def _seen_contains(s,d):
        with s._seen_lock: return d in s._seen
    def _trim_seen(s):
        with s._seen_lock:
            if len(s._seen)<=10000: return
            hidden=s.db.get_hidden_set()
            keep=OrderedDict()
            for k in hidden: keep[k]=True
            items=list(s._seen.items())
            for k,v in items[-2000:]: keep[k]=True
            s._seen=keep
    def _process_domain(s,d,proc=''):
        blocked=s.db.get_blocked_set()
        is_new=s.db.feed_upsert(d,proc)
        with s._seen_lock:
            first=d not in s._seen
            if first: s._seen[d]=True
        if first and is_new:
            ev={'domain':d,'ts':datetime.datetime.now().isoformat(),'process':proc}
            s.dns_event.emit(ev)
            if d in blocked:
                s.db.log_event(d,'blocked',proc,'Blocked by hosts')
                s.blocked_event.emit(ev)
            s.updated.emit()
        s._trim_seen()
    def _scan(s):
        if not s._scan_lock.acquire(blocking=False): return
        try: s._do_scan()
        finally: s._scan_lock.release()
    def _do_scan(s):
        blocked=s.db.get_blocked_set()
        try:
            ok,out=_pps.run(s.CMD,12)
            if not ok or not out.strip(): return
            data=json.loads(out)
            if isinstance(data,dict): data=[data]
            domains=[]
            for e in data:
                d=(e.get('Entry') or e.get('RecordName') or '').lower().strip().rstrip('.')
                if not d or d in IGNORED or '.' not in d: continue
                domains.append(d)
            new=s.db.feed_upsert_batch(domains)
            with s._seen_lock:
                fresh=[d for d in new if d not in s._seen]
                for d in domains: s._seen[d]=True
            for d in fresh:
                ev={'domain':d,'ts':datetime.datetime.now().isoformat()}
                s.dns_event.emit(ev)
                if d in blocked:
                    s.db.log_event(d,'blocked','','Blocked by hosts')
                    s.blocked_event.emit(ev)
            if new: s.updated.emit()
            s._trim_seen()
        except Exception as e: log.debug(f"DNS scan: {e}")
    def manual_scan(s):
        # Run in a worker thread — _scan blocks on a PowerShell roundtrip (up to 12s)
        # and must never run on the GUI thread. _scan_lock already prevents overlap.
        if s.running and not s._use_etw:
            threading.Thread(target=s._scan,daemon=True).start()
    def stop(s):
        s.running=False
        if s._etw_sess:
            try: s._etw_sess.stop()
            except: pass

class SigWorker(QThread):
    resolved=Signal(str,str)
    def __init__(s): super().__init__(); s._q=Queue(); s._stop=TEvent()
    def add(s,path):
        if path not in sig_c: s._q.put(path)
    def run(s):
        while not s._stop.is_set():
            try:
                path=s._q.get(timeout=2)
                if path in sig_c: continue
                try:
                    # -LiteralPath: paths with [ ] (WindowsApps, some versioned dirs)
                    # are otherwise treated as wildcards and fail to resolve.
                    ok,out=_ps(f"(Get-AuthenticodeSignature -LiteralPath {_ps_esc(path)}).Status",5)
                    status=out.strip() if ok else 'Unknown'
                    label={'Valid':'✔','NotSigned':'✘','HashMismatch':'⚠'}.get(status,'?')
                    sig_c.put(path,label); s.resolved.emit(path,label)
                except Exception: sig_c.put(path,'?')
            except Empty: pass
    def stop(s): s._stop.set()

class ConnWorker(QThread):
    ready=Signal(list); need_dns=Signal(str); need_geo=Signal(str); need_sig=Signal(str)
    def __init__(s,db): super().__init__(); s._stop=TEvent(); s._db=db
    def run(s):
        while not s._stop.is_set():
            try: conns=s._scan(); s.ready.emit(conns); bw.update()
            except Exception as e: log.debug(f"ConnWorker scan: {e}")
            s._stop.wait(2.0)
    def _scan(s):
        # Full ISO timestamp — time-of-day-only values broke history pruning,
        # cross-day ordering, and made the UNIQUE index collide across days.
        out=[]; now=datetime.datetime.now().isoformat(timespec='seconds')
        blocked=s._db.get_blocked_set()
        try: conns=psutil.net_connections(kind='all')
        except psutil.AccessDenied: return out
        for c in conns:
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
                            if pname.lower()=='svchost.exe':
                                try:
                                    cl=p.cmdline()
                                    for j,a in enumerate(cl):
                                        if a=='-k' and j+1<len(cl): pname=f"svchost [{cl[j+1]}]"; break
                                except: pass
                            elif 'windowsapps' in ppath.lower():
                                try:
                                    parts=ppath.split(os.sep)
                                    for idx,pt in enumerate(parts):
                                        if pt.lower()=='windowsapps' and idx+1<len(parts):
                                            pkg=parts[idx+1]; pname=f"{pname} [{pkg.split('_')[0]}]"; break
                                except: pass
                            proc_c.put(pid,(pname,ppath))
                        except: pass
                host=dns_c.get(ra) or "-"
                stat="-"
                if host!="-" and host in blocked: stat="BLOCKED"
                elif ra in blocked: stat="BLOCKED"
                state=c.status if hasattr(c,'status') else ""
                cat=categorize(host,rp)
                if ra in DOH_IPS and rp in ('443','853'): cat='DoH/DoT'
                geo=geo_c.get(ra)
                country=(geo[1] or "-") if geo else "-"; cc=geo[0] if geo else ""
                sig_status=''
                if ppath:
                    cached_sig=sig_c.get(ppath)
                    if cached_sig is not None: sig_status=cached_sig
                    elif ppath: s.need_sig.emit(ppath)
                ppid=0; pproc=""
                if pid:
                    try:
                        pp=psutil.Process(pid).parent()
                        if pp: ppid=pp.pid; pproc=pp.name()
                    except Exception: pass
                ci=CI(key=f"{proto}:{la}:{lp}-{ra}:{rp}",ts=now,dir="Out" if c.status!="LISTEN" else "Listen",
                    proto=proto,la=la,lp=lp,ra=ra,rp=rp,host=host,proc=pname,pid=pid,state=state,
                    path=ppath,stat=stat,country=country,cc=cc,category=cat,sig=sig_status,ppid=ppid,pproc=pproc)
                out.append(ci)
                if host=="-": s.need_dns.emit(ra)
                if not geo: s.need_geo.emit(ra)
            except Exception: continue
        return out
    def stop(s): s._stop.set()

class HostsWatcher(QThread):
    changed=Signal(bytes)
    registry_tamper=Signal(str)
    def __init__(s):
        super().__init__(); s._stop=TEvent(); s._hash=b''
        s._expected_dbpath=r'%SystemRoot%\System32\drivers\etc'
    def _file_hash(s):
        try:
            h=hashlib.sha512()
            with open(HOSTS_PATH,'rb') as f:
                for chunk in iter(lambda:f.read(65536),b''): h.update(chunk)
            return h.digest()
        except Exception: return b''
    def run(s):
        s._hash=s._file_hash()
        while not s._stop.is_set():
            new_hash=s._file_hash()
            if new_hash and new_hash!=s._hash: s._hash=new_hash; s.changed.emit(new_hash)
            try:
                import winreg
                k=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters')
                val,_=winreg.QueryValueEx(k,'DataBasePath'); winreg.CloseKey(k)
                if val.lower().rstrip('\\')!=s._expected_dbpath.lower():
                    s.registry_tamper.emit(val)
            except Exception: pass
            s._stop.wait(5)
    def stop(s): s._stop.set()
    def update_hash(s): s._hash=s._file_hash()

# ─── Startup Loader (parallel) ──────────────────────────────────────────────
class StartupLoader(QThread):
    """Fast startup: DB + Hosts + ConnDB only. FW loads post-UI via FWLoadWorker.
    DNS cache is NOT pre-loaded — DNSMonitor picks it up within 3s naturally.
    PersistentPS is warmed up in background so DNSMonitor's first scan is fast."""
    progress=Signal(str,int)
    finished=Signal(object)
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
    ready=Signal(list)
    def run(s):
        rules=[]
        try:
            r=subprocess.run(['powershell','-NoProfile','-Command',_FW_DUMP_CMD],capture_output=True,text=True,timeout=120,creationflags=NOWIN)
            if r.returncode==0: rules=_parse_fw_rules(r.stdout.strip())
        except Exception as e: log.warning(f"FWLoadWorker: {e}")
        fw.set_cache(rules)
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
        s._bar=QProgressBar(); s._bar.setRange(0,100); s._bar.setValue(0); s._bar.setFixedHeight(10)
        s._bar.setTextVisible(False)
        s._bar.setStyleSheet(f"QProgressBar{{background:{C['s0']};border:none;border-radius:4px;}}QProgressBar::chunk{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {C['blue']},stop:1 {C['teal']});border-radius:4px;}}")
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
        s._label.setStyleSheet(f"background:{C['base']};color:{C['text']};font-size:{_dp(12)}px;font-weight:800;border:1px solid {C['s1']};border-radius:{_dp(10)}px;padding:{_dp(12)}px;")
        s._dots=0; s._tmr=QTimer(s); s._tmr.timeout.connect(s._anim); s._tmr.setInterval(400)
    def show_loading(s,text="Loading"):
        s._text=text; s._dots=0; s.setVisible(True); s.raise_(); s._tmr.start(); s._set_parent_loading(True); s._update_geom()
    def hide_loading(s):
        s.setVisible(False); s._tmr.stop(); s._set_parent_loading(False)
    def _anim(s): s._dots=(s._dots+1)%4; s._label.setText(f"{s._text}{'.'*s._dots}")
    def _set_parent_loading(s,on):
        p=s.parent()
        if hasattr(p,"set_loading_state"): p.set_loading_state(on)
    def _update_geom(s):
        if s.parent():
            s.setGeometry(s.parent().rect())
            w=min(_dp(320),max(_dp(220),s.width()-_dp(64))); h=_dp(58)
            s._label.setGeometry((s.width()-w)//2,(s.height()-h)//2,w,h)
    def resizeEvent(s,e): super().resizeEvent(e); s._update_geom()
    def paintEvent(s,e):
        p=QPainter(s); sc=QColor(C['bg']); sc.setAlpha(196); p.fillRect(s.rect(),sc); p.end()

# ─── Learning Mode ──────────────────────────────────────────────────────────
class LearnDB:
    def __init__(s,db):
        s.db=db; s._trusted=set(); s._untrusted=set(); s._prompted=set(); s._enabled=False; s._observe=False; s._load()
    def _load(s):
        cfg=load_cfg(); s._enabled=cfg.get('learning_mode',False); s._observe=cfg.get('observe_mode',False)
        s._trusted=set(cfg.get('trusted_procs',[])); s._untrusted=set(cfg.get('untrusted_procs',[]))
    def save(s):
        cfg=load_cfg(); cfg['learning_mode']=s._enabled; cfg['observe_mode']=s._observe
        cfg['trusted_procs']=list(s._trusted); cfg['untrusted_procs']=list(s._untrusted); save_cfg(cfg)
    @property
    def enabled(s): return s._enabled
    def set_enabled(s,v): s._enabled=v; s.save()
    @property
    def observe(s): return s._observe
    def set_observe(s,v): s._observe=v; s.save()
    def is_trusted(s,proc): return proc.lower() in s._trusted
    def is_untrusted(s,proc): return proc.lower() in s._untrusted
    def trust(s,proc): s._trusted.add(proc.lower()); s._untrusted.discard(proc.lower()); s.save()
    def untrust(s,proc): s._untrusted.add(proc.lower()); s._trusted.discard(proc.lower()); s.save()
    def reset(s,proc): s._trusted.discard(proc.lower()); s._untrusted.discard(proc.lower()); s.save()
    def was_prompted(s,key): return key in s._prompted
    def mark_prompted(s,key): s._prompted.add(key)
    def clear_prompted(s): s._prompted.clear()

# ─── Mini Monitor (always-on-top thumbnail) ────────────────────────────────
class MiniMonitor(QWidget):
    """Compact frameless always-on-top glance widget: live up/down rates and
    live/blocked-today counts. Draggable; fed by the existing bandwidth + connection
    workers. Toggled from the tray."""
    def __init__(s):
        super().__init__(None)
        s.setWindowFlags(Qt.FramelessWindowHint|Qt.WindowStaysOnTopHint|Qt.Tool)
        s.setAttribute(Qt.WA_TranslucentBackground)
        s.setFixedSize(_dp(190),_dp(74)); s._drag=None
        lo=QVBoxLayout(s); lo.setContentsMargins(_dp(12),_dp(8),_dp(12),_dp(8)); lo.setSpacing(_dp(2))
        t=QLabel(f"◆ {APP}"); t.setStyleSheet(f"color:{C['blue']};font-size:{_dp(9)}px;font-weight:800;letter-spacing:0.5px;"); lo.addWidget(t)
        bwr=QHBoxLayout(); bwr.setSpacing(_dp(8))
        s._up=QLabel("▲ --"); s._up.setStyleSheet(f"color:{C['blue']};font-size:{_dp(10)}px;font-weight:700;font-family:'Cascadia Code','Consolas',monospace;")
        s._dn=QLabel("▼ --"); s._dn.setStyleSheet(f"color:{C['teal']};font-size:{_dp(10)}px;font-weight:700;font-family:'Cascadia Code','Consolas',monospace;")
        bwr.addWidget(s._up); bwr.addWidget(s._dn); bwr.addStretch(); lo.addLayout(bwr)
        cr=QHBoxLayout(); cr.setSpacing(_dp(8))
        s._conns=QLabel("0 conns"); s._conns.setStyleSheet(f"color:{C['sub']};font-size:{_dp(9)}px;")
        s._blk=QLabel("0 blocked"); s._blk.setStyleSheet(f"color:{C['red']};font-size:{_dp(9)}px;font-weight:700;")
        cr.addWidget(s._conns); cr.addWidget(s._blk); cr.addStretch(); lo.addLayout(cr)
    def paintEvent(s,e):
        p=QPainter(s); p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(QColor(C['base'])); p.setPen(QPen(QColor(C['s1']),1))
        p.drawRoundedRect(s.rect().adjusted(1,1,-1,-1),_dp(10),_dp(10)); p.end()
    def update_stats(s,up,dn,conns,blocked_today):
        s._up.setText(f"▲ {BWTracker.fmt(up)}"); s._dn.setText(f"▼ {BWTracker.fmt(dn)}")
        s._conns.setText(f"{conns} conns"); s._blk.setText(f"{blocked_today} today")
    def place_top_right(s):
        scr=QApplication.primaryScreen()
        if scr: g=scr.availableGeometry(); s.move(g.right()-s.width()-_dp(16),g.top()+_dp(16))
    def mousePressEvent(s,e):
        if e.button()==Qt.LeftButton: s._drag=e.globalPosition().toPoint()-s.frameGeometry().topLeft()
    def mouseMoveEvent(s,e):
        if s._drag is not None and e.buttons()&Qt.LeftButton: s.move(e.globalPosition().toPoint()-s._drag)
    def mouseReleaseEvent(s,e): s._drag=None
    def mouseDoubleClickEvent(s,e): s.hide()

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

def _button_qss(cls,font_px=11,pad_x=8):
    radius=8
    if cls=="primary":
        return (f"QPushButton{{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 {C['blue']},stop:1 {C['teal']});"
                f"color:{C['onsel']};border:1px solid rgba({_rgb(C['blue'])},0.55);border-radius:{_dp(radius)}px;"
                f"font-size:{_dp(font_px)}px;font-weight:800;padding:0 {_dp(pad_x)}px;}}"
                f"QPushButton:hover{{background:{C['sky']};}}QPushButton:focus{{border:1px solid {C['focus']};}}"
                f"QPushButton:disabled{{background:{C['mantle']};color:{C['dim']};border-color:{C['s0']};}}")
    if cls=="danger":
        return (f"QPushButton{{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 {C['red']},stop:1 {C['danger2']});"
                f"color:{C['on_danger']};border:1px solid rgba({_rgb(C['red'])},0.55);border-radius:{_dp(radius)}px;"
                f"font-size:{_dp(font_px)}px;font-weight:800;padding:0 {_dp(pad_x)}px;}}"
                f"QPushButton:hover{{background:{C['danger_hover']};}}QPushButton:focus{{border:1px solid {C['focus']};}}"
                f"QPushButton:disabled{{background:{C['mantle']};color:{C['dim']};border-color:{C['s0']};}}")
    if cls=="success":
        return (f"QPushButton{{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 {C['green']},stop:1 {C['teal']});"
                f"color:{C['onsel']};border:1px solid rgba({_rgb(C['green'])},0.55);border-radius:{_dp(radius)}px;"
                f"font-size:{_dp(font_px)}px;font-weight:800;padding:0 {_dp(pad_x)}px;}}"
                f"QPushButton:hover{{background:{C['green']};}}QPushButton:focus{{border:1px solid {C['focus']};}}"
                f"QPushButton:disabled{{background:{C['mantle']};color:{C['dim']};border-color:{C['s0']};}}")
    return (f"QPushButton{{background:{C['s0']};color:{C['sub']};border:1px solid {C['s1']};border-radius:{_dp(radius)}px;"
            f"font-size:{_dp(font_px)}px;font-weight:700;padding:0 {_dp(pad_x)}px;}}"
            f"QPushButton:hover{{background:{C['s1']};color:{C['text']};border-color:{C['s2']};}}"
            f"QPushButton:focus{{border:1px solid {C['focus']};color:{C['text']};}}"
            f"QPushButton:disabled{{background:{C['mantle']};color:{C['dim']};border-color:{C['s0']};}}")

def _btn(text,cls="dim",cb=None,tip=None):
    b=QPushButton(text); b.setProperty("class",cls); b.setCursor(Qt.PointingHandCursor)
    b.setFixedHeight(_dp(26)); b.setMinimumWidth(_dp(16))
    b.setSizePolicy(QSizePolicy.Preferred,QSizePolicy.Fixed)
    b.setStyleSheet(_button_qss(cls,11,8))
    if cb: b.clicked.connect(cb)
    b.setAccessibleName(tip or text)
    if tip:
        b.setToolTip(tip); b.setAccessibleDescription(tip)
    b.style().unpolish(b); b.style().polish(b)
    return b

def _tbtn(text,cls="dim",cb=None,w=None,tip=None):
    b=QPushButton(text); b.setProperty("class",cls); b.setCursor(Qt.PointingHandCursor)
    b.setFixedHeight(_dp(30))
    b.setStyleSheet(_button_qss(cls,10,10))
    if w: b.setFixedWidth(_dp(w))
    if cb: b.clicked.connect(cb)
    b.setAccessibleName(text)
    if tip:
        b.setToolTip(tip); b.setAccessibleDescription(tip)
    b.style().unpolish(b); b.style().polish(b)
    return b

class PremiumTableWidget(QTableWidget):
    """QTableWidget with a built-in theme-aware empty state."""
    def __init__(s,*args,**kwargs):
        super().__init__(*args,**kwargs)
        s._empty_title="No rows to show"
        s._empty_detail="Adjust filters or refresh."
        s._loading=False
        s._empty=QLabel(s.viewport())
        s._empty.setAlignment(Qt.AlignCenter)
        s._empty.setWordWrap(True)
        s._empty.setAttribute(Qt.WA_TransparentForMouseEvents,True)
        s._empty.setStyleSheet(f"color:{C['dim']};font-size:{_dp(11)}px;font-weight:650;background:transparent;padding:{_dp(18)}px;")
        s._empty.hide()
    def set_empty_state(s,title,detail=""):
        s._empty_title=title; s._empty_detail=detail; s._sync_empty()
    def set_loading_state(s,on):
        s._loading=on; s._sync_empty()
    def setRowCount(s,rows):
        super().setRowCount(rows); s._sync_empty()
    def resizeEvent(s,e):
        super().resizeEvent(e); s._place_empty()
    def showEvent(s,e):
        super().showEvent(e); s._sync_empty()
    def _place_empty(s):
        s._empty.setGeometry(s.viewport().rect().adjusted(_dp(28),_dp(28),-_dp(28),-_dp(28)))
    def _sync_empty(s):
        s._place_empty()
        detail=f"\n{s._empty_detail}" if s._empty_detail else ""
        s._empty.setText(f"{s._empty_title}{detail}")
        s._empty.setVisible(not s._loading and s.rowCount()==0)

def _badge(text,color):
    l=QLabel(text); l.setAlignment(Qt.AlignCenter)
    l.setStyleSheet(f"background:rgba({_rgb(color)},0.14);color:{color};font-size:{_dp(9)}px;font-weight:800;border:1px solid rgba({_rgb(color)},0.32);border-radius:{_dp(6)}px;padding:{_dp(2)}px {_dp(7)}px;letter-spacing:0.3px;")
    return l
def _row_tint():
    """Subtle blocked-row background that reads in both themes (was a fixed dark-red RGBA)."""
    c=QColor(C['red']); c.setAlpha(28 if _IS_LIGHT else 16); return c
def _num_item(n):
    """Table cell that sorts numerically — plain str items sort '9' after '100'."""
    it=QTableWidgetItem(); it.setData(Qt.DisplayRole,int(n)); return it

def _stat(label,value="0",color=C['blue'],icon=""):
    f=QFrame(); f.setStyleSheet(f"QFrame{{background:rgba({_rgb(C['base'])},0.85);border:1px solid rgba({_rgb(C['s1'])},0.4);border-radius:{_dp(12)}px;}}")
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
    t=PremiumTableWidget(0,len(cols)); t.setHorizontalHeaderLabels(cols)
    t.horizontalHeader().setSectionResizeMode(stretch,QHeaderView.Stretch)
    t.setAlternatingRowColors(True); t.setEditTriggers(QTableWidget.NoEditTriggers)
    t.verticalHeader().setVisible(False); t.setShowGrid(False)
    t.setSelectionBehavior(QTableWidget.SelectRows); t.setSelectionMode(QTableWidget.ExtendedSelection)
    t.setIconSize(QSize(_dp(16),_dp(16))); t.verticalHeader().setDefaultSectionSize(_dp(row_h))
    t.setSortingEnabled(True); t.setContextMenuPolicy(Qt.CustomContextMenu)
    t.set_empty_state("No rows to show","Adjust filters or refresh this view.")
    return t

# ─── Scheduled Blocking Dialog ─────────────────────────────────────────────
class ScheduleDlg(QDialog):
    """CRUD for time-based block windows. Each schedule targets a domain or a
    service name (from BLOCK_SERVICES) and blocks it on selected weekdays between
    a start and end time. Stored in config['schedules']."""
    def __init__(s,parent=None):
        super().__init__(parent); s.setWindowTitle("Scheduled Blocking"); s.setFixedWidth(_dp(560))
        s.setStyleSheet(f"QDialog{{background:{C['base']};}}")
        lo=QVBoxLayout(s); lo.setSpacing(_dp(8)); lo.setContentsMargins(_dp(20),_dp(14),_dp(20),_dp(14))
        hdr=QLabel("Scheduled Blocking"); hdr.setStyleSheet(f"font-size:{_dp(15)}px;font-weight:800;color:{C['text']};"); lo.addWidget(hdr)
        desc=QLabel("Block a domain or service on a recurring weekly schedule. Windows may cross midnight.")
        desc.setWordWrap(True); desc.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); lo.addWidget(desc)
        s.tbl=_tbl(["Target","Days","Start","End"],0,row_h=26)
        s.tbl.set_empty_state("No schedules yet","Add a recurring domain or service window below.")
        s.tbl.setColumnWidth(1,_dp(150)); s.tbl.setColumnWidth(2,_dp(60)); s.tbl.setColumnWidth(3,_dp(60))
        s.tbl.setMaximumHeight(_dp(160)); lo.addWidget(s.tbl)
        # Editor row
        ed=QGroupBox("Add schedule"); el=QVBoxLayout(ed); el.setSpacing(_dp(6))
        r1=QHBoxLayout(); r1.setSpacing(_dp(6))
        r1.addWidget(QLabel("Target"))
        s.target=QComboBox(); s.target.setEditable(True); s.target.addItems(list(BLOCK_SERVICES.keys()))
        s.target.setCurrentText(""); s.target.setToolTip("A service name, such as YouTube, or a domain like example.com")
        s.target.setAccessibleName("Schedule target")
        r1.addWidget(s.target,1)
        r1.addWidget(QLabel("Start")); s.start=QTimeEdit(); s.start.setAccessibleName("Schedule start time"); s.start.setDisplayFormat("HH:mm"); r1.addWidget(s.start)
        r1.addWidget(QLabel("End")); s.end=QTimeEdit(); s.end.setDisplayFormat("HH:mm")
        s.end.setAccessibleName("Schedule end time")
        s.end.setTime(QTime(6,0)); r1.addWidget(s.end)
        el.addLayout(r1)
        r2=QHBoxLayout(); r2.setSpacing(_dp(4)); s.day_cbs=[]
        for i,d in enumerate(_WEEKDAYS):
            cb=QCheckBox(d); cb.setChecked(i<5); r2.addWidget(cb); s.day_cbs.append(cb)
        r2.addStretch(); r2.addWidget(_btn("Add","primary",s._add)); el.addLayout(r2)
        s.err=QLabel(""); s.err.setWordWrap(True); s.err.setStyleSheet(f"color:{C['peach']};font-size:{_dp(10)}px;font-weight:700;")
        el.addWidget(s.err)
        lo.addWidget(ed)
        br=QHBoxLayout(); br.addWidget(_btn("Remove Selected","danger",s._remove)); br.addStretch()
        br.addWidget(_btn("Close","dim",lambda:s.accept())); lo.addLayout(br)
        s._reload()
    def _schedules(s): return load_cfg().get('schedules',[])
    def _reload(s):
        rows=s._schedules(); s.tbl.setRowCount(len(rows))
        for i,sc in enumerate(rows):
            days=",".join(_WEEKDAYS[d] for d in sc.get('days',[]) if 0<=d<7)
            s.tbl.setItem(i,0,QTableWidgetItem(sc.get('target','')))
            s.tbl.setItem(i,1,QTableWidgetItem(days))
            s.tbl.setItem(i,2,QTableWidgetItem(sc.get('start','')))
            s.tbl.setItem(i,3,QTableWidgetItem(sc.get('end','')))
    def _add(s):
        target=s.target.currentText().strip()
        days=[i for i,cb in enumerate(s.day_cbs) if cb.isChecked()]
        if not target:
            s.err.setText("Choose a service or enter a domain to schedule."); s.target.setFocus(); return
        if not days:
            s.err.setText("Select at least one weekday for this schedule."); return
        # Accept a known service name as-is, else require a valid domain
        if target not in BLOCK_SERVICES and not looks_like_domain(target.lower()):
            s.err.setText("Enter a known service name or a valid domain, such as example.com."); s.target.setFocus(); return
        sc={'target':target if target in BLOCK_SERVICES else target.lower(),
            'days':days,'start':s.start.time().toString("HH:mm"),'end':s.end.time().toString("HH:mm")}
        cfg=load_cfg(); sl=cfg.get('schedules',[]); sl.append(sc); cfg['schedules']=sl; save_cfg(cfg)
        s.err.setText(""); s._reload()
        p=s.parent()
        if hasattr(p,'_apply_schedules'): p._apply_schedules()
    def _remove(s):
        row=s.tbl.currentRow()
        if row<0: return
        cfg=load_cfg(); sl=cfg.get('schedules',[])
        if 0<=row<len(sl):
            del sl[row]; cfg['schedules']=sl; save_cfg(cfg); s._reload()
            p=s.parent()
            if hasattr(p,'_apply_schedules'): p._apply_schedules()

# ─── DNS Inspection Dialog ─────────────────────────────────────────────────
class DNSInspectDlg(QDialog):
    def __init__(s,domain,parent=None):
        super().__init__(parent); s.setWindowTitle(f"DNS: {domain}"); s.setFixedWidth(_dp(520))
        s.setStyleSheet(f"QDialog{{background:{C['base']};}}")
        lo=QVBoxLayout(s); lo.setSpacing(_dp(8)); lo.setContentsMargins(_dp(20),_dp(14),_dp(20),_dp(14))
        hdr=QLabel(domain); hdr.setStyleSheet(f"font-size:{_dp(15)}px;font-weight:800;color:{C['text']};"); lo.addWidget(hdr)
        s._result=QPlainTextEdit(); s._result.setReadOnly(True); s._result.setMaximumHeight(_dp(300))
        s._result.setFont(QFont("Cascadia Code,Consolas",_dp(9)))
        s._result.setStyleSheet(f"background:{C['mantle']};color:{C['text']};border:1px solid {C['s0']};border-radius:{_dp(8)}px;padding:{_dp(6)}px;")
        lo.addWidget(s._result,1)
        br=QHBoxLayout(); br.addWidget(_btn("Copy","dim",lambda:QApplication.clipboard().setText(s._result.toPlainText())))
        br.addStretch(); br.addWidget(_btn("Close","dim",lambda:s.reject())); lo.addLayout(br)
        threading.Thread(target=s._resolve,args=(domain,),daemon=True).start()
    def _resolve(s,domain):
        import struct as _st
        lines=[]; t0=time.time()
        for qtype,label in [(1,'A'),(28,'AAAA'),(5,'CNAME')]:
            try:
                resp=s._dns_query(domain,qtype)
                if resp:
                    for name,rtype,ttl,rdata,data,rdata_off in resp:
                        if rtype==1 and len(rdata)==4: val='.'.join(str(b) for b in rdata)
                        elif rtype==28 and len(rdata)==16: val=socket.inet_ntop(socket.AF_INET6,rdata)
                        elif rtype==5: val=s._read_name(data,rdata_off)[0] or '(unresolved)'
                        else: val=rdata.hex()
                        lines.append(f"{label:6s}  {name:40s}  TTL={ttl:<6d}  {val}")
            except Exception as e: lines.append(f"{label:6s}  Error: {e}")
        latency=int((time.time()-t0)*1000)
        blocked='(BLOCKED by hosts)' if domain.lower() in (s.parent().db.get_blocked_set() if hasattr(s.parent(),'db') else set()) else ''
        header=f"Query: {domain} {blocked}\nResolver latency: {latency}ms\n{'─'*60}\n"
        ui_call(lambda:s._result.setPlainText(header+('\n'.join(lines) if lines else 'No records found')))
    @staticmethod
    def _dns_query(domain,qtype):
        import struct as _st
        tid=os.urandom(2)
        qname=b''
        for part in domain.encode().split(b'.'): qname+=bytes([len(part)])+part
        qname+=b'\x00'
        pkt=tid+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+qname+_st.pack('!HH',qtype,1)
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.sendto(pkt,('8.8.8.8',53))
            data,_=sock.recvfrom(4096)
        finally: sock.close()
        if len(data)<12: return []
        _,flags,qdcount,ancount=_st.unpack('!HHHH',data[:8])
        off=12
        for _ in range(qdcount):
            while off<len(data) and data[off]!=0:
                if data[off]&0xc0==0xc0: off+=2; break
                off+=data[off]+1
            else: off+=1
            off+=4
        results=[]
        for _ in range(ancount):
            name,off=DNSInspectDlg._read_name(data,off)
            if off+10>len(data): break
            rtype,_,ttl,rdlen=_st.unpack('!HHIH',data[off:off+10]); off+=10
            rdata_off=off; rdata=data[off:off+rdlen]; off+=rdlen
            # Carry the full packet + rdata offset so name-bearing records (CNAME)
            # can resolve DNS compression pointers that reference earlier positions.
            results.append((name,rtype,ttl,rdata,data,rdata_off))
        return results
    @staticmethod
    def _read_name(data,off):
        parts=[]; jumped=False; save_off=off; hops=0
        while off<len(data):
            l=data[off]
            if l==0: off+=1; break
            if l&0xc0==0xc0:
                if off+2>len(data): break
                if not jumped: save_off=off+2
                import struct as _st
                off=_st.unpack('!H',data[off:off+2])[0]&0x3fff; jumped=True
                hops+=1
                if hops>128: break  # guard against self-referential compression pointer loops
                continue
            off+=1; parts.append(data[off:off+l].decode('ascii','replace')); off+=l
        return '.'.join(parts), save_off if jumped else off

# ─── Connection Detail Dialog ───────────────────────────────────────────────
class ConnDetailDlg(QDialog):
    def __init__(s,ci,db,hm,learn,parent=None):
        super().__init__(parent); s.ci=ci; s.db=db; s.hm=hm; s.learn=learn; s.result_action=None
        s.setWindowTitle(f"Connection: {ci.proc} \u2192 {ci.host if ci.host not in ('-','') else ci.ra}")
        s.setFixedWidth(_dp(640)); s.setStyleSheet(f"QDialog{{background:{C['base']};}}")
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
        fg=QGroupBox("Firewall"); fl=QGridLayout(fg); fl.setHorizontalSpacing(_dp(6)); fl.setVerticalSpacing(_dp(6))
        fl.setColumnStretch(4,1)
        def row_label(text):
            lab=QLabel(text); lab.setStyleSheet(f"color:{C['dim']};font-size:{_dp(9)}px;font-weight:800;")
            return lab
        fl.addWidget(row_label("Remote IP"),0,0)
        fl.addWidget(_btn("Block Out","danger",lambda:s._do('fw_block_ip',ci.ra),"Block this remote IP for outbound traffic"),0,1)
        fl.addWidget(_btn("Block In + Out","danger",lambda:s._do('fw_block_ip_both',ci.ra),"Block this remote IP inbound and outbound"),0,2)
        if ci.path:
            fl.addWidget(row_label("Program"),1,0)
            fl.addWidget(_btn("Block App Out","danger",lambda:s._do('fw_block_prog',ci.path),"Block this program for outbound traffic"),1,1)
            fl.addWidget(_btn("Block App In + Out","danger",lambda:s._do('fw_block_prog_both',ci.path),"Block this program inbound and outbound"),1,2)
        if ci.pid>0: fl.addWidget(_btn(f"Kill PID {ci.pid}","danger",lambda:s._do('kill',str(ci.pid)),f"End process {ci.pid}"),1 if ci.path else 0,3)
        lo.addWidget(fg)
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
        super().__init__(parent); s.setWindowTitle("Create Firewall Rule"); s.setFixedWidth(_dp(480))
        s.setStyleSheet(f"QDialog{{background:{C['base']};}}")
        lo=QVBoxLayout(s); lo.setSpacing(_dp(8)); lo.setContentsMargins(_dp(20),_dp(16),_dp(20),_dp(16))
        hdr=QLabel("Create Firewall Rule"); hdr.setStyleSheet(f"font-size:{_dp(16)}px;font-weight:850;color:{C['text']};"); lo.addWidget(hdr)
        desc=QLabel("Match a remote address, protocol, or program path, then choose whether Windows Firewall blocks or allows it.")
        desc.setWordWrap(True); desc.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); lo.addWidget(desc)
        pf=prefill or {}
        def _r(l,w,tip=""):
            lab=QLabel(l); lab.setStyleSheet(f"color:{C['sub']};font-size:{_dp(10)}px;font-weight:700;")
            if tip: lab.setToolTip(tip); w.setToolTip(tip); w.setAccessibleDescription(tip)
            w.setAccessibleName(l)
            lo.addWidget(lab); lo.addWidget(w)
        s.name=QLineEdit(pf.get('name',FW_PFX)); _r("Rule name",s.name,"HostsGuard prefixes rule names with HG_ so they are easy to audit later.")
        s.dir_c=QComboBox(); s.dir_c.addItems(["Outbound","Inbound"])
        if pf.get('dir'): s.dir_c.setCurrentText(pf['dir'])
        _r("Direction",s.dir_c)
        s.act_c=QComboBox(); s.act_c.addItems(["Block","Allow"])
        if pf.get('action'): s.act_c.setCurrentText(pf['action'])
        _r("Action",s.act_c)
        s.proto_c=QComboBox(); s.proto_c.addItems(["Any","TCP","UDP","ICMPv4"])
        if pf.get('proto') and pf['proto'] not in ('Any',''): s.proto_c.setCurrentText(pf['proto'])
        _r("Protocol",s.proto_c)
        s.addr=QLineEdit(pf.get('addr','')); s.addr.setPlaceholderText("IP, CIDR, range, LocalSubnet, or blank for any")
        _r("Remote address",s.addr,"Examples: 8.8.8.8, 10.0.0.0/8, 192.168.1.1-192.168.1.50, LocalSubnet.")
        pr=QHBoxLayout(); s.prog=QLineEdit(pf.get('prog',''))
        s.prog.setPlaceholderText("Optional path to an executable"); s.prog.setAccessibleName("Program path"); pr.addWidget(s.prog,1)
        pr.addWidget(_btn("\u2026","dim",s._browse,"Choose an executable")); lo.addWidget(QLabel("Program")); lo.addLayout(pr)
        s._err=QLabel(""); s._err.setWordWrap(True); s._err.setStyleSheet(f"color:{C['peach']};font-size:{_dp(10)}px;font-weight:700;")
        lo.addWidget(s._err)
        lo.addSpacing(_dp(6))
        br=QHBoxLayout(); br.addStretch()
        br.addWidget(_btn("Cancel","dim",lambda:s.reject()))
        br.addWidget(_btn("Create Rule","primary",s._try_accept))
        lo.addLayout(br)
    def _browse(s):
        p,_=QFileDialog.getOpenFileName(s,"Select Program","","Executables (*.exe);;All (*)"); 
        if p: s.prog.setText(p)
    @staticmethod
    def _addr_ok(addr):
        if not addr: return True
        return valid_fw_addr(addr) or addr.lower() in {"any","localsubnet","dns","dhcp","wins","defaultgateway"}
    def _try_accept(s):
        name=s.name.text().strip()
        addr=s.addr.text().strip()
        if not name or name==FW_PFX:
            s._err.setText("Enter a rule name after the HG_ prefix."); s.name.setFocus(); return
        if not NewRuleDlg._addr_ok(addr):
            s._err.setText("Remote address must be an IP, CIDR subnet, IP range, LocalSubnet, or blank for any.")
            s.addr.setFocus(); return
        s._err.setText(""); s.accept()
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
        scr=None
        if s.parent(): scr=s.parent().screen() or QApplication.primaryScreen()
        else: scr=QApplication.primaryScreen()
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
        s.search=QLineEdit(); s.search.setPlaceholderText("Search domain, process, or source..."); s.search.setFixedHeight(_dp(30))
        s.search.setAccessibleName("Search DNS activity")
        s.search.setClearButtonEnabled(True)
        s._search_debounce=QTimer(s); s._search_debounce.setSingleShot(True); s._search_debounce.setInterval(200)
        s._search_debounce.timeout.connect(s._on_search)
        s.search.textChanged.connect(lambda:s._search_debounce.start()); tb.addWidget(s.search,1)
        s.filt=QComboBox(); s.filt.addItems(["All","Blocked","Allowed","Unmanaged","Hidden"])
        s.filt.setAccessibleName("Filter DNS activity by status")
        s.filt.currentIndexChanged.connect(s._on_search); tb.addWidget(s.filt)
        tb.addWidget(_tbtn("Scan","primary",s._scan,55)); lo.addLayout(tb)
        s.tbl=_tbl(["Domain","Status","Process","Hits","Last Seen"],0,row_h=30)
        s.tbl.set_empty_state("No DNS activity shown","Start a scan, clear filters, or browse normally to populate this feed.")
        s.tbl.setAccessibleName("DNS activity table")
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
        h=hash(tuple((m[0],m[2],m[3],m[4],m[5],m[6]) for m in rows))
        if h==s._last_hash: s._overlay.hide_loading(); return
        s._last_hash=h
        saved=s._sel_domain()
        s.tbl.setSortingEnabled(False); s.tbl.setRowCount(len(rows))
        for i,row in enumerate(rows):
            domain,fs,ls,hits,proc,hidden,status=row[:7]
            source=row[7] if len(row)>7 else None
            it0=QTableWidgetItem(domain)
            if domain and _fav:
                px=_fav.get(domain)
                if px and not px.isNull(): it0.setIcon(QIcon(px))
            if source and status in ('blocked','whitelisted'):
                it0.setToolTip(f"{'Blocked' if status=='blocked' else 'Allowed'} by: {source}")
            s.tbl.setItem(i,0,it0)
            hc={'blocked':C['red'],'whitelisted':C['green']}.get(status,C['dim'])
            ht={'blocked':'BLOCKED','whitelisted':'ALLOWED'}.get(status,'\u2014')
            s.tbl.setCellWidget(i,1,_badge(ht,hc))
            s.tbl.setItem(i,2,QTableWidgetItem(proc or ""))
            s.tbl.setItem(i,3,_num_item(hits))
            s.tbl.setItem(i,4,QTableWidgetItem((ls or "")[:19]))
            if status=='blocked':
                for col in [0,2,3,4]:
                    it=s.tbl.item(i,col)
                    if it: it.setBackground(_row_tint())
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
            tm=hm.addMenu("Temp Allow"); tm.setStyleSheet(CTX)
            for mins in [5,15,30,60]:
                lbl=f"{mins} min" if mins<60 else "1 hour"
                tm.addAction(lbl).triggered.connect(lambda _=None,d2=d,m2=mins:s._act_temp_allow(d2,m2))
            m.addSeparator()
            if f=="Hidden":
                m.addAction("Unhide").triggered.connect(lambda:(s.db.feed_unhide(d),setattr(s,'_last_hash',0),s._refresh()))
                m.addAction(f"Unhide root ({root})").triggered.connect(lambda:(s.db.feed_unhide_root(d),setattr(s,'_last_hash',0),s._refresh(),s._toast(f"Unhid *{root}",C['green'])))
            else:
                m.addAction("Hide").triggered.connect(lambda:s._act_hide(d))
                m.addAction(f"Hide root ({root})").triggered.connect(lambda:s._act_hide_root(d))
            m.addSeparator()
            m.addAction("DNS Inspect").triggered.connect(lambda:DNSInspectDlg(d,s).exec_())
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
        root=get_root(d); s.db.add_root(d,'whitelisted','manual'); s.hm.unblock(root); s.db.log_event(root,'whitelisted','','Allowed root')
        s._last_hash=0; s._refresh(); s._toast(f"Allowed {root}",C['green'])
    def _act_temp_allow(s,d,mins):
        s.db.add_domain(d,'whitelisted','temp_allow'); s.hm.unblock(d)
        s.db.log_event(d,'whitelisted','',f'Temp allow {mins}m')
        cfg=load_cfg(); ta=cfg.get('temp_allows',{}); ta[d]=time.time()+mins*60
        cfg['temp_allows']=ta; save_cfg(cfg)
        s._last_hash=0; s._refresh(); s._toast(f"Allowed {d} for {mins}m",C['green'])
        QTimer.singleShot(mins*60*1000,lambda:s._revert_temp(d))
    def _revert_temp(s,d):
        cfg=load_cfg(); ta=cfg.get('temp_allows',{})
        ta.pop(d,None); cfg['temp_allows']=ta; save_cfg(cfg)
        # Only revert if the domain is still in temp-allow state — if the user made
        # the allow permanent (or removed the domain) in the meantime, respect that.
        r=s.db._q("SELECT source FROM domains WHERE domain=?",(d,))
        if not r or r[0][0]!='temp_allow': return
        s.db.add_domain(d,'blocked','temp_reverted'); s.hm.block(d)
        s.db.log_event(d,'blocked','','Temp allow expired')
        s._last_hash=0; s._refresh(); s._toast(f"Temp allow expired: {d}",C['red'])
    def resume_temp_allows(s):
        """Re-arm temp-allow expiry timers after restart; revert already-expired ones."""
        ta=load_cfg().get('temp_allows',{})
        now=time.time()
        for d,exp in list(ta.items()):
            remaining=exp-now
            if remaining<=0: s._revert_temp(d)
            else: QTimer.singleShot(int(remaining*1000),lambda _d=d:s._revert_temp(_d))
    def _act_hide(s,d):
        s.db.feed_hide(d)
        w=s.window()
        if hasattr(w,'_dns_mon') and w._dns_mon: w._dns_mon.mark_seen(d.lower())
        s.tbl.setRowCount(0); s._last_hash=0; s._refresh(); s._toast(f"Hidden {d}",C['dim'])
    def _act_hide_root(s,d):
        s.db.feed_hide_root(d); root=get_root(d)
        w=s.window()
        if hasattr(w,'_dns_mon') and w._dns_mon:
            for dom in s.db.get_hidden_set(): w._dns_mon.mark_seen(dom)
        s.tbl.setRowCount(0); s._last_hash=0; s._refresh(); s._toast(f"Hidden *{root}",C['dim'])
    def resizeEvent(s,e): super().resizeEvent(e); s._overlay._update_geom()
    def _toast(s,msg,color):
        w=s.window()
        if hasattr(w,'_toasts'): w._toasts.toast(msg,color)

# ─── Per-App Bandwidth Chart ───────────────────────────────────────────────
_BW_COLORS=[C['blue'],C['green'],C['red'],C['peach'],C['mauve'],C['teal'],C['sky'],C['yellow']]

class BWPerApp:
    """Track per-process connection counts and system bandwidth over time."""
    def __init__(s,max_pts=120):
        s._max=max_pts; s._lock=Lock()
        s._sys_up=[]; s._sys_dn=[]; s._ts=[]
        s._proc_conns=defaultdict(list)
        s._procs_order=[]
    def update(s,conns):
        up,dn=bw.rates(); now=time.time()
        proc_count=defaultdict(int)
        for c in conns:
            if c.proc and c.proc!='?': proc_count[c.proc]+=1
        with s._lock:
            s._sys_up.append(up); s._sys_dn.append(dn); s._ts.append(now)
            for proc in list(s._proc_conns.keys()):
                if proc not in proc_count: s._proc_conns[proc].append(0)
                else: s._proc_conns[proc].append(proc_count[proc])
            for proc,cnt in proc_count.items():
                if proc not in s._proc_conns:
                    s._proc_conns[proc]=[0]*(len(s._ts)-1)+[cnt]
            if len(s._ts)>s._max:
                trim=len(s._ts)-s._max
                s._sys_up=s._sys_up[trim:]; s._sys_dn=s._sys_dn[trim:]; s._ts=s._ts[trim:]
                for p in list(s._proc_conns): s._proc_conns[p]=s._proc_conns[p][trim:]
            active={p for p,vals in s._proc_conns.items() if any(v>0 for v in vals[-10:])}
            s._procs_order=sorted(active,key=lambda p:sum(s._proc_conns[p][-10:]),reverse=True)[:8]
    def snapshot(s):
        with s._lock:
            return {'sys_up':list(s._sys_up),'sys_dn':list(s._sys_dn),'ts':list(s._ts),
                'procs':{p:list(s._proc_conns[p]) for p in s._procs_order}}

class BWChartWidget(QWidget):
    """Stacked area chart of per-process connection activity + system bandwidth."""
    def __init__(s,parent=None):
        super().__init__(parent); s._data=None; s.setMinimumHeight(_dp(160)); s.setMaximumHeight(_dp(220))
    def set_data(s,data): s._data=data; s.update()
    def paintEvent(s,e):
        if not s._data or not s._data['ts']: return
        p=QPainter(s); p.setRenderHint(QPainter.Antialiasing)
        w,h=s.width(),s.height()
        p.fillRect(s.rect(),QColor(C['mantle']))
        p.setPen(QPen(QColor(C['s0']),1)); p.drawRect(0,0,w-1,h-1)
        margin_l,margin_r,margin_t,margin_b=_dp(50),_dp(8),_dp(8),_dp(20)
        cw=w-margin_l-margin_r; ch=h-margin_t-margin_b
        if cw<10 or ch<10: p.end(); return
        pts=len(s._data['ts']); procs=s._data.get('procs',{})
        if not procs and not s._data['sys_up']:
            p.setPen(QColor(C['dim'])); p.drawText(s.rect(),Qt.AlignCenter,"No data yet")
            p.end(); return
        max_conns=max(max((sum(procs[pr][i] for pr in procs) for i in range(pts)),default=1),1)
        for gi in range(5):
            y=margin_t+int(ch*(gi/4)); p.setPen(QPen(QColor(C['s0']),1,Qt.DotLine))
            p.drawLine(margin_l,y,w-margin_r,y)
            p.setPen(QColor(C['dim'])); p.setFont(QFont("Segoe UI",_dp(7)))
            val=int(max_conns*(1-gi/4)); p.drawText(0,y-_dp(5),margin_l-_dp(4),_dp(12),Qt.AlignRight|Qt.AlignVCenter,str(val))
        proc_names=list(procs.keys())
        for pi,pname in enumerate(reversed(proc_names)):
            color=QColor(_BW_COLORS[pi%len(_BW_COLORS)])
            vals=procs[pname]; base=[0]*pts
            for pp in proc_names[proc_names.index(pname)+1:]:
                for i in range(pts): base[i]+=procs[pp][i]
            poly=QPolygonF()
            for i in range(pts):
                x=margin_l+int(cw*i/(max(pts-1,1))); y=margin_t+ch-int(ch*(base[i]+vals[i])/max_conns)
                poly.append(QPointF(x,y))
            for i in range(pts-1,-1,-1):
                x=margin_l+int(cw*i/(max(pts-1,1))); y=margin_t+ch-int(ch*base[i]/max_conns)
                poly.append(QPointF(x,y))
            color.setAlpha(100); p.setBrush(color); p.setPen(Qt.NoPen); p.drawPolygon(poly)
            color.setAlpha(200); p.setPen(QPen(color,_dp(1.5)))
            for i in range(1,pts):
                x0=margin_l+int(cw*(i-1)/(max(pts-1,1))); y0=margin_t+ch-int(ch*(base[i-1]+vals[i-1])/max_conns)
                x1=margin_l+int(cw*i/(max(pts-1,1))); y1=margin_t+ch-int(ch*(base[i]+vals[i])/max_conns)
                p.drawLine(x0,y0,x1,y1)
        p.setPen(QColor(C['dim'])); p.setFont(QFont("Segoe UI",_dp(7)))
        p.drawText(margin_l,h-margin_b,cw,margin_b,Qt.AlignLeft|Qt.AlignTop,"oldest")
        p.drawText(margin_l,h-margin_b,cw,margin_b,Qt.AlignRight|Qt.AlignTop,"now")
        lx=margin_l+_dp(5); ly=margin_t+_dp(3)
        for pi,pname in enumerate(proc_names[:8]):
            color=QColor(_BW_COLORS[pi%len(_BW_COLORS)])
            p.setBrush(color); p.setPen(Qt.NoPen); p.drawRoundedRect(lx,ly,_dp(8),_dp(8),2,2)
            p.setPen(QColor(C['text'])); p.drawText(lx+_dp(11),ly,_dp(120),_dp(10),Qt.AlignLeft|Qt.AlignVCenter,pname[:20])
            ly+=_dp(12)
        up,dn=bw.rates()
        p.setPen(QColor(C['blue'])); p.drawText(w-_dp(140),margin_t+_dp(3),_dp(130),_dp(10),Qt.AlignRight,f"▲ {bw.fmt(up)}")
        p.setPen(QColor(C['teal'])); p.drawText(w-_dp(140),margin_t+_dp(15),_dp(130),_dp(10),Qt.AlignRight,f"▼ {bw.fmt(dn)}")
        p.end()

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 1B: FW ACTIVITY — Live connections, firewall monitoring
# ═════════════════════════════════════════════════════════════════════════════
class FWActivityTab(QWidget):
    def __init__(s,db,hm,cdb,learn):
        super().__init__(); s.db=db; s.hm=hm; s.cdb=cdb; s.learn=learn
        s._conns=[]; s._conn_map={}; s._fw_blocked_ips=set()
        s._last_hash=0; s._first_load=True; s._bw_app=BWPerApp()
        s._build()
        s._tmr=QTimer(s); s._tmr.timeout.connect(s._auto_refresh); s._tmr.start(3000)
    def _build(s):
        lo=QVBoxLayout(s); lo.setContentsMargins(_dp(16),_dp(12),_dp(16),_dp(8)); lo.setSpacing(_dp(8))
        sr=QHBoxLayout(); sr.setSpacing(_dp(8))
        s.c_live=_stat("Connections","0",C['sky'],"\u21C4"); s.c_fw=_stat("FW Rules","0",C['mauve'],"\u229B")
        s.c_fwb=_stat("FW Blocked","0",C['red'],"\u2718"); s.c_procs=_stat("Processes","0",C['teal'],"\u25A3")
        for c in [s.c_live,s.c_fw,s.c_fwb,s.c_procs]: sr.addWidget(c)
        lo.addLayout(sr)
        tb=QHBoxLayout(); tb.setSpacing(_dp(5))
        s.search=QLineEdit(); s.search.setPlaceholderText("Search host, IP, process, or category...")
        s.search.setAccessibleName("Search live connections")
        s.search.setFixedHeight(_dp(30)); s.search.setClearButtonEnabled(True)
        s._search_debounce=QTimer(s); s._search_debounce.setSingleShot(True); s._search_debounce.setInterval(200)
        s._search_debounce.timeout.connect(s._on_search)
        s.search.textChanged.connect(lambda:s._search_debounce.start()); tb.addWidget(s.search,1)
        s.filt=QComboBox(); s.filt.addItems(["All Connections","FW Blocked","Outbound","Inbound/Listen"])
        s.filt.setAccessibleName("Filter live connections")
        s.filt.currentIndexChanged.connect(s._on_search); tb.addWidget(s.filt)
        lo.addLayout(tb)
        s.tbl=_tbl(["Host / IP","Process","Port","FW Status","Country","Category"],0,row_h=30)
        s.tbl.set_empty_state("No live connections shown","Connection monitoring starts automatically. Clear filters if traffic is active.")
        s.tbl.setAccessibleName("Live connections table")
        s.tbl.setColumnWidth(1,_dp(130)); s.tbl.setColumnWidth(2,_dp(55)); s.tbl.setColumnWidth(3,_dp(90))
        s.tbl.setColumnWidth(4,_dp(55)); s.tbl.setColumnWidth(5,_dp(100))
        s.tbl.customContextMenuRequested.connect(s._ctx); s.tbl.doubleClicked.connect(s._dbl)
        lo.addWidget(s.tbl,1)
        s._overlay=LoadingOverlay(s.tbl)
        s._chart=BWChartWidget(s); lo.addWidget(s._chart)
        ib=QHBoxLayout()
        s.info=QLabel(""); s.info.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); ib.addWidget(s.info)
        ib.addStretch()
        s.lock_cb=QCheckBox("Lockdown"); s.lock_cb.setChecked(load_cfg().get('lockdown',False))
        s.lock_cb.toggled.connect(s._toggle_lockdown)
        s.lock_cb.setToolTip("Block all outbound — whitelist programs via right-click"); ib.addWidget(s.lock_cb)
        s.obs_cb=QCheckBox("Observe"); s.obs_cb.setChecked(s.learn.observe)
        s.obs_cb.toggled.connect(lambda v:s.learn.set_observe(v))
        s.obs_cb.setToolTip("Allow all, log silently — review and create rules later"); ib.addWidget(s.obs_cb)
        s.learn_cb=QCheckBox("Learning"); s.learn_cb.setChecked(s.learn.enabled)
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
        h=hash(tuple(c.key for c in conns))
        if h==s._last_hash: s._overlay.hide_loading(); return
        s._last_hash=h; s._filtered_conns=conns
        saved=s._sel_domain()
        s._rebuild_fw_cache(); blocked_hosts=s.db.get_blocked_set()
        vscroll=s.tbl.verticalScrollBar().value()
        s.tbl.setUpdatesEnabled(False); s.tbl.setSortingEnabled(False); s.tbl.setRowCount(len(conns))
        for i,c in enumerate(conns):
            host=c.host if c.host not in ('-','') else c.ra
            _icon_item(s.tbl,i,0,host,c.host if c.host not in ('-','') else None)
            proc_label=f"{c.sig} {c.proc} ({c.pid})" if c.sig else f"{c.proc} ({c.pid})"
            pi=QTableWidgetItem(proc_label)
            if c.pproc: pi.setToolTip(f"Parent: {c.pproc} (PID {c.ppid})")
            s.tbl.setItem(i,1,pi)
            it_port=QTableWidgetItem(); it_port.setData(Qt.DisplayRole,int(c.rp) if c.rp.isdigit() else 0); it_port.setText(c.rp)
            s.tbl.setItem(i,2,it_port)
            f_blocked=c.ra in s._fw_blocked_ips
            h_blocked=c.host in blocked_hosts if c.host not in ('-','') else False
            t_ip=c.ra in _threat_ips
            t_dom=c.host.lower() in _threat_domains if c.host not in ('-','') else False
            if t_ip or t_dom: s.tbl.setCellWidget(i,3,_badge("THREAT",C['peach']))
            elif f_blocked: s.tbl.setCellWidget(i,3,_badge("FW BLOCK",C['mauve']))
            elif h_blocked: s.tbl.setCellWidget(i,3,_badge("HOSTS",C['red']))
            else: s.tbl.setCellWidget(i,3,_badge("\u2014",C['dim']))
            s.tbl.setItem(i,4,QTableWidgetItem(c.cc or ""))
            s.tbl.setItem(i,5,QTableWidgetItem(c.category))
            if f_blocked or h_blocked:
                for col in [0,1,2,4,5]:
                    it=s.tbl.item(i,col)
                    if it: it.setBackground(_row_tint())
        s.tbl.setSortingEnabled(True); s.tbl.setUpdatesEnabled(True)
        s._restore_sel(saved); s.tbl.verticalScrollBar().setValue(vscroll)
        s.info.setText(f"{len(conns)} connections")
        s._overlay.hide_loading()
    def update_conns(s,conns):
        s._conns=conns
        s._conn_map={}
        for c in conns:
            if c.host and c.host not in ('-','','...'): s._conn_map[c.host]=c
        s._last_hash=0; s._load_conns()
        _sv(s.c_live,len(conns))
        s._bw_app.update(conns); s._chart.set_data(s._bw_app.snapshot())
        if s.learn.enabled and not s.learn.observe:
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
    def _get_conn_at_row(s,row):
        if row<0: return None
        it=s.tbl.item(row,0)
        if not it: return None
        display=it.text()
        fc=getattr(s,'_filtered_conns',[])
        for c in fc:
            host=c.host if c.host not in ('-','') else c.ra
            if host==display: return c
        return None
    def _ctx(s,pos):
        row=s.tbl.currentRow(); c=s._get_conn_at_row(row)
        if not c: return
        m=QMenu(s); m.setStyleSheet(CTX)
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
            fm.addAction(f"Allow {c.proc} Out").triggered.connect(lambda:s._fw_allow_prog(c.path))
        fm.addAction("Custom Rule \u2192").triggered.connect(lambda:s._fw_custom(c))
        if c.host not in ('-','','...') and c.proc not in ('?','System'):
            pm=m.addMenu("Per-Process Rules"); pm.setStyleSheet(CTX)
            pm.addAction(f"Block {c.host} for {c.proc}").triggered.connect(lambda:(s.db.add_proc_rule(c.proc,c.host,'block'),s._toast(f"Blocked {c.host} for {c.proc}",C['red'])))
            pm.addAction(f"Allow {c.host} for {c.proc}").triggered.connect(lambda:(s.db.add_proc_rule(c.proc,c.host,'allow'),s._toast(f"Allowed {c.host} for {c.proc}",C['green'])))
        lm=m.addMenu("Learning"); lm.setStyleSheet(CTX)
        lm.addAction(f"Trust {c.proc}").triggered.connect(lambda:(s.learn.trust(c.proc),s._toast(f"Trusted {c.proc}",C['green'])))
        lm.addAction(f"Untrust {c.proc}").triggered.connect(lambda:(s.learn.untrust(c.proc),s._toast(f"Untrusted {c.proc}",C['red'])))
        m.addSeparator()
        if c.pid>0: m.addAction(f"Kill (PID {c.pid})").triggered.connect(lambda:s._kill(c.pid,c.proc))
        if c.host not in ('-','','...'): m.addAction("DNS Inspect").triggered.connect(lambda:DNSInspectDlg(c.host,s).exec_())
        m.addAction("Research \u2192").triggered.connect(lambda:open_research(c.host if c.host not in ('-','') else c.ra))
        m.addAction("Copy IP").triggered.connect(lambda:QApplication.clipboard().setText(c.ra))
        m.exec_(s.tbl.viewport().mapToGlobal(pos))
    def _dbl(s,idx):
        c=s._get_conn_at_row(idx.row())
        if c: s._open_detail(c)
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
        root=get_root(d); s.db.add_root(d,'blocked','manual'); s.hm.block(root); s.db.log_event(root,'blocked','','Hosts block root')
        s._last_hash=0; s._refresh(); s._toast(f"Blocked {root}",C['red'])
    def _act_allow(s,d):
        s.db.add_domain(d,'whitelisted','manual'); s.hm.unblock(d); s.db.log_event(d,'whitelisted','','Allowed')
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
    def _fw_allow_prog(s,path):
        name=f"{FW_PFX}Allow_{Path(path).stem}"
        if not fw.exists(name):
            fw.create(name,"Outbound","Allow",program=path,desc=f"HostsGuard whitelist {datetime.datetime.now():%Y-%m-%d %H:%M}")
            s._toast(f"Allowed {Path(path).name} outbound",C['green'])
        else: s._toast("Allow rule already exists",C['dim'])
    def _fw_custom(s,ci):
        pf={'addr':ci.ra,'prog':ci.path or '','proto':ci.proto,'name':f'{FW_PFX}Block_{ci.proc.replace(".exe","")}'}
        dlg=NewRuleDlg(s,pf)
        if dlg.exec_()==QDialog.Accepted:
            dd=dlg.data(); fw.create(dd['name'],dd['dir'],dd['action'],dd.get('addr',''),dd.get('proto',''),dd.get('prog',''))
            s._rebuild_fw_cache(); s._last_hash=0; s._refresh(); s._toast(f"Created {dd['name']}",C['green'])
    def _kill(s,pid,name):
        if pid>0 and fw.kill_conn(pid): s._toast(f"Killed {name}",C['peach'])
    def _toggle_lockdown(s,on):
        action="Block" if on else "Allow"
        def _bg():
            ok,_=_ps(f'Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction {action}',10)
            if ok:
                cfg=load_cfg(); cfg['lockdown']=on; save_cfg(cfg)
                msg=f"Lockdown {'ON — all outbound blocked' if on else 'OFF — outbound allowed'}"
                ui_call(lambda:s._toast(msg,C['red'] if on else C['green']))
            else:
                # Don't pretend: revert the checkbox and say the policy change failed.
                def _revert():
                    s.lock_cb.blockSignals(True); s.lock_cb.setChecked(not on); s.lock_cb.blockSignals(False)
                    s._toast("Failed to change firewall outbound policy",C['red'])
                ui_call(_revert)
        threading.Thread(target=_bg,daemon=True).start()
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
        s.d_search=QLineEdit(); s.d_search.setPlaceholderText("Search domain, source, or note..."); s.d_search.setFixedHeight(_dp(30))
        s.d_search.setAccessibleName("Search managed domains"); s.d_search.setClearButtonEnabled(True)
        s.d_search.textChanged.connect(s._load_d); tr.addWidget(s.d_search,1)
        s.d_filt=QComboBox(); s.d_filt.addItems(["All","Blocked","Allowed"]); s.d_filt.setAccessibleName("Filter managed domains by status"); s.d_filt.currentIndexChanged.connect(s._load_d); tr.addWidget(s.d_filt)
        s.d_src=QComboBox(); s.d_src.addItem("All Sources"); s.d_src.setAccessibleName("Filter managed domains by source"); s.d_src.currentIndexChanged.connect(s._load_d); tr.addWidget(s.d_src)
        tr.addWidget(_tbtn("Refresh","dim",s._sync_and_load,65))
        tr.addWidget(_tbtn("+ Add","primary",s._add,60)); tr.addWidget(_tbtn("Sync > Hosts","dim",s._sync,100))
        dl.addLayout(tr)
        s.d_tbl=_tbl(["Domain","Status","Source","Hits","Modified"],0)
        s.d_tbl.set_empty_state("No managed domains","Add a domain, import a list, or sync the hosts file to build a policy.")
        s.d_tbl.setAccessibleName("Managed domains table")
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
        s.paste=QPlainTextEdit(); s.paste.setPlaceholderText("Paste domains, one per line"); s.paste.setAccessibleName("Paste domains"); s.paste.setMaximumHeight(_dp(60)); mgl.addWidget(s.paste)
        mr=QHBoxLayout(); mr.addWidget(_tbtn("Add to Hosts","primary",s._paste_h,100)); mr.addWidget(_tbtn("DB Only","dim",s._paste_db,70)); mr.addStretch()
        mgl.addLayout(mr); bl.addWidget(mg)
        sg=QGroupBox("Auto-Refresh"); sgl=QVBoxLayout(sg)
        sr=QHBoxLayout(); sr.setSpacing(_dp(5))
        sr.addWidget(QLabel("Refresh selected lists every"))
        s._ref_hours=QComboBox(); s._ref_hours.addItems(["Off","6h","12h","24h","48h"])
        cfg=load_cfg(); rh=cfg.get('blocklist_refresh_hours',0)
        idx={'0':0,'6':1,'12':2,'24':3,'48':4}.get(str(rh),0); s._ref_hours.setCurrentIndex(idx)
        s._ref_hours.currentIndexChanged.connect(s._save_refresh)
        sr.addWidget(s._ref_hours)
        sr.addWidget(_tbtn("Subscribe Checked","dim",s._subscribe,130)); sr.addStretch()
        sgl.addLayout(sr); bl.addWidget(sg)
        ag=QGroupBox("Allowlist Subscriptions"); agl=QVBoxLayout(ag)
        ad=QLabel("Domains from these URLs are whitelisted (never blocked), overriding blocklists. One URL per line.")
        ad.setWordWrap(True); ad.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); agl.addWidget(ad)
        s.allow_urls=QPlainTextEdit(); s.allow_urls.setMaximumHeight(_dp(54))
        s.allow_urls.setPlaceholderText("https://example.com/allowlist.txt")
        s.allow_urls.setAccessibleName("Allowlist subscription URLs")
        s.allow_urls.setPlainText("\n".join(load_cfg().get('allowlist_subscriptions',[]))); agl.addWidget(s.allow_urls)
        ar=QHBoxLayout(); ar.addWidget(_tbtn("Save & Apply Now","primary",s._apply_allowlists,140))
        s.allow_st=QLabel(""); s.allow_st.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); ar.addWidget(s.allow_st); ar.addStretch()
        agl.addLayout(ar); bl.addWidget(ag)
        s._sub.addTab(bw,"Blocklists")
        # Services — one-click block toggles for popular services
        sw=QWidget(); svl=QVBoxLayout(sw); svl.setContentsMargins(0,_dp(6),0,0); svl.setSpacing(_dp(6))
        sd=QLabel("One-click block popular services via the hosts file. Best-effort (exact "
                  "hostnames, no wildcards); pair with Block Encrypted DNS so apps can't bypass it.")
        sd.setWordWrap(True); sd.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); svl.addWidget(sd)
        sscroll=QScrollArea(); sscroll.setWidgetResizable(True); sscroll.setFrameShape(QFrame.NoFrame)
        sinner=QWidget(); sgl=QVBoxLayout(sinner); sgl.setContentsMargins(0,0,0,0); sgl.setSpacing(_dp(2))
        s._svc_cbs={}
        for name,domains in BLOCK_SERVICES.items():
            row=QWidget(); rl=QHBoxLayout(row); rl.setContentsMargins(_dp(4),0,_dp(4),0); rl.setSpacing(_dp(6))
            cb=QCheckBox(name); cb.setStyleSheet(f"font-size:{_dp(12)}px;")
            cb.toggled.connect(lambda on,n=name:s._toggle_service(n,on)); rl.addWidget(cb,1)
            dl=QLabel(f"{len(domains)} domains"); dl.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); rl.addWidget(dl)
            sgl.addWidget(row); s._svc_cbs[name]=cb
        sgl.addStretch(); sscroll.setWidget(sinner); svl.addWidget(sscroll,1)
        s._sub.addTab(sw,"Services")
        lo.addWidget(s._sub)
        s._sub.currentChanged.connect(lambda i: s._sync_and_load() if i==0 else s._reload() if i==1 else s._load_services() if i==3 else None)

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
        ui_call(s._load_d)
        ui_call(s._d_overlay.hide_loading)

    def _sync_and_load(s):
        """Manual refresh — re-read hosts file, sync to DB, reload table."""
        s._d_overlay.show_loading("Syncing hosts file")
        threading.Thread(target=s._bg_sync_and_load,daemon=True).start()

    def _load_d(s):
        q=s.d_search.text().strip() or None; f=s.d_filt.currentText().lower()
        st=None if f=='all' else f.replace('allowed','whitelisted')
        src=s.d_src.currentText() if s.d_src.currentIndex()>0 else None
        rows=s.db.get_domains(status=st,search=q,source=src)
        srcs=s.db.get_sources()
        s.d_src.blockSignals(True)
        cur=s.d_src.currentText(); s.d_src.clear(); s.d_src.addItem("All Sources")
        for src_name in srcs: s.d_src.addItem(src_name)
        idx=s.d_src.findText(cur)
        if idx>=0: s.d_src.setCurrentIndex(idx)
        s.d_src.blockSignals(False)
        s.d_tbl.setSortingEnabled(False); s.d_tbl.setRowCount(len(rows))
        for i,(domain,status,cat,source,added,mod,hits,notes) in enumerate(rows):
            _icon_item(s.d_tbl,i,0,domain,domain)
            s.d_tbl.setCellWidget(i,1,_badge(status.upper(),C['red'] if status=='blocked' else C['green']))
            s.d_tbl.setItem(i,2,QTableWidgetItem((source or "")[:20]))
            s.d_tbl.setItem(i,3,_num_item(hits)); s.d_tbl.setItem(i,4,QTableWidgetItem((mod or "")[:19]))
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
            src_val=(cur[0][3] if cur and cur[0][3] else None)
            if src_val:
                sm=m.addMenu(f"Source: {src_val[:20]}"); sm.setStyleSheet(CTX)
                sm.addAction("Allow all from this source").triggered.connect(lambda:s._toggle_src(src_val,'whitelisted'))
                sm.addAction("Block all from this source").triggered.connect(lambda:s._toggle_src(src_val,'blocked'))
            m.addSeparator(); m.addAction("Research \u2192").triggered.connect(lambda:open_research(d))
            m.addAction("Copy").triggered.connect(lambda:QApplication.clipboard().setText(d))
        m.exec_(s.d_tbl.viewport().mapToGlobal(pos))

    def _tog(s,d,cur):
        new='whitelisted' if cur=='blocked' else 'blocked'; s.db.update_status(d,new)
        (s.hm.block if new=='blocked' else s.hm.unblock)(d); s._load_d(); s._toast(f"{'Blocked' if new=='blocked' else 'Allowed'} {d}",C['red'] if new=='blocked' else C['green'])
    def _tog_multi(s,ds):
        ct=0
        for d in ds:
            cur=s.db._q("SELECT status FROM domains WHERE domain=?",(d,)); st=cur[0][0] if cur else 'blocked'
            new='whitelisted' if st=='blocked' else 'blocked'; s.db.update_status(d,new)
            (s.hm.block if new=='blocked' else s.hm.unblock)(d,flush=False); ct+=1
        s.hm._flush(); s._load_d(); s._toast(f"Toggled {ct} domains",C['blue'])
    def _del(s,d): s.db.remove_domain(d); s.hm.unblock(d); s._load_d()
    def _del_multi(s,ds):
        for d in ds: s.db.remove_domain(d); s.hm.unblock(d)
        s._load_d()
    # Services (one-click block toggles)
    def _load_services(s):
        """Reflect actual hosts state: a service is checked only if ALL its domains are blocked."""
        blocked=s.hm.get_blocked()
        for name,cb in s._svc_cbs.items():
            on=all(d.lower() in blocked for d in BLOCK_SERVICES[name])
            cb.blockSignals(True); cb.setChecked(on); cb.blockSignals(False)
    def _toggle_service(s,name,on):
        domains=BLOCK_SERVICES.get(name,[])
        if not domains: return
        if on:
            ct=s.hm.block_bulk(domains)
            s.db.add_domains_bulk([(d.lower(),'blocked',f'service:{name}') for d in domains])
            s._toast(f"Blocked {name} ({ct} new)",C['red'])
        else:
            for d in domains: s.hm.unblock(d,flush=False); s.db.remove_domain(d)
            s.hm._flush()
            s._toast(f"Unblocked {name}",C['green'])
        if s._sub.currentIndex()==0: s._load_d()
    def _toggle_src(s,source,new_status):
        s.db.toggle_source(source,new_status)
        domains=s.db.get_domains(source=source)
        for r in domains:
            if new_status=='blocked': s.hm.block(r[0],flush=False)
            else: s.hm.unblock(r[0],flush=False)
        s.hm._flush(); s._load_d()
        s._toast(f"{'Blocked' if new_status=='blocked' else 'Allowed'} all from {source}",C['red'] if new_status=='blocked' else C['green'])
    def _add(s):
        d,ok=QInputDialog.getText(s,"Block Domain","Domain to block:"); d=d.strip().lower()
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
        if QMessageBox.question(s,"Reset hosts file",
            "Reset the hosts file to the Windows default template?\n\n"
            "HostsGuard creates a backup first, then removes current custom hosts entries.",
            QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:
            return
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
        if getattr(s,'_importing',False):
            # A scheduled auto-refresh must not clobber an in-flight manual import
            # (they share _iq/_ii/_cw; reassigning _cw drops a running QThread).
            s._toast("An import is already running",C['peach']); return
        warn=[n for n,_ in sources if n in _DEFENDER_WARN]
        if warn:
            r=QMessageBox.warning(s,"Windows Defender Warning",
                f"These lists block Microsoft telemetry domains:\n{', '.join(warn)}\n\n"
                "Windows Defender may flag your hosts file as "
                "'SettingsModifier:Win32/HostsFileHijack' (Severe).\n\n"
                "To prevent this, add the hosts file path to Defender exclusions:\n"
                "Settings → Virus & Threat Protection → Exclusions → Add\n"
                f"Path: {HOSTS_PATH}\n\nContinue importing?",
                QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
            if r!=QMessageBox.Yes: return
        # Warn if importing a very large list, or if the hosts file is already large.
        big=[n for n,_ in sources if n in _LARGE_LISTS]
        cur=len(s.hm.get_blocked())
        if big or cur>=LARGE_HOSTS_WARN:
            reason=(f"selected lists ({', '.join(big)}) each add 100k+ domains" if big
                    else f"your hosts file already has {cur:,} entries")
            r=QMessageBox.warning(s,"Large hosts file",
                f"Heads up — {reason}.\n\n"
                "A very large hosts file (100k+ entries) can make the Windows DNS "
                "Client (svchost) spike CPU and slow name resolution. For blocking at "
                "this scale, firewall IP rules or a network-wide DNS blocker are lighter.\n\n"
                "Continue importing?",
                QMessageBox.Yes|QMessageBox.No,QMessageBox.No)
            if r!=QMessageBox.Yes: return
        s._importing=True
        s.bl_prog.setVisible(True); s.bl_prog.setRange(0,len(sources)); s.bl_prog.setValue(0)
        s._iq=list(sources); s._ii=0; s._it=0; s._do_next()
    def _do_next(s):
        if s._ii>=len(s._iq):
            s._importing=False
            s.bl_prog.setVisible(False); s.bl_st.setText(f"Done! {s._it} domains")
            s._reapply_db_allowlist()  # keep allowlisted domains out of the hosts file
            s._toast(f"Imported {s._it} from {len(s._iq)} sources",C['green']); s._sync_and_load()
            total=len(s.hm.get_blocked())
            if total>=LARGE_HOSTS_WARN:
                s._toast(f"Hosts file now {total:,} entries — watch DNS Client CPU",C['peach'])
            return
        name,url=s._iq[s._ii]; s.bl_st.setText(f"{name}...")
        if name in s._chk: s._chk[name][2].setText("\u2026")
        s._cw=ImpWorker(name,url,s.hm,s.db); s._cw.done.connect(s._on_imp); s._cw.start()
    def _on_imp(s,name,ct,total,err):
        if name in s._chk:
            if err:
                s._chk[name][2].setText("\u2717")
                s._chk[name][2].setStyleSheet(f"color:{C['red']};font-size:{_dp(10)}px;min-width:{_dp(45)}px;")
            else:
                existing=total-ct
                lbl=f"\u2713 +{ct}" if ct else f"\u2713 {total}"
                if existing>0 and ct>0: lbl+=f" ({existing} dup)"
                s._chk[name][2].setText(lbl)
                s._chk[name][2].setStyleSheet(f"color:{C['green']};font-size:{_dp(10)}px;min-width:{_dp(45)}px;")
        s._it+=ct; s._ii+=1; s.bl_prog.setValue(s._ii); s._do_next()
    def _paste_h(s):
        ds=[d.strip().lower() for d in s.paste.toPlainText().splitlines() if looks_like_domain(d.strip().lower())]
        if not ds: s._toast("No valid domains to add",C['peach']); return
        ct=s.hm.block_bulk(ds)
        s.db.add_domains_bulk([(d,'blocked','paste') for d in ds])
        s._toast(f"Added {ct} to hosts file",C['green']); s.paste.clear(); s._load_d()
    def _paste_db(s):
        ds=[d.strip().lower() for d in s.paste.toPlainText().splitlines() if looks_like_domain(d.strip().lower())]
        if not ds: s._toast("No valid domains to add",C['peach']); return
        s.db.add_domains_bulk([(d,'blocked','paste') for d in ds])
        s._toast(f"Added {len(ds)} to database",C['green']); s.paste.clear(); s._load_d()
    def _save_refresh(s,idx):
        hours=[0,6,12,24,48][idx]
        cfg=load_cfg(); cfg['blocklist_refresh_hours']=hours; save_cfg(cfg)
        s._toast(f"Auto-refresh: {'off' if not hours else f'every {hours}h'}",C['blue'])
    def _subscribe(s):
        sel=[n for n,(cb,_,_) in s._chk.items() if cb.isChecked()]
        cfg=load_cfg(); cfg['blocklist_subscriptions']=sel; save_cfg(cfg)
        s._toast(f"Subscribed to {len(sel)} lists",C['green'])
    def _apply_allowlists(s):
        urls=[u.strip() for u in s.allow_urls.toPlainText().splitlines() if u.strip().startswith(('http://','https://'))]
        cfg=load_cfg(); cfg['allowlist_subscriptions']=urls; save_cfg(cfg)
        if not urls: s.allow_st.setText("No allowlist URLs"); return
        s.allow_st.setText("Applying…")
        s._aw=AllowWorker(urls,s.hm,s.db); s._aw.done.connect(s._on_allow); s._aw.start()
    def _on_allow(s,count,err):
        if err: s.allow_st.setText("✗ "+err); s._toast(f"Allowlist error: {err}",C['red']); return
        s.allow_st.setText(f"✓ {count} allowed")
        s._toast(f"Allowlisted {count} domains",C['green']); s._load_d()
    def _reapply_db_allowlist(s):
        """Remove any currently-blocked hosts entry whose DB status is whitelisted —
        keeps allowlist entries out of the hosts file after a blocklist import (local,
        no network refetch)."""
        blocked=s.hm.get_blocked(); changed=False
        for r in s.db.get_domains(status='whitelisted'):
            if r[0] in blocked: s.hm.unblock(r[0],flush=False); changed=True
        if changed: s.hm._flush()
    def _toast(s,msg,color):
        w=s.window()
        if hasattr(w,'_toasts'): w._toasts.toast(msg,color)

class ImpWorker(QThread):
    done=Signal(str,int,int,str)
    def __init__(s,name,url,hm,db): super().__init__(); s.name,s.url,s.hm,s.db=name,url,hm,db
    def run(s):
        try:
            req=urllib.request.Request(s.url,headers={'User-Agent':f'HostsGuard/{VER}'})
            with urllib.request.urlopen(req,timeout=30) as resp:
                lines=resp.read().decode('utf-8',errors='replace').splitlines()
            domains=[d for l in lines if (d:=norm_line(l,False)) and looks_like_domain(d)]
            total=len(domains)
            ct=s.hm.block_bulk(domains,flush=False)
            s.db.add_domains_bulk([(d,'blocked',f'list:{s.name}') for d in domains])
            s.hm._flush(); s.done.emit(s.name,ct,total,"")
        except Exception as e: s.done.emit(s.name,0,0,str(e)[:40])

class AllowWorker(QThread):
    """Fetch allowlist URLs and whitelist their domains (unblock + mark whitelisted),
    so blocklists never re-block them (add_domains_bulk preserves 'whitelisted')."""
    done=Signal(int,str)
    def __init__(s,urls,hm,db): super().__init__(); s.urls,s.hm,s.db=urls,hm,db
    def run(s):
        try:
            doms=set()
            for url in s.urls:
                try:
                    req=urllib.request.Request(url,headers={'User-Agent':f'HostsGuard/{VER}'})
                    with urllib.request.urlopen(req,timeout=30) as resp:
                        for l in resp.read().decode('utf-8',errors='replace').splitlines():
                            d=norm_line(l,False)
                            if d and looks_like_domain(d): doms.add(d)
                except Exception as e: log.warning(f"allowlist {url}: {e}")
            if doms:
                s.db.add_domains_bulk([(d,'whitelisted','allowlist') for d in doms])
                for d in doms: s.hm.unblock(d,flush=False)
                s.hm._flush()
            s.done.emit(len(doms),"")
        except Exception as e: s.done.emit(0,str(e)[:60])

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
        s.fw_s=QLineEdit(); s.fw_s.setPlaceholderText("Search rule name, program, or remote address..."); s.fw_s.setFixedHeight(_dp(30))
        s.fw_s.setAccessibleName("Search firewall rules"); s.fw_s.setClearButtonEnabled(True)
        s.fw_s.textChanged.connect(s._apply); tb.addWidget(s.fw_s,1)
        s.fw_f=QComboBox(); s.fw_f.addItems(["All","HG Only","Block","Allow","Inbound","Outbound"])
        s.fw_f.setAccessibleName("Filter firewall rules")
        s.fw_f.currentIndexChanged.connect(s._apply); tb.addWidget(s.fw_f)
        tb.addWidget(_tbtn("\u21BB Refresh","primary",s._refresh,75))
        tb.addWidget(_tbtn("+ Rule","dim",s._new,60)); lo.addLayout(tb)
        qa=QHBoxLayout(); qa.setSpacing(_dp(5))
        qa.addWidget(_tbtn("Block IP Out","danger",s._qblock_ip,85))
        qa.addWidget(_tbtn("Block IP In+Out","danger",s._qblock_ip_both,105))
        qa.addWidget(_tbtn("Block Program","danger",s._qblock_prog,110))
        qa.addWidget(_tbtn("Enable Profiles","dim",s._profiles,110))
        qa.addWidget(_tbtn("Save Baseline","dim",s._save_baseline,95))
        qa.addWidget(_tbtn("Show Drift","dim",s._show_drift,80)); qa.addStretch()
        qa.addWidget(_tbtn("Delete All HG","danger",s._del_all_hg,115)); lo.addLayout(qa)
        s.tbl=_tbl(["","Name","Dir","Action","Proto","Remote","Program","Src"],1,row_h=28)
        s.tbl.set_empty_state("No firewall rules shown","Refresh rules or clear the current search/filter.")
        s.tbl.setAccessibleName("Firewall rules table")
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
        ui_call(lambda:s.prof.setText("Profiles: "+' \u00B7 '.join(parts)))
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
                orphan=s._is_orphan(r)
                pit=QTableWidgetItem((prog+"  \u26A0") if orphan else prog)
                if orphan:
                    pit.setForeground(QColor(C['peach']))
                    pit.setToolTip(f"Program no longer exists \u2014 this rule matches nothing (likely moved by an update):\n{r.program}\nRight-click \u2192 Re-bind program.")
                s.tbl.setItem(i,6,pit)
                si=QTableWidgetItem(r.source or ""); si.setForeground(QColor(C['blue'] if r.source=="hostsguard" else C['dim'])); s.tbl.setItem(i,7,si)
            s.tbl.setSortingEnabled(True)
            hg=sum(1 for r in s._rules if r.source=="hostsguard")
            orph=sum(1 for r in s._rules if s._is_orphan(r))
            s.info.setText(f"{len(rules)} shown \u00B7 {len(s._rules)} total \u00B7 {hg} HG"+(f" \u00B7 \u26A0 {orph} orphaned" if orph else ""))
        except Exception as e: s.info.setText(f"Error: {e}")
    @staticmethod
    def _is_orphan(r):
        """HG program rule whose target executable no longer exists \u2014 it silently
        stops enforcing (Windows FW matches by path; an app update that changes the
        install path orphans the rule)."""
        if r.source!="hostsguard" or not r.program: return False
        p=r.program.split(',')[0].strip()
        try: return bool(p) and not os.path.exists(p)
        except OSError: return False
    def _rebind(s,rule):
        old=rule.program.split(',')[0].strip() if rule.program else ""
        newp,_=QFileDialog.getOpenFileName(s,"Re-bind rule to program",str(Path(old).parent) if old else "","Executables (*.exe);;All (*)")
        if not newp: return
        # Recreate the rule against the new path, preserving direction/action, then drop the old one.
        direction="Inbound" if rule.direction=="In" else "Outbound"
        newname=f"{FW_PFX}{rule.action}_{Path(newp).stem}"+("_In" if rule.direction=="In" else "")
        if fw.create(newname,direction,rule.action,program=newp,desc=f"Re-bound by {APP}"):
            fw.delete(rule.name)
            s._remove_local(rule.name)
            s._inject_rule(newname,rule.direction,rule.action,program=newp)
            s._toast(f"Re-bound to {Path(newp).name}",C['green'])
        else:
            s._toast("Re-bind failed",C['red'])

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
            if rule.source=="hostsguard" and rule.program:
                m.addAction("Re-bind program…").triggered.connect(lambda:s._rebind(rule))
            if rule.program and not s._is_orphan(rule):
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

    def _create_from_dialog(s,d):
        """Validate + create a rule from NewRuleDlg data. Shared by _new/_dup."""
        if not d['name'][len(FW_PFX):].strip(): s._toast("Rule name is required",C['peach']); return
        if d.get('addr') and not NewRuleDlg._addr_ok(d['addr']):
            s._toast(f"Invalid remote address: {d['addr']}",C['peach']); return
        fw.create(d['name'],d['dir'],d['action'],d.get('addr',''),d.get('proto',''),d.get('prog',''))
        dr="In" if d['dir']=="Inbound" else "Out"
        s._inject_rule(d['name'],dr,d['action'],d.get('addr',''),d.get('prog','')); s._toast(f"Created {d['name']}",C['green'])

    def _dup(s,r):
        pf={'name':r.name,'dir':{'In':'Inbound','Out':'Outbound'}.get(r.direction,'Outbound'),
            'action':r.action,'proto':r.protocol,'addr':r.remote_addr if r.remote_addr!='Any' else '','prog':r.program}
        dlg=NewRuleDlg(s,pf)
        if dlg.exec_()==QDialog.Accepted: s._create_from_dialog(dlg.data())

    def _new(s):
        dlg=NewRuleDlg(s)
        if dlg.exec_()==QDialog.Accepted: s._create_from_dialog(dlg.data())

    def _qblock_ip(s):
        ip,ok=QInputDialog.getText(s,"Block outbound address","IP address, CIDR subnet, or range:")
        if ok and ip.strip():
            ip=ip.strip()
            if not valid_fw_addr(ip): s._toast(f"Invalid address: {ip}",C['peach']); return
            n=fw.block_ip(ip)
            if n: s._inject_rule(n,"Out","Block",remote_addr=ip); s._toast(f"Blocked {ip} outbound",C['red'])
            else: s._toast("Rule already exists",C['dim'])
    def _qblock_ip_both(s):
        ip,ok=QInputDialog.getText(s,"Block address in both directions","IP address, CIDR subnet, or range:")
        if ok and ip.strip():
            ip=ip.strip()
            if not valid_fw_addr(ip): s._toast(f"Invalid address: {ip}",C['peach']); return
            created=fw.block_ip_both(ip)
            if created:
                for n in created:
                    d="In" if "_In" in n else "Out"
                    s._inject_rule(n,d,"Block",remote_addr=ip)
                s._toast(f"Blocked {ip} in+out ({len(created)} rules)",C['red'])
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
    def _profiles(s):
        ok,_=_ps("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",10)
        s._toast("Enabled all profiles" if ok else "Failed to enable profiles",C['green'] if ok else C['red'])
    def _del_all_hg(s):
        hg=[r.name for r in s._rules if r.source=="hostsguard" and r.name]
        if not hg: s._toast("No HG rules to delete",C['dim']); return
        if QMessageBox.question(s,"Delete HostsGuard firewall rules",
            f"Delete {len(hg)} HostsGuard-created firewall rules?\n\n"
            "Only HG_ rules are removed. Windows and third-party firewall rules are left untouched.",
            QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:
            return
        def _bg():
            for n in hg:
                try: fw.delete(n)
                except: pass
            ui_call(lambda:(setattr(s,'_rules',[r for r in s._rules if r.source!="hostsguard"]),fw.set_cache([r for r in fw.get_cached() if r.source!="hostsguard"]),s._apply(),s._toast(f"Deleted {len(hg)} HG rules",C['red'])))
        threading.Thread(target=_bg,daemon=True).start()
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
    def _save_baseline(s):
        bl={r.name:(r.direction,r.action,r.enabled,r.remote_addr,r.protocol,r.program) for r in s._rules}
        cfg=load_cfg(); cfg['fw_baseline']=bl; cfg['fw_baseline_ts']=datetime.datetime.now().isoformat(); save_cfg(cfg)
        s._toast(f"Baseline saved: {len(bl)} rules",C['green'])
    def _show_drift(s):
        cfg=load_cfg(); bl=cfg.get('fw_baseline')
        if not bl: s._toast("No baseline saved",C['peach']); return
        current={r.name:(r.direction,r.action,r.enabled,r.remote_addr,r.protocol,r.program) for r in s._rules}
        added=[n for n in current if n not in bl]; removed=[n for n in bl if n not in current]
        changed=[n for n in current if n in bl and current[n]!=bl[n]]
        if not added and not removed and not changed: s._toast("No drift from baseline",C['green']); return
        parts=[]
        if added: parts.append(f"+{len(added)} new")
        if removed: parts.append(f"-{len(removed)} removed")
        if changed: parts.append(f"~{len(changed)} changed")
        ts=cfg.get('fw_baseline_ts','?')[:19]
        msg=f"Drift from {ts}: {', '.join(parts)}"
        detail=[]
        for n in added[:10]: detail.append(f"+ {n}")
        for n in removed[:10]: detail.append(f"- {n}")
        for n in changed[:10]: detail.append(f"~ {n}")
        QMessageBox.information(s,"Firewall Drift",f"{msg}\n\n"+'\n'.join(detail))
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
        g1=QGroupBox("DNS + Network"); l1=QVBoxLayout(g1); l1.setSpacing(_dp(4))
        l1.addWidget(_tbtn("Flush DNS","primary",s._flush)); l1.addWidget(_tbtn("Winsock Reset","dim",s._winsock))
        l1.addWidget(_tbtn("DHCP Renew","dim",s._renew))
        l1.addWidget(_tbtn("Check Browser DoH","dim",s._check_browser_doh))
        s._doh_cb=QCheckBox("Block Encrypted DNS (DoH/DoT)")
        s._doh_cb.setToolTip("Firewall-block known DoH resolver IPs + DoT/DoQ port 853 so apps\n"
                             "can't tunnel DNS past hosts blocking. Your own DNS resolver is exempt.\n"
                             "Note: per-app DoH can't be fully closed without a driver/proxy.")
        s._doh_cb.toggled.connect(s._toggle_doh); l1.addWidget(s._doh_cb)
        s._tel_cb=QCheckBox("Block Windows Telemetry")
        s._tel_cb.setToolTip("One-click block ~28 Microsoft telemetry endpoints via the hosts file.\n"
                             "Note: this trips Defender's HostsFileHijack alert (add a hosts exclusion).")
        s._tel_cb.toggled.connect(s._toggle_telemetry); l1.addWidget(s._tel_cb)
        dr=QHBoxLayout(); dr.setSpacing(_dp(3))
        s._dns_cb=QComboBox(); s._dns_cb.addItems(["System Default","Cloudflare (1.1.1.1)","Google (8.8.8.8)","Quad9 (9.9.9.9)","AdGuard (94.140.14.14)","NextDNS (45.90.28.0)"])
        dr.addWidget(s._dns_cb,1); dr.addWidget(_btn("Apply","primary",s._apply_dns)); l1.addLayout(dr)
        l1.addWidget(_tbtn("Scheduled Blocking…","dim",s._open_schedules))
        s._rec_btn=_tbtn("Record Session","dim",s._toggle_rec); l1.addWidget(s._rec_btn)
        s._recording=False; s._rec_data=[]
        l1.addStretch(); grid.addWidget(g1)
        g2=QGroupBox("Config + Data"); l2=QVBoxLayout(g2); l2.setSpacing(_dp(4))
        l2.addWidget(_tbtn("Export Config","primary",s._export)); l2.addWidget(_tbtn("Import Config","dim",s._import))
        l2.addWidget(_tbtn("Export Connections","dim",s._export_conns))
        l2.addWidget(_tbtn("Prune History (30d)","dim",s._prune)); l2.addWidget(_tbtn("Clear Favicons","dim",s._clear_fav))
        l2.addWidget(_tbtn("Open Config Folder","dim",s._open)); l2.addStretch(); grid.addWidget(g2)
        g3=QGroupBox("Learning Mode"); l3=QVBoxLayout(g3); l3.setSpacing(_dp(4))
        s.learn_st=QLabel(""); l3.addWidget(s.learn_st)
        l3.addWidget(_tbtn("View Trusted","dim",s._show_t)); l3.addWidget(_tbtn("View Untrusted","dim",s._show_u))
        l3.addWidget(_tbtn("Clear All Trust","danger",s._clear_t)); l3.addStretch(); grid.addWidget(g3)
        # Recovery section
        g4=QGroupBox("Backup + Recovery"); l4=QVBoxLayout(g4); l4.setSpacing(_dp(4))
        s.rec_st=QLabel(""); s.rec_st.setWordWrap(True); s.rec_st.setStyleSheet(f"color:{C['dim']};font-size:{_dp(10)}px;"); l4.addWidget(s.rec_st)
        l4.addWidget(_tbtn("Restore Hosts from DB","primary",s._restore_hosts))
        l4.addWidget(_tbtn("Restore FW Rules from DB","primary",s._restore_fw))
        l4.addWidget(_tbtn("Sync Hosts File to DB","dim",s._sync_hosts_db))
        l4.addWidget(_tbtn("Backup Hosts Now","dim",lambda:(s.hm.backup(),s._toast("Backed up",C['green']))))
        l4.addWidget(_tbtn("Save Current to Profile","dim",s._save_profile))
        l4.addWidget(_tbtn("Re-baseline (accept current)","dim",s._rebaseline))
        l4.addWidget(_tbtn("Harden Hosts ACL","dim",s._harden_acl))
        l4.addWidget(_tbtn("Restore from StevenBlack","dim",s._restore_upstream))
        s._ar_cb=QCheckBox("Auto-restore on tamper"); s._ar_cb.setChecked(load_cfg().get('auto_restore_on_tamper',False))
        s._ar_cb.toggled.connect(s._toggle_auto_restore)
        s._ar_cb.setToolTip("Automatically restore hosts file from backup if externally modified"); l4.addWidget(s._ar_cb)
        l4.addStretch(); grid.addWidget(g4)
        lo.addLayout(grid)
        lg=QGroupBox("Event Log"); ll=QVBoxLayout(lg)
        lr=QHBoxLayout(); lr.setSpacing(_dp(5))
        s.log_s=QLineEdit(); s.log_s.setPlaceholderText("Search domain, action, process, or details..."); s.log_s.setFixedHeight(_dp(28))
        s.log_s.setAccessibleName("Search event log"); s.log_s.setClearButtonEnabled(True)
        s.log_s.textChanged.connect(s._log); lr.addWidget(s.log_s,1)
        s.log_f=QComboBox(); s.log_f.addItems(["All","blocked","whitelisted","fw_blocked"])
        s.log_f.setAccessibleName("Filter event log by action")
        s.log_f.currentIndexChanged.connect(s._log); lr.addWidget(s.log_f)
        lr.addWidget(_tbtn("Clear Log","danger",s._clear_log,90,"Delete all event log rows")); ll.addLayout(lr)
        s.log_tbl=_tbl(["Time","Domain","Action","Process","Details"],1,row_h=26)
        s.log_tbl.set_empty_state("No events recorded","Block, allow, import, and firewall actions will appear here.")
        s.log_tbl.setAccessibleName("Event log table")
        s.log_tbl.setColumnWidth(0,_dp(140)); s.log_tbl.setColumnWidth(2,_dp(75)); s.log_tbl.setColumnWidth(3,_dp(95)); s.log_tbl.setColumnWidth(4,_dp(170))
        ll.addWidget(s.log_tbl,1); lo.addWidget(lg,1)

    def showEvent(s,e):
        super().showEvent(e); s._log(); s._upd_learn(); s._upd_rec()
        # Reflect actual firewall state (rules persist across restarts) without re-toggling.
        s._doh_cb.blockSignals(True); s._doh_cb.setChecked(load_cfg().get('block_doh',False)); s._doh_cb.blockSignals(False)
        # Telemetry preset reflects actual hosts state (checked only if all blocked)
        tb=s.hm.get_blocked(); tel_on=all(d.lower() in tb for d in MS_TELEMETRY)
        s._tel_cb.blockSignals(True); s._tel_cb.setChecked(tel_on); s._tel_cb.blockSignals(False)
    def _open_schedules(s):
        ScheduleDlg(s.window()).exec_()
    def _toggle_telemetry(s,on):
        if on:
            r=QMessageBox.warning(s,"Windows Defender Warning",
                f"Blocking Microsoft telemetry endpoints ({len(MS_TELEMETRY)} domains) will likely "
                "trip Windows Defender's 'SettingsModifier:Win32/HostsFileHijack' (Severe).\n\n"
                "Add a Defender exclusion for the hosts file first:\n"
                "Settings → Virus & Threat Protection → Exclusions → Add\n"
                f"Path: {HOSTS_PATH}\n\nContinue?",
                QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
            if r!=QMessageBox.Yes:
                s._tel_cb.blockSignals(True); s._tel_cb.setChecked(False); s._tel_cb.blockSignals(False); return
            ct=s.hm.block_bulk(MS_TELEMETRY)
            s.db.add_domains_bulk([(d.lower(),'blocked','telemetry') for d in MS_TELEMETRY])
            s._toast(f"Blocked Windows telemetry ({ct} new)",C['red'])
        else:
            for d in MS_TELEMETRY: s.hm.unblock(d,flush=False); s.db.remove_domain(d.lower())
            s.hm._flush(); s._toast("Unblocked Windows telemetry",C['green'])
    def _toggle_doh(s,on):
        def _bg():
            if on:
                exempt=_system_dns_servers()
                created=fw.block_doh(exempt=exempt)
                cfg=load_cfg(); cfg['block_doh']=True; save_cfg(cfg)
                msg=(f"Encrypted DNS blocked ({len(created)} rules)"+(f", exempting your resolver" if exempt else "")) if created else "Failed to create DoH block rules"
                color=C['green'] if created else C['red']
                if not created:
                    def _revert():
                        s._doh_cb.blockSignals(True); s._doh_cb.setChecked(False); s._doh_cb.blockSignals(False)
                    ui_call(_revert)
                ui_call(lambda:s._toast(msg,color))
            else:
                fw.unblock_doh()
                cfg=load_cfg(); cfg['block_doh']=False; save_cfg(cfg)
                ui_call(lambda:s._toast("Encrypted DNS block removed",C['dim']))
        threading.Thread(target=_bg,daemon=True).start()
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
    def _clear_log(s):
        if QMessageBox.question(s,"Clear event log",
            "Delete all HostsGuard event log rows?\n\n"
            "This does not change hosts entries, firewall rules, or connection history.",
            QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:
            return
        s.db.clear_log(); s._log(); s._toast("Event log cleared",C['dim'])
    def _toggle_rec(s):
        if s._recording:
            s._recording=False; s._rec_btn.setText("Record Session")
            p=os.path.join(CONFIG_DIR,f"session_{datetime.datetime.now():%Y%m%d_%H%M%S}.jsonl")
            with open(p,'w',encoding='utf-8') as f:
                for ev in s._rec_data: f.write(json.dumps(ev,ensure_ascii=False)+'\n')
            s._toast(f"Saved {len(s._rec_data)} events: {Path(p).name}",C['green']); s._rec_data=[]
        else:
            s._recording=True; s._rec_data=[]; s._rec_btn.setText("Stop Recording")
            s._toast("Recording started",C['blue'])
    def record_event(s,ev_type,data):
        if s._recording:
            s._rec_data.append({'ts':datetime.datetime.now().isoformat(),'type':ev_type,**data})
    def _check_browser_doh(s):
        findings=[]
        def _bg():
            import winreg
            checks=[
                (winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Policies\Google\Chrome","DnsOverHttpsMode","Chrome (Policy)"),
                (winreg.HKEY_CURRENT_USER,r"SOFTWARE\Policies\Google\Chrome","DnsOverHttpsMode","Chrome (User Policy)"),
                (winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Policies\Microsoft\Edge","DnsOverHttpsMode","Edge (Policy)"),
                (winreg.HKEY_CURRENT_USER,r"SOFTWARE\Policies\Microsoft\Edge","DnsOverHttpsMode","Edge (User Policy)"),
            ]
            for hive,path,val,label in checks:
                try:
                    k=winreg.OpenKey(hive,path)
                    v,_=winreg.QueryValueEx(k,val); winreg.CloseKey(k)
                    if v and v.lower()!='off': findings.append(f"{label}: {v}")
                except (FileNotFoundError,OSError): pass
            chrome_prefs=os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Preferences")
            if os.path.exists(chrome_prefs):
                try:
                    with open(chrome_prefs,'r',encoding='utf-8') as f: prefs=json.load(f)
                    doh=prefs.get('dns_over_https',{})
                    mode=doh.get('mode','')
                    if mode and mode!='off': findings.append(f"Chrome preferences: DoH mode={mode}")
                except Exception: pass
            if findings:
                def _prompt():
                    r=QMessageBox.warning(s,"Browser DoH Detected",
                        "These browsers have DNS-over-HTTPS enabled, which bypasses "
                        "HostsGuard's DNS monitoring and hosts file blocking:\n\n"+'\n'.join(findings)+
                        "\n\nBlock encrypted DNS now (firewall-block DoH resolver IPs + port 853, "
                        "exempting your own resolver)?\n\n"
                        "You can also disable it per-browser by setting DnsOverHttpsMode to 'off' "
                        "(chrome://settings/security).",
                        QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
                    if r==QMessageBox.Yes: s._doh_cb.setChecked(True)  # triggers _toggle_doh
                ui_call(_prompt)
            else:
                ui_call(lambda:s._toast("No browser DoH detected",C['green']))
        threading.Thread(target=_bg,daemon=True).start()
    def _apply_dns(s):
        dns_map={"System Default":None,"Cloudflare (1.1.1.1)":("1.1.1.1","1.0.0.1"),
            "Google (8.8.8.8)":("8.8.8.8","8.8.4.4"),"Quad9 (9.9.9.9)":("9.9.9.9","149.112.112.112"),
            "AdGuard (94.140.14.14)":("94.140.14.14","94.140.15.15"),"NextDNS (45.90.28.0)":("45.90.28.0","45.90.30.0")}
        sel=s._dns_cb.currentText(); addrs=dns_map.get(sel)
        def _bg():
            if addrs is None:
                ok,_=_ps("Get-NetAdapter|Where-Object{$_.Status -eq 'Up'}|Set-DnsClientServerAddress -ResetServerAddresses",10)
            else:
                ok,_=_ps(f"Get-NetAdapter|Where-Object{{$_.Status -eq 'Up'}}|Set-DnsClientServerAddress -ServerAddresses {_ps_esc(addrs[0]+','+addrs[1])}",10)
            _ps("ipconfig /flushdns",5)
            ui_call(lambda:s._toast(f"DNS set to {sel}" if ok else "DNS change failed",C['green'] if ok else C['red']))
        threading.Thread(target=_bg,daemon=True).start()
    def _flush(s): ok,_=_ps("ipconfig /flushdns",5); s._toast("DNS flushed" if ok else "DNS flush failed",C['green'] if ok else C['red'])
    def _winsock(s):
        def _bg():
            ok,_=_ps("netsh winsock reset",10)
            ui_call(lambda:s._toast("Winsock reset (reboot needed)" if ok else "Winsock reset failed",C['green'] if ok else C['red']))
        threading.Thread(target=_bg,daemon=True).start()
    def _renew(s):
        s._toast("Renewing...",C['blue'])
        def _bg():
            # '&&' is a parse error in Windows PowerShell 5.1 — the command silently did nothing
            ok,_=_ps("ipconfig /release; ipconfig /renew",30)
            ui_call(lambda:s._toast("IP renewed" if ok else "Renew failed",C['green'] if ok else C['red']))
        threading.Thread(target=_bg,daemon=True).start()
    def _export(s):
        data={'version':VER,'schema':SCHEMA_VER,'domains':[{'domain':r[0],'status':r[1],'source':r[3]} for r in s.db.get_domains()],
            'fw_rules':[r.name for r in fw.get_cached() if r.source=='hostsguard'],
            'fw_state':[{'name':r[0],'direction':r[1],'action':r[2],'remote_addr':r[3],'protocol':r[4],'program':r[5]} for r in s.db.get_fw_state()],
            'trusted':list(s.learn._trusted),'untrusted':list(s.learn._untrusted)}
        p=os.path.join(CONFIG_DIR,f"hg_export_{datetime.datetime.now():%Y%m%d_%H%M}.json")
        tmp=p+'.tmp'
        try:
            with open(tmp,'w') as f: json.dump(data,f,indent=2)
            os.replace(tmp,p); s._toast(f"Exported: {Path(p).name}",C['green'])
        except Exception as e: s._toast(f"Export failed: {e}",C['red'])
    def _import(s):
        p,_=QFileDialog.getOpenFileName(s,"Import","","JSON (*.json)")
        if not p: return
        try:
            with open(p,encoding='utf-8') as f: data=json.load(f)
            if not isinstance(data,dict): raise ValueError("not a HostsGuard config file")
            # Skip malformed entries instead of aborting the whole import on one.
            rows=[(str(d['domain']).lower(),d.get('status','blocked'),d.get('source','import'))
                  for d in data.get('domains',[]) if isinstance(d,dict) and d.get('domain')]
            ct=s.db.add_domains_bulk(rows)
            for r in data.get('fw_state',[]):
                if isinstance(r,dict) and r.get('name'):
                    s.db.save_fw_rule(r.get('name',''),r.get('direction',''),r.get('action','Block'),r.get('remote_addr',''),r.get('protocol',''),r.get('program',''))
            for proc in data.get('trusted',[]):
                if isinstance(proc,str): s.learn.trust(proc)
            for proc in data.get('untrusted',[]):
                if isinstance(proc,str): s.learn.untrust(proc)
            fwct=len(data.get('fw_state',[]))
            s._toast(f"Imported {ct} domains, {fwct} FW rules — use Restore buttons to apply",C['green']); s._upd_learn()
        except Exception as e: s._toast(f"Import failed: {e}",C['red'])
    def _export_conns(s):
        p,_=QFileDialog.getSaveFileName(s,"Export Connections",os.path.join(CONFIG_DIR,f"connections_{datetime.datetime.now():%Y%m%d_%H%M}"),"CSV (*.csv);;JSONL (*.jsonl)")
        if not p: return
        rows=s.cdb.search('',limit=100000)
        cols=['ts','proto','local_addr','local_port','remote_addr','remote_port','host','process','pid','state','org','country','cc','category']
        try:
            if p.endswith('.jsonl'):
                with open(p,'w',encoding='utf-8') as f:
                    for r in rows: f.write(json.dumps(dict(zip(cols,r)),ensure_ascii=False)+'\n')
            else:
                with open(p,'w',newline='',encoding='utf-8') as f:
                    w=csv.writer(f); w.writerow(cols)
                    for r in rows: w.writerow(r)
            s._toast(f"Exported {len(rows)} connections",C['green'])
        except Exception as e: s._toast(f"Export failed: {e}",C['red'])
    def _prune(s): s.cdb.prune(30); s._toast("Pruned",C['green'])
    def _clear_fav(s):
        ct=0
        for f in Path(FAV_DIR).glob("*.png"):
            try: f.unlink(); ct+=1
            except OSError: pass  # locked/in-use file shouldn't abort the whole clear
        if _fav:
            with _fav._lock: _fav._mem.clear()
        s._toast(f"Cleared {ct} cached favicons",C['green'])
    def _open(s):
        if sys.platform=='win32': os.startfile(CONFIG_DIR)
    def _show_t(s): QMessageBox.information(s,"Trusted",'\n'.join(sorted(s.learn._trusted) or ["(none)"]))
    def _show_u(s): QMessageBox.information(s,"Untrusted",'\n'.join(sorted(s.learn._untrusted) or ["(none)"]))
    def _clear_t(s):
        if QMessageBox.question(s,"Clear learning decisions",
            "Clear all trusted and untrusted process decisions?\n\n"
            "Learning Mode will prompt again as those processes connect.",
            QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:
            return
        s.learn._trusted.clear(); s.learn._untrusted.clear(); s.learn.save(); s._upd_learn(); s._toast("Learning decisions cleared",C['dim'])
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
    def _harden_acl(s):
        def _bg():
            ok1,_=_ps(f'icacls {_ps_esc(HOSTS_PATH)} /inheritance:r /grant:r "NT AUTHORITY\\SYSTEM:(F)" "BUILTIN\\Administrators:(F)" /deny "BUILTIN\\Users:(W,D)"',10)
            ok2,_=_ps(f'auditpol /set /subcategory:"File System" /success:enable /failure:enable',10)
            ui_call(lambda:s._toast("Hosts ACL hardened + audit enabled" if ok1 else "ACL hardening failed",C['green'] if ok1 else C['red']))
        threading.Thread(target=_bg,daemon=True).start()
    def _restore_upstream(s):
        def _bg():
            try:
                url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
                req=urllib.request.Request(url,headers={'User-Agent':f'HostsGuard/{VER}'})
                with urllib.request.urlopen(req,timeout=30) as resp:
                    content=resp.read().decode('utf-8',errors='replace')
                s.hm.backup()
                err=s.hm.save_raw(content)
                if err: ui_call(lambda:s._toast(f"Restore failed: {err}",C['red']))
                else:
                    s.db.sync_hosts_to_db(s.hm)
                    w=s.window()
                    if hasattr(w,'_watcher'): w._watcher.update_hash()
                    ui_call(lambda:s._toast("Restored from StevenBlack upstream",C['green']))
            except Exception as e: ui_call(lambda:s._toast(f"Download failed: {e}",C['red']))
        if QMessageBox.question(s,"Restore from Upstream",
            "Replace your hosts file with the StevenBlack unified hosts list?\n"
            "A backup of the current file will be created first.",
            QMessageBox.Yes|QMessageBox.No)!=QMessageBox.Yes: return
        s._toast("Downloading StevenBlack hosts...",C['blue'])
        threading.Thread(target=_bg,daemon=True).start()
    def _save_profile(s):
        w=s.window(); name=w._prof_cb.currentText() if hasattr(w,'_prof_cb') else 'Default'
        if name=="+ New Profile...": name='Default'
        s.db.save_profile_snapshot(name)
        s._toast(f"Saved current rules to profile '{name}'",C['green'])
    def _rebaseline(s):
        s.hm.backup(); s.hm.read(); s.db.sync_hosts_to_db(s.hm)
        w=s.window()
        if hasattr(w,'_watcher'): w._watcher.update_hash()
        s._toast("Baseline updated — current hosts file accepted as known-good",C['green']); s._upd_rec()
    def _toggle_auto_restore(s,v):
        cfg=load_cfg(); cfg['auto_restore_on_tamper']=v; save_cfg(cfg)
        s._toast(f"Auto-restore {'ON' if v else 'OFF'}",C['green'] if v else C['dim'])
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
        s._launch_time=time.time(); s._notif_cd={}; s._live_keys=set()
        s._monitoring=False; s._conn_on=False; s._mini=None; s._last_conn_count=0
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
        s._sig_w=SigWorker(); s._sig_w.start()
        s._conn_w=None; s._dns_mon=None
        s._build_ui()
        s._refresh_profiles()
        s._prof_cb.currentTextChanged.connect(s._switch_profile)
        s._build_tray()
        # Launch FW rule loading in background (dedicated subprocess, not PPS)
        s._fw_tab._overlay.show_loading("Loading firewall rules")
        s._fw_loader=FWLoadWorker(); s._fw_loader.ready.connect(s._fw_tab.set_rules); s._fw_loader.start()
        # Hosts watcher
        s._watcher=HostsWatcher(); s._watcher.changed.connect(s._on_hosts_changed)
        s._watcher.registry_tamper.connect(s._on_registry_tamper); s._watcher.start()
        # Start monitors — no delay needed, data already loaded
        QTimer.singleShot(100,s._start_dns)
        QTimer.singleShot(200,s._start_conns)
        # Lazy-load favicons after UI is visible
        QTimer.singleShot(500,_init_fav)
        # Re-arm temp-allow expirations that were pending when the app last closed
        QTimer.singleShot(1000,s._hosts_act.resume_temp_allows)
        # Scheduled blocking — apply now and re-check every minute
        s._sched_tmr=QTimer(s); s._sched_tmr.timeout.connect(s._apply_schedules); s._sched_tmr.start(60000)
        QTimer.singleShot(1500,s._apply_schedules)
        # Refresh allowlist subscriptions on launch (fetch + whitelist)
        if load_cfg().get('allowlist_subscriptions'):
            QTimer.singleShot(3000,s._hosts_tab._apply_allowlists)
        # Scheduled blocklist refresh
        cfg=load_cfg(); interval_h=cfg.get('blocklist_refresh_hours',0)
        if interval_h>0:
            s._bl_tmr=QTimer(s); s._bl_tmr.timeout.connect(s._auto_refresh_lists)
            s._bl_tmr.start(interval_h*3600*1000)
        # Threat intel feeds go stale on long-running sessions — refresh every 6h
        s._ti_tmr=QTimer(s)
        s._ti_tmr.timeout.connect(lambda:threading.Thread(target=_load_threat_intel,daemon=True).start())
        s._ti_tmr.start(6*3600*1000)

    def _apply_schedules(s):
        """Block/unblock scheduled targets based on the current weekday+time.
        Only unblocks domains it applied itself (source='schedule'), so it never
        clobbers a manual/blocklist block on the same domain."""
        scheds=load_cfg().get('schedules',[])
        if not scheds: return
        now=datetime.datetime.now(); wd=now.weekday(); tnow=now.strftime("%H:%M")
        blocked=s.hm.get_blocked(); changed=False
        for sc in scheds:
            target=sc.get('target','');
            if not target: continue
            active=wd in sc.get('days',[]) and _in_window(tnow,sc.get('start','00:00'),sc.get('end','00:00'))
            doms=BLOCK_SERVICES.get(target,[target])
            for d in doms:
                d=d.lower()
                if active and d not in blocked:
                    if s.hm.block(d,flush=False): s.db.add_domain(d,'blocked','schedule'); changed=True
                elif not active and d in blocked:
                    r=s.db._q("SELECT source FROM domains WHERE domain=?",(d,))
                    if r and r[0][0]=='schedule':
                        s.hm.unblock(d,flush=False); s.db.remove_domain(d); changed=True
        if changed:
            s.hm._flush()
            s._hosts_act._last_hash=0

    def _auto_refresh_lists(s):
        cfg=load_cfg(); lists=cfg.get('blocklist_subscriptions',[])
        if not lists: return
        sources=[]
        for cat,items in SOURCES.items():
            for name,url in items:
                if name in lists: sources.append((name,url))
        if sources: s._hosts_tab._run_imp(sources)

    def _startup_sync(s):
        """Run at startup: backup hosts, sync hosts entries to DB, prune old data, load threat intel."""
        try: s.hm.backup()
        except: pass
        try: s.db.sync_hosts_to_db(s.hm)
        except: pass
        try: s.cdb.prune(30); s.db.prune_log()
        except: pass
        try: _load_threat_intel()
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
        s._dot=QLabel(); s._dot.setFixedSize(_dp(10),_dp(10)); s._dot.setStyleSheet(f"background:{C['dim']};border-radius:{_dp(4)}px;"); tb.addWidget(s._dot)
        s._status=QLabel("STARTING"); s._status.setStyleSheet(f"color:{C['dim']};font-size:{_dp(9)}px;font-weight:700;letter-spacing:0.5px;"); tb.addWidget(s._status)
        s._status.setAccessibleName("Monitoring status")
        s._status.setToolTip("Current DNS and connection monitoring state")
        try: adm=ctypes.windll.shell32.IsUserAnAdmin()!=0
        except: adm=False
        ac=C['green'] if adm else C['peach']
        ab=QLabel("ADMIN" if adm else "USER"); ab.setToolTip("Running elevated — hosts file and firewall changes are available" if adm else "Not elevated — hosts/firewall changes will fail. Relaunch as Administrator.")
        ab.setStyleSheet(f"color:{ac};font-size:{_dp(8)}px;font-weight:800;background:rgba({_rgb(ac)},0.12);border:1px solid rgba({_rgb(ac)},0.28);border-radius:{_dp(4)}px;padding:1px 6px;"); tb.addWidget(ab)
        tb.addStretch()
        s._bw_up=QLabel("\u25B2 --"); s._bw_up.setStyleSheet(f"color:{C['blue']};font-size:{_dp(9)}px;font-weight:600;font-family:'Cascadia Code','Consolas',monospace;"); tb.addWidget(s._bw_up)
        s._bw_dn=QLabel("\u25BC --"); s._bw_dn.setStyleSheet(f"color:{C['teal']};font-size:{_dp(9)}px;font-weight:600;font-family:'Cascadia Code','Consolas',monospace;"); tb.addWidget(s._bw_dn)
        sep2=QFrame(); sep2.setFixedSize(1,_dp(20)); sep2.setStyleSheet(f"background:{C['s0']};"); tb.addWidget(sep2)
        s._cbtn=QPushButton("CONNECTIONS: OFF"); s._cbtn.setCursor(Qt.PointingHandCursor); s._cbtn.setFixedHeight(_dp(24))
        s._cbtn.setStyleSheet(f"background:{C['s0']};color:{C['dim']};padding:2px 12px;border-radius:{_dp(6)}px;font-weight:800;font-size:{_dp(8)}px;border:1px solid {C['s1']};letter-spacing:0.5px;")
        s._cbtn.setAccessibleName("Toggle live connection monitoring")
        s._cbtn.setToolTip("Start or stop live connection monitoring")
        s._cbtn.clicked.connect(s._toggle_conns); tb.addWidget(s._cbtn)
        # Notification mute toggle
        s._notif_muted=load_cfg().get('notif_muted',False)
        s._mbtn=QPushButton("NOTIF: OFF" if s._notif_muted else "NOTIF: ON")
        s._mbtn.setCursor(Qt.PointingHandCursor); s._mbtn.setFixedHeight(_dp(24))
        s._mbtn.setAccessibleName("Toggle blocked-domain notifications")
        s._mbtn.setToolTip("Toggle desktop notifications for blocked domains")
        s._upd_mute_btn(); s._mbtn.clicked.connect(s._toggle_mute); tb.addWidget(s._mbtn)
        s._prof_cb=QComboBox(); s._prof_cb.setFixedHeight(_dp(24)); s._prof_cb.setFixedWidth(_dp(100))
        s._prof_cb.setAccessibleName("Network profile")
        s._prof_cb.setToolTip("Network profile — different rule sets per network")
        s._prof_cb.setStyleSheet(f"background:{C['s0']};color:{C['sub']};border:1px solid {C['s1']};border-radius:{_dp(6)}px;font-size:{_dp(8)}px;padding:0 {_dp(4)}px;")
        tb.addWidget(s._prof_cb)
        s._tbtn=QPushButton("LIGHT" if load_cfg().get('theme')=='light' else "DARK")
        s._tbtn.setCursor(Qt.PointingHandCursor); s._tbtn.setFixedHeight(_dp(24))
        s._tbtn.setAccessibleName("Toggle theme")
        s._tbtn.setToolTip("Switch between dark and light theme (requires restart)")
        s._tbtn.setStyleSheet(f"background:{C['s0']};color:{C['dim']};padding:2px 10px;border-radius:{_dp(6)}px;font-weight:800;font-size:{_dp(8)}px;border:1px solid {C['s1']};letter-spacing:0.5px;")
        s._tbtn.clicked.connect(s._toggle_theme); tb.addWidget(s._tbtn)
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
        s._dns_mon.dns_event.connect(lambda ev:s._tools.record_event('dns',ev))
        s._dns_mon.updated.connect(s._hosts_act._refresh)
        s._hosts_act.set_monitor(s._dns_mon)
        s._dns_mon.start(); s._monitoring=True; s._set_st("DNS Active")

    def _on_blocked(s,ev):
        if not s._tray or s._notif_muted: return
        if time.time()-s._launch_time<15: return
        d=ev.get('domain',''); now=time.time()
        if d in s._notif_cd and now-s._notif_cd[d]<60: return
        s._notif_cd[d]=now
        if len(s._notif_cd)>5000:
            cutoff=now-60
            s._notif_cd={k:v for k,v in s._notif_cd.items() if v>cutoff}
        s._tray.showMessage(APP,f"Blocked: {d}",QSystemTrayIcon.Warning,2000)

    def _toggle_mute(s):
        s._notif_muted=not s._notif_muted; s._upd_mute_btn()
        cfg=load_cfg(); cfg['notif_muted']=s._notif_muted; save_cfg(cfg)
        s._toasts.toast("Notifications OFF" if s._notif_muted else "Notifications ON",C['dim'] if s._notif_muted else C['green'])
    def _upd_mute_btn(s):
        on=not s._notif_muted
        s._mbtn.setText("NOTIF: ON" if on else "NOTIF: OFF")
        if on: s._mbtn.setStyleSheet(f"background:{C['s0']};color:{C['green']};padding:2px 10px;border-radius:{_dp(6)}px;font-weight:800;font-size:{_dp(8)}px;border:1px solid {C['s1']};letter-spacing:0.5px;")
        else: s._mbtn.setStyleSheet(f"background:{C['s0']};color:{C['dim']};padding:2px 10px;border-radius:{_dp(6)}px;font-weight:800;font-size:{_dp(8)}px;border:1px solid {C['s1']};letter-spacing:0.5px;")
    def _toggle_theme(s):
        cfg=load_cfg(); cur=cfg.get('theme','dark')
        new='light' if cur!='light' else 'dark'; cfg['theme']=new; save_cfg(cfg)
        s._tbtn.setText(new.upper())
        # The stylesheet is baked at import time, so offer an immediate restart
        # rather than leaving the user with a half-applied theme.
        if QMessageBox.question(s,"Restart to apply theme",
                f"Theme set to {new}. Restart HostsGuard now to apply it?",
                QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)==QMessageBox.Yes:
            s._restart()
        else:
            s._toasts.toast(f"Theme set to {new} — applies on next start",C['blue'])
    def _restart(s):
        """Relaunch the app and quit this instance."""
        try:
            args=([] if getattr(sys,'frozen',False) else [os.path.abspath(__file__)])+[a for a in sys.argv[1:]]
            if sys.platform=='win32':
                import ctypes
                params=' '.join(f'"{a}"' for a in args)
                ctypes.windll.shell32.ShellExecuteW(None,"runas" if not ctypes.windll.shell32.IsUserAnAdmin() else "open",sys.executable,params,None,1)
            else:
                os.execv(sys.executable,[sys.executable]+args)
        except Exception as e: log.warning(f"Restart failed: {e}"); s._toasts.toast("Restart failed — please reopen manually",C['red']); return
        s._quit()
    def _refresh_profiles(s):
        s._prof_cb.blockSignals(True)
        cur=s._prof_cb.currentText() or load_cfg().get('active_profile','Default')
        s._prof_cb.clear()
        for p in s.db.get_profiles(): s._prof_cb.addItem(p)
        s._prof_cb.addItem("+ New Profile...")
        idx=s._prof_cb.findText(cur)
        if idx>=0: s._prof_cb.setCurrentIndex(idx)
        s._prof_cb.blockSignals(False)
    def _switch_profile(s,name):
        if name=="+ New Profile...":
            n,ok=QInputDialog.getText(s,"New Profile","Profile name:")
            if ok and n.strip():
                n=n.strip(); s.db.create_profile(n); s.db.save_profile_snapshot(n)
                s._refresh_profiles(); s._prof_cb.setCurrentText(n)
                s._toasts.toast(f"Profile '{n}' created from current rules",C['green'])
            else: s._refresh_profiles()
            return
        if not name: return
        # Persist the outgoing profile's current rules before switching away, so
        # edits made since the last save aren't silently discarded by load_profile's
        # DELETE FROM domains. Profiles behave like auto-saved workspaces.
        prev=load_cfg().get('active_profile','Default')
        if prev and prev!=name and prev in s.db.get_profiles():
            s.db.save_profile_snapshot(prev)
        s.db.load_profile(name)
        s.hm.read()
        # Rewrite the hosts file to match the new profile exactly — domains the
        # previous profile blocked but this one doesn't must be unblocked, not
        # left stranded in the hosts file. Runs even for an empty profile.
        blocked=[r[0] for r in s.db.get_domains(status='blocked')]
        s.hm.reconcile(blocked)
        cfg=load_cfg(); cfg['active_profile']=name; save_cfg(cfg)
        s._toasts.toast(f"Switched to '{name}' ({len(blocked)} blocked)",C['blue'])

    def _start_conns(s):
        s._conn_w=ConnWorker(s.db)
        s._conn_w.ready.connect(s._on_conns)
        s._conn_w.need_dns.connect(s._dns_w.add); s._conn_w.need_geo.connect(s._geo_w.add); s._conn_w.need_sig.connect(s._sig_w.add)
        s._conn_w.start(); s._conn_on=True; s._set_st("All Active")
        s._cbtn.setText("CONNECTIONS: ON")
        s._cbtn.setStyleSheet(f"background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {C['blue']},stop:1 {C['teal']});color:#071019;padding:2px 12px;border-radius:{_dp(6)}px;font-weight:800;font-size:{_dp(8)}px;border:1px solid rgba({_rgb(C['blue'])},0.55);letter-spacing:0.5px;")

    def _stop_conns(s):
        if s._conn_w: s._conn_w.stop()
        s._conn_on=False; s._set_st("DNS Only")
        s._cbtn.setText("CONNECTIONS: OFF")
        s._cbtn.setStyleSheet(f"background:{C['s0']};color:{C['dim']};padding:2px 12px;border-radius:{_dp(6)}px;font-weight:800;font-size:{_dp(8)}px;border:1px solid {C['s1']};letter-spacing:0.5px;")

    def _toggle_conns(s):
        if s._conn_on: s._stop_conns()
        else: s._start_conns()

    def _on_conns(s,conns):
        s._fw_act.update_conns(conns); s._last_conn_count=len(conns)
        live=[c for c in conns if c.ra and c.ra!="*" and c.dir!="Listen"]
        if live:
            # Record each connection once when it is first observed — inserting
            # every 2s scan bloated connections.db with duplicate rows.
            cur_keys={c.key for c in live}
            new=[c for c in live if c.key not in s._live_keys]
            s._live_keys=cur_keys
            if new: s.cdb.insert_batch(new)
            if s._tools._recording:
                for c in new[:20]:
                    s._tools.record_event('conn',{'proto':c.proto,'remote':c.ra,'port':c.rp,'host':c.host,'proc':c.proc})

    def _on_hosts_changed(s,new_hash=b''):
        if s.hm.is_self_change(new_hash): return
        s.hm.read()
        threading.Thread(target=lambda:s.db.sync_hosts_to_db(s.hm),daemon=True).start()
        s._toasts.toast("Hosts file changed externally",C['peach'])
        threading.Thread(target=lambda:_evt_log("Hosts file modified externally"),daemon=True).start()
        _post_webhook('tamper',{'msg':'hosts file modified externally'})
        cfg=load_cfg()
        if cfg.get('auto_restore_on_tamper',False):
            if s.hm.restore(): s._toasts.toast("Auto-restored hosts from backup",C['green']); s._watcher.update_hash()
    def _on_registry_tamper(s,val):
        QMessageBox.critical(s,"Registry Tamper Detected",
            f"The hosts file DataBasePath registry key has been redirected!\n\n"
            f"Expected: %SystemRoot%\\System32\\drivers\\etc\n"
            f"Found: {val}\n\n"
            "This may indicate malware has redirected DNS resolution to a different hosts file. "
            "Check HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\DataBasePath.")
        threading.Thread(target=lambda:_evt_log(f"CRITICAL: DataBasePath registry tamper detected: {val}",'Error'),daemon=True).start()
    def _set_st(s,msg):
        on=s._monitoring or s._conn_on; c=C['green'] if on else C['red']
        s._dot.setStyleSheet(f"background:{c};border-radius:{_dp(4)}px;")
        s._status.setText(msg.upper()[:25]); s._status.setStyleSheet(f"color:{c};font-size:{_dp(9)}px;font-weight:700;letter-spacing:0.5px;")
        s._status.setToolTip(f"Monitoring status: {msg}")
    def _upd_bw(s):
        up,dn=bw.rates(); s._bw_up.setText(f"\u25B2 {bw.fmt(up)}"); s._bw_dn.setText(f"\u25BC {bw.fmt(dn)}")
        if s._mini and s._mini.isVisible():
            try: today=s.db.get_stats()['today_hits']
            except Exception: today=0
            s._mini.update_stats(up,dn,s._last_conn_count,today)
    def _toggle_mini(s):
        if s._mini is None: s._mini=MiniMonitor()
        if s._mini.isVisible(): s._mini.hide()
        else: s._mini.place_top_right(); s._mini.show(); s._upd_bw()

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
        m.addAction("Mini Monitor").triggered.connect(s._toggle_mini)
        m.addAction("Quit").triggered.connect(s._quit)
        s._tray.setContextMenu(m)
        s._tray.activated.connect(lambda r:s.show() if r==QSystemTrayIcon.DoubleClick else None)
        s._tray.show()

    def closeEvent(s,e):
        if s._tray: e.ignore(); s.hide()
        else: s._quit()

    def _quit(s):
        try:
            if s._mini: s._mini.close()
            workers=[]
            if s._dns_mon: s._dns_mon.stop(); workers.append(s._dns_mon)
            if s._conn_w: s._conn_w.stop(); workers.append(s._conn_w)
            if s._watcher: s._watcher.stop(); workers.append(s._watcher)
            s._dns_w.stop(); workers.append(s._dns_w)
            s._geo_w.stop(); workers.append(s._geo_w)
            s._sig_w.stop(); workers.append(s._sig_w)
            for w in workers: w.wait(3000)
            _pps.close()
        except: pass
        QApplication.quit()

    def resizeEvent(s,e): super().resizeEvent(e); s._toasts._place()

# ═════════════════════════════════════════════════════════════════════════════
#  CLI — headless commands without GUI
# ═════════════════════════════════════════════════════════════════════════════
def _is_admin():
    if sys.platform!='win32': return True
    try:
        import ctypes; return ctypes.windll.shell32.IsUserAnAdmin()!=0
    except Exception: return False

def _cli(args):
    cmd=args[0] if args else ''
    if cmd in ('block','allow','unblock') and not _is_admin():
        print("This command modifies the hosts file and requires an elevated terminal.")
        print("Re-run from an Administrator prompt."); return 2
    db=DB(); hm=HostsMgr()
    if cmd=='block' and len(args)>1:
        d=args[1].lower().strip()
        if not looks_like_domain(d): print(f"Invalid domain: {d}"); return 1
        already=d in hm.get_blocked()
        ok=already or hm.block(d)
        db.add_domain(d,'blocked','cli')
        if not ok: print(f"Failed to write hosts file (see {os.path.join(CONFIG_DIR,'hostsguard.log')})"); return 1
        db.log_event(d,'blocked','','CLI block')
        print(f"Already blocked: {d}" if already else f"Blocked: {d}"); return 0
    elif cmd=='allow' and len(args)>1:
        d=args[1].lower().strip()
        if not looks_like_domain(d): print(f"Invalid domain: {d}"); return 1
        db.add_domain(d,'whitelisted','cli'); hm.unblock(d)
        db.log_event(d,'whitelisted','','CLI allow'); print(f"Allowed: {d}"); return 0
    elif cmd=='unblock' and len(args)>1:
        d=args[1].lower().strip(); db.remove_domain(d); hm.unblock(d)
        print(f"Unblocked: {d}"); return 0
    elif cmd=='status':
        st=db.get_stats(); blocked=hm.get_blocked()
        print(f"{APP} v{VER}")
        print(f"Hosts: {len(blocked)} blocked")
        print(f"DB: {st['blocked']} blocked, {st['whitelisted']} allowed")
        print(f"Feed: {st['feed_total']} domains seen")
        print(f"Today: {st['today_hits']} blocks")
        return 0
    elif cmd=='export':
        try:
            for r in db.get_domains(): print(f"{r[1]}\t{r[0]}\t{r[3] or ''}")
        except (BrokenPipeError,OSError): pass  # piped into head/findstr that exited early
        return 0
    else:
        print(f"{APP} v{VER} — CLI")
        print("Commands: block <domain>, allow <domain>, unblock <domain>, status, export")
        print("GUI: run without arguments"); return 0

# ═════════════════════════════════════════════════════════════════════════════
#  HEADLESS SERVICE MODE — monitoring without GUI
# ═════════════════════════════════════════════════════════════════════════════
def _service():
    """Run HostsGuard as a headless background service with HTTP JSON-RPC."""
    import http.server,json as _json,hmac as _hmac
    print(f"{APP} v{VER} — Headless Service Mode")
    db=DB(); hm=HostsMgr(); cdb=ConnDB()
    hm.backup(); db.sync_hosts_to_db(hm)
    cdb.prune(30); db.prune_log()
    threading.Thread(target=_load_threat_intel,daemon=True).start()
    dns_cache_cmd='Get-DnsClientCache -EA SilentlyContinue|Select Entry,RecordName|ConvertTo-Json -Compress'
    stop_evt=TEvent()
    def _dns_loop():
        seen=set()
        while not stop_evt.is_set():
            try:
                ok,out=_pps.run(dns_cache_cmd,12)
                if ok and out.strip():
                    data=_json.loads(out)
                    if isinstance(data,dict): data=[data]
                    blocked=db.get_blocked_set()
                    domains=[]
                    for e in data:
                        d=(e.get('Entry') or e.get('RecordName') or '').lower().strip().rstrip('.')
                        if not d or d in IGNORED or '.' not in d: continue
                        domains.append(d)
                    db.feed_upsert_batch(domains)
                    for d in domains:
                        if d not in seen:
                            seen.add(d)
                            if d in blocked:
                                db.log_event(d,'blocked','','Blocked by hosts')
                                threading.Thread(target=_evt_log,args=(f"Blocked: {d}",),daemon=True).start()
                                _post_webhook('blocked',{'domain':d})
                    if len(seen)>20000: seen.clear()
            except Exception: pass
            stop_evt.wait(3)
    def _conn_loop():
        prev_keys=set()
        while not stop_evt.is_set():
            try:
                conns=psutil.net_connections(kind='all'); bw.update()
                live=[]
                for c in conns:
                    try:
                        ra=c.raddr.ip if c.raddr else ""
                        if not ra or ra in ('','*','0.0.0.0','::','::1') or PRIV_RE.match(ra): continue
                        pid=c.pid or 0; pname="?"
                        if pid:
                            try: pname=psutil.Process(pid).name()
                            except: pass
                        host=dns_c.get(ra) or "-"; rp=str(c.raddr.port) if c.raddr else ""
                        la=c.laddr.ip if c.laddr else ""; lp=str(c.laddr.port) if c.laddr else ""
                        proto="TCP" if c.type==socket.SOCK_STREAM else "UDP"
                        ci=CI(key=f"{proto}:{la}:{lp}-{ra}:{rp}",ts=datetime.datetime.now().isoformat(timespec='seconds'),
                            proto=proto,la=la,lp=lp,ra=ra,rp=rp,host=host,proc=pname,pid=pid)
                        live.append(ci)
                    except: continue
                cur_keys={c.key for c in live}
                new=[c for c in live if c.key not in prev_keys]
                prev_keys=cur_keys
                if new: cdb.insert_batch(new)
            except Exception: pass
            stop_evt.wait(2)
    def _watcher_loop():
        def _fhash():
            h=hashlib.sha512()
            try:
                with open(HOSTS_PATH,'rb') as f:
                    for chunk in iter(lambda:f.read(65536),b''): h.update(chunk)
            except OSError: return b''
            return h.digest()
        last=_fhash()
        while not stop_evt.is_set():
            try:
                d=_fhash()
                if d and d!=last:
                    last=d
                    if not hm.is_self_change(d):
                        hm.read(); db.sync_hosts_to_db(hm)
                        _evt_log("Hosts file modified externally")
                        _post_webhook('tamper',{'msg':'hosts file modified externally'})
                        cfg=load_cfg()
                        if cfg.get('auto_restore_on_tamper',False):
                            hm.restore(); last=_fhash()  # accept restored content, no re-trigger
            except Exception: pass
            stop_evt.wait(5)
    threads=[]
    for fn in [_dns_loop,_conn_loop,_watcher_loop]:
        t=threading.Thread(target=fn,daemon=True); t.start(); threads.append(t)
    # Auth is REQUIRED, not optional — the service runs elevated and mutates the
    # hosts file, so an unauthenticated endpoint would let any local process do so.
    # Prefer HG_TOKEN from the environment; otherwise auto-generate and persist a
    # token so the endpoint is never open by default.
    token=os.environ.get('HG_TOKEN','').strip()
    tok_path=os.path.join(CONFIG_DIR,'service_token')
    if not token:
        try:
            if os.path.exists(tok_path):
                with open(tok_path) as f: token=f.read().strip()
            if not token:
                token=uuid.uuid4().hex+uuid.uuid4().hex
                fd=os.open(tok_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
                with os.fdopen(fd,'w') as f: f.write(token)
        except Exception as e:
            log.warning(f"service token: {e}")
    class Handler(http.server.BaseHTTPRequestHandler):
        def _authed(s):
            """Require a constant-time-matched X-HG-Token on every request."""
            if token and _hmac.compare_digest(s.headers.get('X-HG-Token',''),token): return True
            s._json_reply(401,{'ok':False,'error':'missing or invalid X-HG-Token'})
            return False
        def _json_reply(s,code,obj):
            body=_json.dumps(obj).encode()
            s.send_response(code); s.send_header('Content-Type','application/json')
            s.send_header('Content-Length',str(len(body))); s.end_headers()
            s.wfile.write(body)
        def do_GET(s):
            if not s._authed(): return
            if s.path=='/status':
                st=db.get_stats(); blocked=hm.get_blocked(); up,dn=bw.rates()
                s._json_reply(200,{'app':APP,'version':VER,'blocked':len(blocked),'db_blocked':st['blocked'],
                    'db_allowed':st['whitelisted'],'feed_total':st['feed_total'],'today_hits':st['today_hits'],
                    'bw_up':up,'bw_dn':dn})
            elif s.path=='/domains':
                s._json_reply(200,[{'domain':r[0],'status':r[1],'source':r[3]} for r in db.get_domains()])
            elif s.path=='/stats':
                st=db.get_stats()
                s._json_reply(200,{'blocked':st['blocked'],'whitelisted':st['whitelisted'],
                    'feed_total':st['feed_total'],'today_hits':st['today_hits'],
                    'top_blocked':[{'domain':d,'count':c} for d,c in st['top_blocked']],
                    'connections_total':cdb.count() if hasattr(cdb,'count') else None})
            elif s.path=='/log':
                rows=db.get_log(limit=200)
                s._json_reply(200,[{'ts':r[1],'domain':r[2],'action':r[3],'process':r[4],'details':r[5]} for r in rows])
            else:
                s._json_reply(404,{'ok':False,'error':'unknown endpoint'})
        def do_POST(s):
            if not s._authed(): return
            if s.path!='/domains':
                s._json_reply(404,{'ok':False,'error':'unknown endpoint'}); return
            try:
                length=min(int(s.headers.get('Content-Length',0) or 0),1_000_000)
                body=_json.loads(s.rfile.read(length)) if length else {}
                if not isinstance(body,dict): raise ValueError("body must be a JSON object")
                action=str(body.get('action','')); domain=str(body.get('domain','')).lower().strip()
            except Exception as e:
                s._json_reply(400,{'ok':False,'error':f'bad request: {e}'}); return
            if not looks_like_domain(domain):
                s._json_reply(400,{'ok':False,'error':'invalid domain'}); return
            if action=='block':
                db.add_domain(domain,'blocked','rpc'); hm.block(domain); db.log_event(domain,'blocked','','RPC block')
                s._json_reply(200,{'ok':True})
            elif action=='allow':
                db.add_domain(domain,'whitelisted','rpc'); hm.unblock(domain)
                db.log_event(domain,'whitelisted','','RPC allow')
                s._json_reply(200,{'ok':True})
            else:
                s._json_reply(400,{'ok':False,'error':'action must be block or allow'})
        def log_message(s,*a): pass
    port=int(os.environ.get('HG_PORT','7847'))
    srv=http.server.ThreadingHTTPServer(('127.0.0.1',port),Handler)
    print(f"JSON-RPC listening on http://127.0.0.1:{port}")
    print("Endpoints: GET /status /domains /stats /log, POST /domains (action+domain)")
    if not token:
        print("WARNING: no auth token could be established — endpoint will reject all requests.")
    elif os.environ.get('HG_TOKEN','').strip():
        print("Auth: send header 'X-HG-Token: <your HG_TOKEN>' on every request.")
    else:
        print(f"Auth: send header 'X-HG-Token: <token>' — token stored at {tok_path}")
    print("Press Ctrl+C to stop")
    try: srv.serve_forever()
    except KeyboardInterrupt: print("\nShutting down...")
    finally:
        stop_evt.set()
        for t in threads: t.join(3)
        _pps.close(); db.close(); cdb.close()

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
        _init_ui_bridge()
        branding_icon = QIcon(str(_branding_icon_path()))
        app.setWindowIcon(branding_icon)
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
            from PySide6.QtWidgets import QMessageBox as MB,QApplication as Q2
            if not Q2.instance(): Q2(sys.argv)
            MB.critical(None,f"{APP} Crash",f"{e}\n\nSee: {crash}")
        except: pass
        print(f"CRASH: {e}\n{tb}",file=sys.stderr); sys.exit(1)

if __name__=="__main__":
    multiprocessing.freeze_support()
    if '--service' in sys.argv:
        _service()
    else:
        cli_args=[a for a in sys.argv[1:] if not a.startswith('--')]
        if cli_args and cli_args[0] in CLI_CMDS:
            sys.exit(_cli(cli_args))
        main()
