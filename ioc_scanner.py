#!/usr/bin/env python3
"""Comprehensive IOC scanner for Android SMS-banking trojan disassembly.
   Pass 2: hidden base64 IOC decoder + register-tracked pref key extraction.
"""

import os
import re
import sys
import json
import base64
import zipfile
from collections import defaultdict

SMALI_DIRS = [
    r"D:\DroidForensix\_apk2\payload_smali",
    r"D:\DroidForensix\_apk2\smali",
    r"D:\DroidForensix\_hole5\split1_smali",
]
DEX_DIRS = [
    r"D:\DroidForensix\_apk2",
    r"D:\DroidForensix\_hole5\split1",
]
PHASE4_DIR = r"D:\DroidForensix\uploads\44b10841-c0ac-4d21-8979-7227d154896f\rto_extracted\phase4_payload"
EXTRA_BINARIES = [
    r"D:\DroidForensix\_apk2\wQtPQS.dec",
    r"D:\DroidForensix\_hole5\dec_payload+1.bin",
    r"D:\DroidForensix\_hole5\assets\dataQpoJzkbmfX",
]
MANIFESTS = [
    r"D:\DroidForensix\_apk2\AndroidManifest_decompiled.xml",
    r"D:\DroidForensix\_apk2\AndroidManifest.xml",
]
OUTPUT_FILE = r"D:\DroidForensix\_ioc_catalog.txt"

KNOWN_DECRYPTED_C2 = [
    ("sdks.hzbeyond.com", "assets/f5.txt (decrypted)"),
    ("sdkj.hzbeyond.com", "assets/f5.txt (decrypted)"),
    ("sdkjk.idmzone.com", "assets/f5.txt (decrypted)"),
    ("sdkjx.idmzone.com", "assets/f5.txt (decrypted)"),
]

KNOWN_TLDS = set("""
com net org io cn top xyz info biz me cc vc co online site club vip shop tech live space
cloud fun app store tv mobi asia la capital link win work us de ru jp kr hk tw vn th id
my sg in name pro wiki news city world video cool blog red cat agency today social
company group center network zone wang tv sh wuxue app inc int moe sbs gq km tech
""".split())

urls = defaultdict(set)
phone_numbers = defaultdict(set)
package_names = defaultdict(set)
broadcast_actions = defaultdict(set)
pref_files = defaultdict(set)
pref_keys = defaultdict(set)
emails = set()
crypto_addresses = set()
ip_addresses = defaultdict(set)
file_downloads = defaultdict(set)
hidden_iocs = defaultdict(set)
manifest_components = defaultdict(set)
sms_commands = defaultdict(set)
banking_terms = defaultdict(set)

ALL_SMALI_STRINGS = []   # (line, value, rel)
ALL_BYTE_STRINGS = []    # (value, rel)
ALL_CLEAN_STRINGS = []   # (value, rel) from smali (deduped)

# ──────────────────────────────────────────────────────────────────────────
# Extraction helpers
# ──────────────────────────────────────────────────────────────────────────

def rel_path(filepath):
    base = r"D:\DroidForensix"
    if filepath.startswith(base):
        return os.path.relpath(filepath, base)
    return filepath

def scan_smali_file(filepath):
    rel = rel_path(filepath)
    out = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"  [ERR] {filepath}: {e}", file=sys.stderr)
        return out, []
    smali_str_re = re.compile(r'^\s*const-string(?:\s*/jumbo)?\s+([vp]\d+),\s*"((?:[^"\\]|\\.)*)"')
    pref_key_re = re.compile(r'(putString|putInt|putBoolean|putLong|putFloat|getString|getInt|getBoolean|getLong|getFloat)')
    pref_file_re = re.compile(r'^\s*invoke-virtual .*Context;->getSharedPreferences\(Ljava/lang/String;I\)')
    method_re = re.compile(r'^\s*\.method ')
    endmethod_re = re.compile(r'^\s*\.end method')
    in_method = False
    regs = {}
    pref_items = []   # (kind, key, line)
    for i, line in enumerate(lines, start=1):
        m = smali_str_re.match(line)
        if m:
            val = m.group(2).replace('\\"', '"').replace('\\\\', '\\')
            out.append((i, val, rel))
            if in_method:
                regs[m.group(1)] = val
        elif method_re.match(line):
            in_method = True
            regs = {}
        elif endmethod_re.match(line):
            in_method = False
            regs = {}
        elif in_method and (pref_key_re.search(line) or pref_file_re.search(line)):
            # capture register that holds the key string
            cm = re.search(r'invoke-(?:interface|virtual)\s*\{([^}]*)\}.*Editor;->(putString|putInt|putBoolean|putLong|putFloat|getString|getInt|getBoolean|getLong|getFloat)\(Ljava/lang/String;', line)
            if cm:
                args = [a.strip() for a in cm.group(1).split(',')]
                if len(args) >= 2:
                    reg = args[1]  # key argument register
                    prog = regs.get(reg)
                    if prog:
                        pref_items.append((cm.group(2), prog, i, rel))
            fm = pref_file_re.match(line)
            if fm:
                args = [a.strip() for a in re.search(r'\{([^}]*)\}', line).group(1).split(',')]
                if len(args) >= 2:
                    reg = args[1]
                    prog = regs.get(reg)
                    if prog:
                        pref_files[prog].add((i, rel))
    return out, pref_items

def extract_bin_strings(filepath, minlen=4):
    rel = rel_path(filepath)
    out = []
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"  [ERR] {filepath}: {e}", file=sys.stderr)
        return out
    pattern = re.compile(rb'([\x20-\x7e]{%d,})' % minlen)
    for m in pattern.finditer(data):
        out.append((m.group(1).decode('ascii', errors='replace'), rel))
    return out

def extract_apk_strings(filepath):
    rel = rel_path(filepath)
    out = []
    if not zipfile.is_zipfile(filepath):
        return extract_bin_strings(filepath, minlen=4)
    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            for name in zf.namelist():
                if name.endswith('.dex'):
                    data = zf.read(name)
                    pattern = re.compile(rb'([\x20-\x7e]{4,})')
                    for m in pattern.finditer(data):
                        out.append((m.group(1).decode('ascii', errors='replace'), f"{rel}!{name}"))
    except Exception as e:
        print(f"  [ERR] APK {filepath}: {e}", file=sys.stderr)
    return out

# ──────────────────────────────────────────────────────────────────────────
# Classification
# ──────────────────────────────────────────────────────────────────────────

def classify_url(url_str):
    lower = url_str.lower()
    if any(kw in lower for kw in ['/sms', 'intercept', 'sendmsg', 'steal', 'forward']):
        return "SMS Interception"
    if any(kw in lower for kw in ['host', 'hzbeyond', 'idmzone', 'ilast']):
        return "C2"
    if any(kw in lower for kw in ['download', '.apk', 'install', 'payload', 'update', 'fetch', 'getfile']):
        return "Download/Install"
    if any(kw in lower for kw in ['config', 'setting', '.json', 'conf']):
        return "Config JSON"
    if any(kw in lower for kw in ['webview', 'loadurl', 'load_url', '.html', '.htm']):
        return "WebView / Phishing Page"
    if any(kw in lower for kw in ['pay', 'charge', 'subscribe', 'premium', 'ali', 'recharge', 'order', 'sdk', 'app.jtmtht']):
        return "Payment / Carrier Billing SDK"
    if any(kw in lower for kw in ['report', 'stat', 'track', 'log', 'register', 'collect', 'upload']):
        return "Telemetry/Report"
    if any(kw in lower for kw in ['bank', 'login', 'credential', 'phish']):
        return "Banking Phish"
    if '.php' in lower or '.asp' in lower or '.jsp' in lower:
        return "Server Script"
    if 'api' in lower or 'rest' in lower:
        return "API"
    return "Uncategorized"

def categorize_phone(num):
    if re.match(r'^10[0-9]{3}$', num):
        return "Short Code (10xxx)"
    if re.match(r'^12[0-9]{3,4}$', num):
        return "Short Code (12xxx)"
    if re.match(r'^95[0-9]{3}$', num):
        return "Short Code (95xxx)"
    if re.match(r'^1[3-9]\d{9}$', num):
        return "CN Mobile"
    if num.startswith('106'):
        return "Premium SMS Gateway (106)"
    if re.match(r'^\d{5,8}$', num):
        return "Short Code (generic)"
    return "Other Number"

SKIP_PKG_PREFIXES = (
    'java.', 'javax.', 'android.os.', 'android.app.', 'android.content.',
    'android.view.', 'android.widget.', 'android.graphics.', 'android.util.',
    'android.net.', 'android.database.', 'android.provider.', 'android.hardware.',
    'android.text.', 'org.apache.', 'org.json.', 'org.xml.', 'dalvik.',
    'kotlin.', 'com.google.', 'com.android.internal.', 'android.animation.',
    'android.media.', 'android.webkit.', 'android.preference.', 'android.renderscript.',
    'android.support.', 'org.w3c.', 'org.xmlpull.', 'com.android.org.', 'okhttp3.',
    'okio.', 'retrofit2.', 'com.tencent.', 'androidx.',
)

def looks_like_pkg(s):
    """True if the dotted string is more likely a java class path than a host."""
    if any(p in s for p in SKIP_PKG_PREFIXES):
        return True
    if s.startswith('com.') or s.startswith('org.') or s.startswith('net.'):
        return True
    if '.R$' in s or '$' in s:
        return True
    return False

def classify_clean_smali_strings():
    # URL regex with known TLD check
    URL_SCHEME = re.compile(r'(?:https?|ftp|ws|wss)://([^\s"\'<>\\}\],;]+)')
    BARE_DOMAIN = re.compile(r'((?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}(?:/[^\s"\'<>\\}\],;]*)?)')
    CN_MOBILE = re.compile(r'(?<!\d)(1[3-9]\d{9})(?!\d)')
    SHORTCODE = re.compile(r'(?<!\d)(106\d{5,12}|10\d{3,5}|12\d{3,5}|95\d{3}|10\d{2}0\d{4})(?!\d)')
    PREFIX86 = re.compile(r'(\+86?1[3-9]\d{9})')
    pkg_re = re.compile(r'\b([a-z][a-z0-9_]*(?:\.[a-zA-Z0-9_]+){2,})\b')
    email_re = re.compile(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b')
    btc_re = re.compile(r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
    eth_re = re.compile(r'\b(0x[0-9a-fA-F]{40})\b')
    ip_re = re.compile(r'(?<!\d\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)')
    file_ext_re = re.compile(r'(?<![\w/.])([^"<>\\\s]*\.(?:apk|dex|jar|so|zip|bin|obb))')
    android_action_re = re.compile(r'^android\.(?:intent\.action|provider\.Telephony|telephony|app)\.') 

    for line, s, rel in ALL_SMALI_STRINGS:
        s = s.strip()
        if not s:
            continue

        # Broadcast actions: known android actions and custom SENT/DELIVERED patterns
        if android_action_re.match(s) and s not in ('android.intent.action.MAIN',):
            broadcast_actions[s].add((line, rel))
        if re.match(r'^[A-Z][A-Z0-9_]*(_ACTION_[A-Z_]+|_SENT|_DELIVERED)$', s):
            broadcast_actions[f"[CUSTOM] {s}"].add((line, rel))
        if s in ('USER_PRESENT', 'BOOT_COMPLETED', 'SMS_RECEIVED', 'PHONE_STATE',
                 'NEW_OUTGOING_SMS', 'SCREEN_ON', 'SCREEN_OFF', 'PACKAGE_ADDED',
                 'LOCKED_BOOT_COMPLETED'):
            broadcast_actions[f"[CUSTOM] {s}"].add((line, rel))

        # Pref key patterns from standalone strings
        if re.match(r'^[a-z_][a-z0-9_]{1,40}$', s) and any(k in s for k in
                ('key', 'url', 'ip', 'port', 'last', 'first', 'sms', 'phone', 'num',
                 'version', 'time', 'code', 'device', 'install', 'token', 'config',
                 'password', 'pwd', 'user', 'pass', 'uuid', 'data', 'report', 'upload',
                 'command', 'cmd', 'interval', 'count', 'status', 'state', 'on', 'off')):
            pass  # too noisy; keys captured precisely via register tracking below

        # URLs
        for mm in URL_SCHEME.finditer(s):
            u = mm.group(0)
            if len(u) > 8:
                cats = [c for c in (classify_url(u.split('?')[0]), classify_url(u))]
                cat = cats[0]
                urls[cat].add((u, f"{rel}:{line}"))
        for mm in BARE_DOMAIN.finditer(s):
            cand = mm.group(1).rstrip('/')
            tld = cand.rsplit('.', 1)[-1].lower() if '.' in cand else ''
            if tld in KNOWN_TLDS and not looks_like_pkg(cand) and not cand.startswith('android.'):
                if not cand.startswith(('http', 'www.')):
                    urls["Bare Host (no scheme)"].add((cand, f"{rel}:{line}"))

        # Phone numbers
        for mm in CN_MOBILE.finditer(s):
            num = mm.group(1)
            phone_numbers[categorize_phone(num)].add((num, f"{rel}:{line}", s[:140]))
        for mm in SHORTCODE.finditer(s):
            num = mm.group(1)
            phone_numbers[categorize_phone(num)].add((num, f"{rel}:{line}", s[:140]))
        for mm in PREFIX86.finditer(s):
            phone_numbers["+86 prefix"].add((mm.group(1), f"{rel}:{line}", s[:140]))

        # Package names
        for mm in pkg_re.finditer(s):
            p = mm.group(1)
            if not looks_like_pkg(p):
                package_names[p].add(f"{rel}:{line}")

        # Emails
        for mm in email_re.finditer(s):
            e = mm.group(1)
            if not e.endswith(('.png', '.jpg', '.gif', '.xml', '.java', '.class', '.smali')):
                emails.add((e, f"{rel}:{line}"))

        # Crypto
        for mm in btc_re.finditer(s):
            crypto_addresses.add(("BTC", mm.group(1), f"{rel}:{line}"))
        for mm in eth_re.finditer(s):
            crypto_addresses.add(("ETH", mm.group(1), f"{rel}:{line}"))

        # IPs
        for mm in ip_re.finditer(s):
            ip = mm.group(1)
            octs = ip.split('.')
            if all(0 <= int(o) <= 255 for o in octs):
                if ip not in ('0.0.0.0', '255.255.255.255', '127.0.0.1', '1.0.0.1'):
                    ip_addresses[ip].add(f"{rel}:{line}")

        # Downloadable files
        for mm in file_ext_re.finditer(s):
            file_downloads[mm.group(1)].add(f"{rel}:{line}")

    # SMS/banking keyword collection
    sms_kw = re.compile(r'(sms|短信|验证码|forward|intercept|steal|delete|kill|upload|inforeceived|收发)', re.I)
    bank_kw = re.compile(r'(bank|pay|金融|贷款|借款|支付|支付宝|微信|工行|建行|农行|招行|中行|交行|信用|card|visa|master|充值|扣费)', re.I)
    for line, s, rel in ALL_SMALI_STRINGS:
        if sms_kw.search(s) and 4 <= len(s) <= 80:
            sms_commands[s].add(f"{rel}:{line}")
        if bank_kw.search(s) and 4 <= len(s) <= 80:
            banking_terms[s].add(f"{rel}:{line}")

def classify_byte_strings():
    CN_MOBILE = re.compile(r'(?<!\d)(1[3-9]\d{9})(?!\d)')
    SHORTCODE = re.compile(r'(?<!\d)(106\d{5,12}|10\d{3,5}|12\d{3,5}|95\d{3})(?!\d)')
    URL_SCHEME = re.compile(r'(?:https?|ftp|ws|wss)://([^\s"\'<>\\}\],;]{4,})')
    email_re = re.compile(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b')
    btc_re = re.compile(r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
    eth_re = re.compile(r'\b(0x[0-9a-fA-F]{40})\b')
    ip_re = re.compile(r'(?<!\d\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)')
    file_ext_re = re.compile(r'(?<![\w/.])([^"<>\\\s]*\.(?:apk|dex|jar|so|zip|bin|obb))')
    BARE = re.compile(r'((?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}(?:/[^\s"\'<>\\}\],;]*)?)')
    already = set()

    for s, rel in ALL_BYTE_STRINGS:
        s = s.strip()
        if not s or len(s) < 4:
            continue
        # skip type descriptors
        if re.match(r'^[L\[]', s) or ';->' in s or ';' in s[-1:]:
            continue
        for mm in URL_SCHEME.finditer(s):
            u = mm.group(0)
            if len(u) > 8:
                cat = classify_url(u)
                urls[cat].add((u, f"bytes:{rel}"))
        for mm in CN_MOBILE.finditer(s):
            num = mm.group(1)
            phone_numbers[categorize_phone(num)].add((num, f"bytes:{rel}", s[:140]))
        for mm in SHORTCODE.finditer(s):
            num = mm.group(1)
            phone_numbers[categorize_phone(num)].add((num, f"bytes:{rel}", s[:140]))
        for mm in email_re.finditer(s):
            e = mm.group(1)
            if not e.endswith(('.png', '.jpg', '.gif', '.xml')):
                emails.add((e, f"bytes:{rel}"))
        for mm in btc_re.finditer(s):
            crypto_addresses.add(("BTC", mm.group(1), f"bytes:{rel}"))
        for mm in eth_re.finditer(s):
            crypto_addresses.add(("ETH", mm.group(1), f"bytes:{rel}"))
        for mm in ip_re.finditer(s):
            ip = mm.group(1)
            octs = ip.split('.')
            if all(0 <= int(o) <= 255 for o in octs):
                if ip not in ('0.0.0.0', '255.255.255.255', '127.0.0.1'):
                    ip_addresses[ip].add(f"bytes:{rel}")
        for mm in file_ext_re.finditer(s):
            file_downloads[mm.group(1)].add(f"bytes:{rel}")
        for mm in BARE.finditer(s):
            cand = mm.group(1).rstrip('/')
            tld = cand.rsplit('.', 1)[-1].lower() if '.' in cand else ''
            if tld in KNOWN_TLDS and len(cand) >= 8 and not looks_like_pkg(cand) and cand not in already:
                already.add(cand)
                urls["Bare Host (decoded/binary)"].add((cand, f"bytes:{rel}"))


# ──────────────────────────────────────────────────────────────────────────
# Hidden IOC decoder (recursive base64)
# ──────────────────────────────────────────────────────────────────────────

def is_printable(b):
    if not b:
        return False
    return sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13)) / len(b) > 0.6

def ascii_runs(data):
    """Extract readable ASCII runs from raw bytes regardless of overall printability."""
    runs = []
    for m in re.finditer(rb'[\x20-\x7e]{6,}', data):
        runs.append(m.group(0).decode('ascii', errors='replace'))
    return runs

def deep_b64_hunt(data, depth=0, path=""):
    """Recursively find printable reveals inside base64-wrapped blobs.

    Works on raw byte scan (not gated by is_printable) so URLs embedded in
    random-padded blobs are still recovered.
    """
    results = []
    if depth > 3 or not data or len(data) < 8:
        return results
    # surface-level ASCII runs first
    for run in ascii_runs(data):
        results.append((run, path))
    # inner base64 tokens
    for m in re.finditer(rb'[A-Za-z0-9+/]{16,}={0,2}', data):
        tok = m.group(0)
        # strip random chars, attempt decode
        padded = tok + b'=' * (-len(tok) % 4)
        try:
            dec = base64.b64decode(padded, validate=False)
        except Exception:
            continue
        if not dec:
            continue
        # keep readable runs even inside otherwise-binary output
        for run in ascii_runs(dec):
            results.append((run, path + "->b64"))
        results.extend(deep_b64_hunt(dec, depth + 1, path + "->b64"))
    # dedupe preserving order
    seen = set()
    out = []
    for run, p in results:
        key = (run, p)
        if key not in seen:
            seen.add(key)
            out.append((run, p))
    return out

def clean_url(u):
    """Trim trailing junk that obfuscation padding appends after a URL."""
    u = u.rstrip('.,;:)')
    u = re.sub(r'[!@#$%\^&\*\(\)\{\}\[\]\|]+[A-Za-z0-9]{0,8}$', '', u)
    return u

def find_hidden_iocs():
    B64_CAND = re.compile(r'[A-Za-z0-9+/]{24,}={0,2}')
    url_pat = re.compile(r'(?:https?|ftp)://[^\s]+')
    phone_pat = re.compile(r'(?<!\d)(1[3-9]\d{9}|106\d{5,12}|95\d{3})(?!\d)')
    mail_pat = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    ip_pat = re.compile(r'(?<!\d\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)')

    for line, s, rel in ALL_SMALI_STRINGS:
        for mm in B64_CAND.finditer(s):
            tok = mm.group(0)
            padded = tok + '=' * (-len(tok) % 4)
            try:
                dec = base64.b64decode(padded, validate=False)
            except Exception:
                continue
            hits = []
            hits = deep_b64_hunt(dec, 0, "b64")
            for inner, _path in hits:
                for u in url_pat.findall(inner):
                    u = clean_url(u)
                    hidden_iocs["Hidden URL"].add((u, f"{rel}:{line}", s[:100]))
                for p in phone_pat.findall(inner):
                    hidden_iocs["Hidden Phone"].add((p, f"{rel}:{line}", s[:100]))
                for e in mail_pat.findall(inner):
                    hidden_iocs["Hidden Email"].add((e, f"{rel}:{line}", s[:100]))
                for ip in ip_pat.findall(inner):
                    hidden_iocs["Hidden IP"].add((ip, f"{rel}:{line}", s[:100]))
            # also scan directly printable first layer
            if is_printable(dec):
                text = dec.decode('ascii', errors='replace')
                for u in url_pat.findall(text):
                    u = clean_url(u)
                    hidden_iocs["Hidden URL"].add((u, f"{rel}:{line}", s[:100]))
                for p in phone_pat.findall(text):
                    hidden_iocs["Hidden Phone"].add((p, f"{rel}:{line}", s[:100]))
                for e in mail_pat.findall(text):
                    hidden_iocs["Hidden Email"].add((e, f"{rel}:{line}", s[:100]))
                for ip in ip_pat.findall(text):
                    hidden_iocs["Hidden IP"].add((ip, f"{rel}:{line}", s[:100]))

# ──────────────────────────────────────────────────────────────────────────
# Manifest scanning
# ──────────────────────────────────────────────────────────────────────────

def scan_manifests():
    for mf in MANIFESTS:
        if not os.path.isfile(mf):
            continue
        rel = rel_path(mf)
        try:
            with open(mf, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception as e:
            print(f"  [ERR] {mf}: {e}", file=sys.stderr)
            continue
        # binary manifest: keep only readable runs
        if '\x00' in content[:200]:
            content = '\n'.join(re.findall(r'[\x20-\x7e]{6,}', content))
        for m in re.finditer(r'<action\s+android:name="([^"]+)"', content):
            manifest_components[m.group(1)].add(f"{rel} (registered action)")
        for m in re.finditer(r'<receiver\s+android:name="([^"]+)"', content):
            manifest_components[f"[RECEIVER] {m.group(1)}"].add(rel)
        for m in re.finditer(r'<service\s+android:name="([^"]+)"', content):
            manifest_components[f"[SERVICE] {m.group(1)}"].add(rel)
        for m in re.finditer(r'<provider\s+android:name="([^"]+)"', content):
            manifest_components[f"[PROVIDER] {m.group(1)}"].add(rel)
        for m in re.finditer(r'<activity\s+android:name="([^"]+)"', content):
            manifest_components[f"[ACTIVITY] {m.group(1)}"].add(rel)
        for m in re.finditer(r'<uses-permission\s+android:name="([^"]+)"', content):
            manifest_components[m.group(1)].add(f"{rel} (permission)")

# ──────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────

def main():
    global ALL_SMALI_STRINGS, ALL_BYTE_STRINGS

    print("=" * 70)
    print("IOC SCANNER v2: Android SMS-Banking Trojan (hidden-IOC decoder)")
    print("=" * 70)

    print("\n[1/6] Scanning smali files...")
    smali_count = 0
    for sd in SMALI_DIRS:
        if not os.path.isdir(sd):
            print(f"  skip: {sd}")
            continue
        for root, dirs, files in os.walk(sd):
            for fn in files:
                if fn.endswith('.smali'):
                    strings, pref_items = scan_smali_file(os.path.join(root, fn))
                    ALL_SMALI_STRINGS.extend(strings)
                    for kind, key, ln, rel in pref_items:
                        pref_keys[key].add((kind, ln, rel))
                    smali_count += 1
    print(f"  {smali_count} smali files, {len(ALL_SMALI_STRINGS)} string literals")

    print("\n[2/6] Scanning DEX binaries...")
    dex_count = 0
    for dd in DEX_DIRS + [PHASE4_DIR]:
        if not os.path.isdir(dd):
            continue
        for root, dirs, files in os.walk(dd):
            for fn in files:
                if fn.endswith('.dex'):
                    ALL_BYTE_STRINGS.extend(extract_bin_strings(os.path.join(root, fn)))
                    dex_count += 1
    print(f"  {dex_count} dex files")

    print("\n[3/6] Scanning APK inner dex...")
    apk_count = 0
    for root, dirs, files in os.walk(PHASE4_DIR):
        for fn in files:
            if fn.endswith('.apk'):
                ALL_BYTE_STRINGS.extend(extract_apk_strings(os.path.join(root, fn)))
                apk_count += 1
    print(f"  {apk_count} apk files")

    print("\n[4/6] Scanning extra binaries/assets...")
    for b in EXTRA_BINARIES:
        if os.path.isfile(b):
            ALL_BYTE_STRINGS.extend(extract_bin_strings(b))
            print(f"  scanned {rel_path(b)}")
    for b in [r"D:\DroidForensix\_hole5\dec_payload+1.bin",
              r"D:\DroidForensix\analysis\recovered\M_PARIWAHAN\kesaj3fo_decrypted.bin"]:
        if os.path.isfile(b):
            ALL_BYTE_STRINGS.extend(extract_bin_strings(b))
            print(f"  scanned {rel_path(b)}")

    print("\n[5/6] Parsing config files...")
    config_files = {}
    for cfg_name in ["miner_config.json", "payload_config.json"]:
        cfg_path = os.path.join(PHASE4_DIR, cfg_name)
        if os.path.isfile(cfg_path):
            with open(cfg_path, 'r') as f:
                content = f.read()
            config_files[cfg_name] = json.loads(content)
            for tok in re.findall(r'"[^"]+"|[0-9a-zA-Z.]{5,}', content):
                tok = tok.strip('"')
                if tok and len(tok) > 3:
                    ALL_BYTE_STRINGS.append((tok, cfg_name))

    print("\n[6/6] Classifying & decoding...")
    classify_clean_smali_strings()
    classify_byte_strings()
    find_hidden_iocs()
    scan_manifests()

    # known decrypted C2 with their paths
    for d, loc in KNOWN_DECRYPTED_C2:
        urls["Known Decrypted C2 (f5.txt dict)"].add((d, loc))

    # ── Report ──
    L = []
    L.append("=" * 84)
    L.append("COMPLETE IOC CATALOG - Android SMS-Banking Trojan Static Analysis")
    L.append(f"Scanned: {smali_count} smali | {dex_count} dex | {apk_count} apk | {len(ALL_BYTE_STRINGS)} binary strings")
    L.append(f"String literals: {len(ALL_SMALI_STRINGS)}")
    L.append("=" * 84)

    def section(title):
        L.append("")
        L.append("=" * 84)
        L.append(title)
        L.append("=" * 84)

    # 1. URLs
    section("1. URLS AND DOMAINS")
    for cat in sorted(urls.keys()):
        L.append("")
        L.append(f"  --- {cat} ({len(urls[cat])}) ---")
        for url, loc in sorted(urls[cat]):
            L.append(f"    {url}")
            L.append(f"      @ {loc}")

    # 2. Phone numbers
    section("2. PHONE NUMBERS / PREMIUM SHORT CODES")
    for cat in sorted(phone_numbers.keys()):
        L.append("")
        L.append(f"  --- {cat} ({len(phone_numbers[cat])}) ---")
        for num, loc, ctx in sorted(phone_numbers[cat]):
            L.append(f"    {num}")
            L.append(f"      @ {loc}")
            if ctx:
                L.append(f"      ctx: {ctx}")

    # 3. Package names
    section("3. PACKAGE NAMES (const-strings)")
    for p in sorted(package_names.keys()):
        locs = sorted(package_names[p])
        L.append(f"  {p}  ({len(locs)} refs)")
        for loc in locs[:4]:
            L.append(f"      @ {loc}")
        if len(locs) > 4:
            L.append(f"      ... +{len(locs)-4} more")

    # 4. Broadcast actions
    section("4. BROADCAST ACTION STRINGS")
    for a in sorted(broadcast_actions.keys()):
        locs = sorted(broadcast_actions[a])
        L.append(f"  {a}")
        for loc in locs[:3]:
            if isinstance(loc, tuple):
                L.append(f"      @ {loc[1]}:{loc[0]}")
            else:
                L.append(f"      @ {loc}")
    L.append("")
    L.append("  --- Registered components / permissions from AndroidManifest ---")
    for c in sorted(manifest_components.keys()):
        locs = sorted(manifest_components[c])
        L.append(f"  {c}")
        for loc in locs[:2]:
            L.append(f"      @ {loc}")

    # 5. SharedPreferences
    section("5. SHARED PREFERENCES / SETTINGS KEYS AND FILES")
    L.append("  --- Preference files (getSharedPreferences arg, register-tracked) ---")
    for f in sorted(pref_files.keys()):
        for ln, rel in sorted(pref_files[f])[:4]:
            L.append(f"    {f}  @ {rel}:{ln}")
    L.append("")
    L.append("  --- Preference keys (Editor.put*/get* args, register-tracked) ---")
    for k in sorted(pref_keys.keys()):
        for kind, ln, rel in sorted(pref_keys[k])[:4]:
            L.append(f"    {k}  ({kind}) @ {rel}:{ln}")

    # 6. Emails, crypto, IPs
    section("6. EMAIL ADDRESSES, CRYPTO WALLETS, HARDCODED IPs")
    L.append("--- EMAIL ADDRESSES ---")
    if emails:
        for e, loc in sorted(emails):
            L.append(f"  {e}  @ {loc}")
    else:
        L.append("  (none found)")
    L.append("")
    L.append("--- CRYPTO WALLETS ---")
    if crypto_addresses:
        for ctype, addr, loc in sorted(crypto_addresses):
            L.append(f"  [{ctype}] {addr}  @ {loc}")
    else:
        L.append("  (none found)")
    L.append("")
    L.append("--- HARDCODED IP ADDRESSES ---")
    if ip_addresses:
        for ip in sorted(ip_addresses.keys()):
            for loc in sorted(ip_addresses[ip])[:5]:
                L.append(f"  {ip}  @ {loc}")
    else:
        L.append("  (none found)")

    # 7. Downloadable files
    section("7. DOWNLOADED / INSTALLED / LOADED FILES (.apk/.dex/.jar/.so/.zip/.bin/.obb)")
    for f in sorted(file_downloads.keys()):
        locs = sorted(file_downloads[f])
        L.append(f"  {f}")
        for loc in locs[:3]:
            L.append(f"      @ {loc}")

    # 8. Config files
    section("8. CONFIGURATION FILE CONTENTS (phase4_payload)")
    for fname, content in config_files.items():
        L.append("")
        L.append(f"  {fname}:")
        for line in json.dumps(content, indent=2).split('\n'):
            L.append(f"    {line}")

    # 9. Hidden nested-base64 IOCs
    section("9. OBFUSCATED IOCS (nested base64 reveals)")
    for cat in sorted(hidden_iocs.keys()):
        L.append("")
        L.append(f"  --- {cat} ({len(hidden_iocs[cat])}) ---")
        for ioc, loc, outer in sorted(hidden_iocs[cat]):
            L.append(f"    {ioc}")
            L.append(f"      @ {loc}")
            L.append(f"      outer: {outer[:120]}")

    # 10. SMS commands
    section("10. SMS COMMAND / KEYWORD STRINGS")
    for kw in sorted(sms_commands.keys()):
        locs = sorted(sms_commands[kw])
        if len(locs) > 4:
            L.append(f"  \"{kw}\"  ({len(locs)} refs)")
        else:
            L.append(f"  \"{kw}\"")
            for loc in locs:
                L.append(f"      @ {loc}")

    # 11. Banking terms
    section("11. BANKING / FINANCE / CARRIER-BILLING STRINGS")
    for term in sorted(banking_terms.keys()):
        locs = sorted(banking_terms[term])
        if len(locs) > 4:
            L.append(f"  \"{term}\"  ({len(locs)} refs)")
        else:
            L.append(f"  \"{term}\"")
            for loc in locs:
                L.append(f"      @ {loc}")

    # 12. Summary
    section("12. SUMMARY STATISTICS")
    L.append(f"  smali files:          {smali_count}")
    L.append(f"  dex files:            {dex_count}")
    L.append(f"  apk files:            {apk_count}")
    L.append(f"  string literals:      {len(ALL_SMALI_STRINGS)}")
    L.append(f"  binary strings:       {len(ALL_BYTE_STRINGS)}")
    L.append(f"  URLs/domains:         {sum(len(v) for v in urls.values())}")
    L.append(f"  phone numbers:        {sum(len(v) for v in phone_numbers.values())}")
    L.append(f"  package names:        {len(package_names)}")
    L.append(f"  broadcast actions:    {len(broadcast_actions)}")
    L.append(f"  pref files:           {len(pref_files)}")
    L.append(f"  pref keys:            {len(pref_keys)}")
    L.append(f"  emails:               {len(emails)}")
    L.append(f"  crypto wallets:       {len(crypto_addresses)}")
    L.append(f"  hardcoded IPs:        {len(ip_addresses)}")
    L.append(f"  downloadable files:   {len(file_downloads)}")
    L.append(f"  obfuscated IOCs:      {sum(len(v) for v in hidden_iocs.values())}")
    L.append(f"  SMS keywords:         {len(sms_commands)}")

    L.append("")
    L.append("=" * 84)
    L.append("END OF IOC CATALOG")
    L.append("=" * 84)

    report = '\n'.join(L)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"\nReport written to {OUTPUT_FILE} ({len(report)} bytes, {len(L)} lines)")
    print(f"  URLs/domains:       {sum(len(v) for v in urls.values())}")
    print(f"  Phone numbers:      {sum(len(v) for v in phone_numbers.values())}")
    print(f"  Package names:      {len(package_names)}")
    print(f"  Broadcast actions:  {len(broadcast_actions)}")
    print(f"  Pref files/keys:    {len(pref_files)}/{len(pref_keys)}")
    print(f"  Emails:             {len(emails)}")
    print(f"  Crypto:             {len(crypto_addresses)}")
    print(f"  IPs:                {len(ip_addresses)}")
    print(f"  Downloads:          {len(file_downloads)}")
    print(f"  Obfuscated IOCs:    {sum(len(v) for v in hidden_iocs.values())}")

if __name__ == '__main__':
    main()