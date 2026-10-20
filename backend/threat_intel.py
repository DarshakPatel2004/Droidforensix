"""
Threat-intel aggregation and exports.

Builds the Phase-2 threat-intelligence view consumed by the frontend
``ThreatIntelView`` from a pipeline result, and produces CSV / STIX / YARA
exports. C2 indicators are read from ``c2_infrastructure`` in the result;
DNS-liveness ``status`` and ``classification`` fields are used when present
(added by the offline ``enrich_c2_activity.py`` / ``build_final_outputs.py``
batch scripts) and computed on the fly otherwise so the endpoint works for
any analyzed sample.

Geo-location is read from the shared cache ``analysis/work/c2_geo.json`` when
available; no network calls are made from the request path.
"""

import csv
import io
import ipaddress
import json
import logging
import os
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen

from backend.censys_enrichment import enrich_ip as _censys_enrich
from backend.config import settings
from backend.family_id import identify_family

logger = logging.getLogger(__name__)

try:
    import geoip2.database
    _GEO_READER = geoip2.database.Reader(str(settings.GEOIP_PATH)) if settings.GEOIP_PATH.exists() else None
except Exception:
    _GEO_READER = None

_ISP_CACHE_PATH = settings.WORK_DIR / 'isp_cache.json'
_LAST_ISP_QUERY = 0.0

def _load_isp_cache() -> Dict[str, Any]:
    if _ISP_CACHE_PATH.exists():
        try:
            with open(_ISP_CACHE_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            logger.debug("Failed to load ISP cache")
    return {}

def _save_isp_cache(cache: Dict[str, Any]) -> None:
    try:
        with open(_ISP_CACHE_PATH, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2)
    except Exception:
        logger.warning("Failed to save ISP cache")

def _enrich_isp(ip: str) -> Dict[str, str]:
    """Query ip-api.com for ISP/org/AS, with rate limiting and caching."""
    global _LAST_ISP_QUERY
    cache = _load_isp_cache()
    if ip in cache:
        return cache[ip]

    if _classify_ip(ip) != 'public':
        result = {'isp': '', 'org': '', 'as': ''}
        cache[ip] = result
        _save_isp_cache(cache)
        return result

    elapsed = time.time() - _LAST_ISP_QUERY
    if elapsed < 1.4:
        time.sleep(1.4 - elapsed)
    _LAST_ISP_QUERY = time.time()

    failed = False
    error_reason = ''
    try:
        req = Request(f'http://ip-api.com/json/{ip}?fields=status,isp,org,as,country,regionName,city',
                      headers={'User-Agent': 'DroidForensix/1.0'})
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        if data.get('status') == 'success':
            result = {
                'isp': data.get('isp', ''),
                'org': data.get('org', ''),
                'as': data.get('as', ''),
            }
        else:
            # status != 'success' is usually a rate-limit or bad request
            failed = True
            error_reason = str(data.get('message') or data.get('status') or 'lookup failed')
            result = {'isp': '', 'org': '', 'as': ''}
    except Exception as exc:
        failed = True
        error_reason = '%s: %s' % (type(exc).__name__, exc)
        result = {'isp': '', 'org': '', 'as': ''}

    if failed:
        # Do NOT persist a transient failure. Caching this would make the IP
        # permanently report "no ISP data" in every future report, which reads as
        # a finding rather than a failed lookup.
        logger.debug("ISP lookup failed for %s (%s); not caching", ip, error_reason)
        return {'isp': '', 'org': '', 'as': '', 'lookup_error': error_reason}

    cache[ip] = result
    _save_isp_cache(cache)
    return result


def _geo_lookup(ip: str) -> Optional[Dict[str, Any]]:
    """On-the-fly GeoIP lookup via MaxMind when the cache misses."""
    if not ip or _GEO_READER is None:
        return None
    try:
        response = _GEO_READER.city(ip)
        return {
            'country': response.country.name or 'Unknown',
            'region': response.subdivisions.most_specific.name if response.subdivisions else '',
            'city': response.city.name or '',
            'lat': response.location.latitude,
            'lon': response.location.longitude,
            'isp': response.traits.isp or '',
        }
    except Exception as exc:
        logger.warning("Suppressed error in _geo_lookup: %s", exc)
        return None


# --- Whitelist of known benign SDK / ad domains (mirrors build_final_outputs.py) ---
BENIGN_SDK_DOMAINS = {
    'admob.com', 'www.admob.com', 'a.admob.com', 'media.admob.com', 'e.admob.com',
    'googleads.g.doubleclick.net', 'doubleclick.net', 'googleadservices.com',
    'www.googleadservices.com', 'pagead2.googlesyndication.com',
    'googlesyndication.com', 'google-analytics.com', 'www.google-analytics.com',
    'ssl.google-analytics.com', 'analytics.google.com',
    'maps.googleapis.com', 'maps.google.com', 'ditu.google.cn',
    'www.googleapis.com', 'android.clients.google.com',
    'facebook.com', 'www.facebook.com', 'api.facebook.com', 'apps.facebook.com',
    'graph.facebook.com', 'connect.facebook.net',
    'amazon-adsystem.com', 's3.amazonaws.com', 'aws.amazon.com',
    'applovin.com', 'a.applovin.com', 'd.applovin.com',
    'flurry.com', 'data.flurry.com', 'cdn.flurry.com', 'adlog.flurry.com', 'ads.flurry.com',
    'vungle.com', 'api.vungle.com',
    'tapjoy.com', 'connect.tapjoy.com',
    'appodeal.com', 'ach.appodeal.com', 'adwatch.appodeal.com',
    'startappexchange.com', 'www.startappexchange.com',
    'pubnative.net', 'api.pubnative.net',
    'inmobi.com', 'www.inmobi.com',
    'revmob.com', 'android.revmob.com',
    'mopub.com', 'analytics.mopub.com',
    'adcolony.com', 'androidads23.adcolony.com',
    'unity3d.com', 'cdn.unityads.unity3d.com',
    'avocarrot.com', 'ads.avocarrot.com',
    'rubiconproject.com', 'ads.rubiconproject.com',
    'leadbolt.net', 'ad.leadbolt.net',
    'mydas.mobi', 'ads.mp.mydas.mobi', 'cvt.mydas.mobi', 'androidsdk.ads.mp.mydas.mobi',
    'scoreloop.com', 'api.scoreloop.com', 'community.scoreloop.com',
    'openfeint.com', 'api.openfeint.com', 'ads.openfeint.com',
    'apptornado.com', 'applift-a.apptornado.com',
    'whalecloud.com', 'feedback.whalecloud.com',
    'apple.com', 'www.apple.com', 'itunes.apple.com', 'phobos.apple.com',
    'adobe.com', 'www.adobe.com', 'www.macromedia.com',
    'crl3.adobe.com', 'airdownload.adobe.com', 'airinstall.adobe.com',
    'microsoft.com', 'www.microsoft.com', 'live.com', 'msn.com',
    'cloudfront.net', 'akamai.net', 'akamaihd.net',
    'github.com', 'raw.githubusercontent.com',
    'curl.haxx.se', 'daneden.me', 'tumblr.com', 'api.tumblr.com',
    'yahoo.com', 'www.yahoo.com',
    # Indian payment gateways
    'paytm.in', 'securegw.paytm.in', 'easypay.paytm.in',
    'payu.in', 'payumoney.com', 'ccavenue.com',
    'mobikwik.com', 'zaakpay.com',
    'npci.org.in',
    # Indian bank 3D Secure / ACS
    'onlinesbi.com', 'hdfcbank.com', 'icicibank.com',
    'citibank.co.in', 'enstage.com', 'idbibank.com',
    'amxvpos.com', 'deutschebank.co.in',
    # Xiaomi / Mi ecosystem
    'xiaomi.com', 'xiaomi.net', 'mi.com',
    'xmpush.global.xiaomi.com', 'appmifile.com',
    # Payment 3DS authentication providers
    'arcot.com',
    # Xiaomi POCO sub-brand
    'po.co',
    # Other legitimate services
    'cashify.in', 'uber.com', 'schema.org',
    'twitter.com', 'worldpay.com', 'apaylater.com',
    'indusguard.com', 'monstat.com',
    'paysecure.ru',
    'paypal.com', 'www.paypal.com', 'api.paypal.com',
    # Iranian / Middle East ad networks
    'adivery.com', 'api.adivery.com',
    'tapsell.ir', 'api.tapsell.ir',
    'pushe.co',
    # No-code / cross-platform SDKs
    'appybuilder.com', 'editor.appybuilder.com',
    'appcelerator.com', 'api.appcelerator.com',
    # Iranian app store
    'cafebazaar.ir',
    # CDN / icon services
    'fontawesome.com',
    # Material Design
    'material.io', 'mapstyle.withgoogle.com',
    # Android library author websites
    'mikepenz.com',
    # Bilibili (Chinese video platform, commonly embedded in apps)
    'bilibili.com', 'app.bilibili.com', 'live.bilibili.com', 'api.bilibili.com',
    'www.bilibili.com', 'm.bilibili.com', 'passport.bilibili.com',
    # Other Chinese services
    'lovequiz.us',
    # Additional ad/analytics networks
    'www.mopub.com',
    # .NET framework namespaces (common in Xamarin/Mono Android apps)
    'system.net', 'system.io', 'system.web', 'system.data', 'system.core',
    # Google OAuth / Firebase / Firebase Auth
    'googleusercontent.com', 'apps.googleusercontent.com',
    'firebaseio.com', 'firebaseapp.com', 'firebase.analytics.app',
    # Xiaomi payment / HPPlay
    'mipay.com', 'hpplay.cn', 'hpplay.com.cn', 'hpplay.cdn.cibn.cc',
    'cdnauth1.hpplay.cn', 'cdnauth2.hpplay.cn', 'dep.hpplay.cn',
    'devicemgr.hpplay.cn', 'misdkauth.hpplay.cn', 'logu.hpplay.cn', 'loguhk.hpplay.cn',
    'image.hpplay.cn', 'api.box.appmob.cn', 'frame.top',
    # URL shorteners / legitimate short domains
    'youtu.be', 'goo.gl', 'bit.ly', 'tinyurl.com', 'ow.ly',
    # Amazon Associates
    'assoc-amazon.com', 'amazon.com', 'amazonaws.com',
    # Alipay
    'alipay.com', 'alipay.net', 'alipaydev.com', 'mobilegw.alipay.com',
    'wappaygw.alipay.com',
    # OpenSDK / China SDKs
    'opensdk.com', 'mobile.opensdk.com',
    # Niotron
    'niotron.com', 'rendezvous.niotron.com',
    # YouTube img
    'ytimg.com', 'i.ytimg.com', 'i1.ytimg.com', 'i2.ytimg.com', 'i3.ytimg.com', 'i4.ytimg.com',
    # ID6 URL shortener
    'id6.me',
    # Applovin China SDK
    'applvn.com', 'a.applvn.com', 'd.applvn.com', 'ms.applvn.com', 'rt.applvn.com',
    # Bilibili SDK
    'bili-location.sdk.manager.downgrade', 'bili-location.sdk.manager.request',
}

# Legitimate TLDs that are commonly used - NOT suspicious
LEGITIMATE_TLDS = {'.com', '.net', '.org', '.io', '.co', '.uk', '.de', '.jp',
                   '.fr', '.au', '.ca', '.cn', '.in', '.ru', '.br', '.kr', '.it', '.es',
                   '.gov', '.edu', '.mil', '.int', '.app', '.dev', '.xyz', '.top', '.club',
                   '.work', '.bid', '.date', '.win', '.men', '.loan', '.online', '.site',
                   '.store', '.tech', '.info', '.biz', '.name', '.mobi', '.pro', '.cc',
                   '.me', '.tv', '.ws', '.us', '.eu', '.asia', '.tel', '.co.uk', '.co.jp'}

# Suspicious TLDs - only truly abused ones, not broadly used legitimate TLDs
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq'}
SUSPICIOUS_PORTS = {8080, 8443, 444, 6666, 6667, 6668, 6669, 7000, 7070, 8888,
                    9999, 31337, 1337, 4444, 5555, 9000, 10000}

SUSPICIOUS_PATH_KEYWORDS = ['/admin', '/panel', '/gate', '/command', '/shell',
                            '/exec', '/c2', '/bot', '/callback']

# Single English words and common code identifiers that appear as "domains"
# in DEX strings but are never real C2 infrastructure.
_JUNK_DOMAIN_WORDS = frozenset({
    'descriptionrelatively', 'applicationslink', 'navigation', 'interested',
    'familiar', 'whether', 'interpreted', 'according', 'addeventlistenerresponsible',
    'applications', 'description', 'relatively', 'responsible', 'event',
    'listener', 'addEventListener', 'function', 'return', 'callback',
    'handler', 'trigger', 'execute', 'process', 'request', 'response',
    'success', 'failure', 'error', 'warning', 'debug', 'info', 'log',
    'message', 'notification', 'alert', 'confirm', 'prompt', 'input',
    'output', 'result', 'data', 'value', 'text', 'string', 'number',
    'boolean', 'object', 'array', 'list', 'map', 'set', 'item',
    'index', 'count', 'total', 'sum', 'min', 'max', 'average',
    'start', 'stop', 'begin', 'end', 'first', 'last', 'next', 'prev',
    'current', 'previous', 'new', 'old', 'temp', 'tmp', 'test',
    'default', 'custom', 'standard', 'normal', 'basic', 'advanced',
    'simple', 'complex', 'main', 'primary', 'secondary', 'alternate',
    'original', 'copy', 'clone', 'base', 'core', 'common', 'shared',
    'local', 'remote', 'internal', 'external', 'public', 'private',
    'global', 'static', 'dynamic', 'final', 'const', 'variable',
    'parameter', 'argument', 'option', 'setting', 'configuration',
    'property', 'attribute', 'field', 'member', 'element', 'component',
    'module', 'package', 'library', 'framework', 'platform', 'system',
    'service', 'manager', 'controller', 'provider', 'factory',
    'builder', 'creator', 'generator', 'parser', 'formatter', 'converter',
    'validator', 'checker', 'matcher', 'comparator', 'iterator', 'enumerator',
    'collection', 'container', 'wrapper', 'proxy', 'adapter', 'bridge',
    'facade', 'decorator', 'observer', 'subscriber', 'publisher',
    'action', 'operation', 'task', 'job', 'work', 'thread', 'routine', 'procedure', 'method', 'logic',
    'algorithm', 'pattern', 'structure', 'model', 'view', 'template',
    'instance', 'reference', 'pointer', 'handle', 'identifier', 'key',
    'name', 'title', 'label', 'tag', 'category', 'type', 'kind', 'sort',
    'group', 'class', 'family', 'series', 'version', 'edition', 'release',
    'build', 'revision', 'update', 'upgrade', 'patch', 'fix', 'change',
    'add', 'remove', 'delete', 'insert', 'replace', 'swap',
    'move', 'merge', 'split', 'join', 'connect',
    'disconnect', 'open', 'close', 'read', 'write', 'load', 'save',
    'fetch', 'send', 'receive', 'get', 'put', 'post', 'create',
    'destroy', 'init', 'setup', 'configure', 'initialize', 'reset',
    'clear', 'clean', 'refresh', 'reload', 'restart', 'resume', 'pause',
    'cancel', 'abort', 'skip', 'ignore', 'reject', 'accept', 'approve',
    'verify', 'validate', 'check', 'trace',
    'record', 'track', 'monitor', 'watch', 'observe', 'detect',
    'find', 'search', 'lookup', 'query', 'select', 'filter', 'order', 'arrange', 'organize', 'combine', 'divide', 'separate', 'extract', 'parse', 'format', 'convert',
    'transform', 'translate', 'encode', 'decode', 'compress', 'decompress',
    'encrypt', 'decrypt', 'hash', 'sign', 'authenticate',
    'authorize', 'login', 'logout', 'register', 'subscribe', 'unsubscribe',
    'follow', 'unfollow', 'like', 'unlike', 'share', 'comment', 'rate',
    'review', 'feedback', 'support', 'help', 'about', 'contact',
    'privacy', 'terms', 'conditions', 'policy', 'legal', 'copyright',
    'license', 'permission', 'access', 'right', 'role', 'status', 'state',
    'mode', 'style', 'theme', 'layout', 'design', 'content', 'context', 'environment', 'preference', 'feature', 'functionality', 'capability', 'capacity', 'limit', 'bound',
    'range', 'scope', 'domain', 'zone', 'region', 'area', 'location',
    'position', 'place', 'point', 'spot', 'site', 'address', 'url',
    'link', 'source', 'origin', 'destination', 'target',
    'goal', 'objective', 'purpose', 'intent', 'reason', 'cause', 'effect',
    'outcome', 'consequence', 'impact', 'influence', 'factor',
    'aspect', 'part', 'piece', 'segment', 'section', 'portion',
    'fraction', 'percentage', 'ratio', 'speed', 'velocity',
    'frequency', 'period', 'duration', 'interval', 'delay', 'timeout',
    'threshold', 'boundary', 'margin', 'padding', 'spacing', 'gap',
    'width', 'height', 'depth', 'length', 'size', 'scale', 'dimension',
    'weight', 'mass', 'volume', 'density', 'intensity', 'strength',
    'force', 'power', 'energy', 'effort', 'attempt', 'try',
    'notice',
})


def _is_junk_domain(domain: str) -> bool:
    """Return True if domain looks like a sentence fragment or code identifier.

    Conservative by design: when in doubt return False and let classify_c2's
    reasons-based logic (suspicious TLD/port/path, NXDOMAIN, ...) decide.
    Over-broad heuristics here mislabel *real* C2 infrastructure as benign
    junk — which drops those indicators from YARA/CSV exports and hides them
    in the UI.
    """
    if not domain:
        return True
    domain = domain.rstrip('.')
    parts = domain.split('.')

    # Contains semicolons, spaces, or other non-domain characters
    if any(c in domain for c in ' ;(){}[]'):
        return True

    # Single-part: bare words / numbers never resolve as hostnames
    if len(parts) == 1:
        word = parts[0].lower()
        if word in _JUNK_DOMAIN_WORDS:
            return True
        if word.isalpha() and len(word) >= 4:
            return True
        if word.isdigit():
            return True

    # Two-part: SLD is a curated junk word (English word / code identifier)
    # with a common TLD — e.g. "applicationslink.com", "system.net".
    # Deliberately NOT any alphabetic SLD: that blanket rule flagged real C2
    # like telegram.org / smsreplier.net / searchmobileonline.com.
    if len(parts) == 2:
        sld = parts[0].lower()
        if sld.startswith('www'):
            sld = sld[3:]
        if not sld:
            return True
        tld = parts[-1].lower()
        real_tlds = {'com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'uk', 'de', 'jp',
                     'fr', 'au', 'ca', 'cn', 'in', 'ru', 'br', 'kr', 'it', 'es'}
        if sld in _JUNK_DOMAIN_WORDS and tld in real_tlds:
            return True

    # NOTE: no 3+ part rule. api./app./cdn./live. prefixes are used by real C2
    # (e.g. api.go108.cn) as often as by legitimate services; legitimate ones
    # are already whitelisted via BENIGN_SDK_DOMAINS before this is reached.
    return False


def _result_package(result: Dict[str, Any]) -> str:
    """Package name from result metadata (handles both key spellings)."""
    meta = result.get('metadata', {}) or {}
    return meta.get('package') or meta.get('package_name') or ''


def classify_c2(c2: Dict[str, Any]) -> Tuple[str, str]:
    """Return (classification, reason) for a C2 indicator.

    Mirrors build_final_outputs.classify_c2 so on-the-fly results match the
    offline batch output.
    """
    reasons: List[str] = []
    domain = (c2.get('domain') or '').lower()
    ip = c2.get('ip') or ''
    port = c2.get('port') or 0
    path = c2.get('path') or ''
    protocol = c2.get('protocol') or ''
    live = c2.get('live_dns') or {}
    circl = c2.get('circl') or {}

    # 0. Artifact patterns (DEX strings, build artifacts, not real domains)
    artifact_patterns = [
        r'\.aar$', r'\.so$', r'\.jar$', r'\.ttf$', r'\.gif$', r'\.png$', r'\.jpg$',
        r'^debug\.', r'^android-system\.cc$', r'^basic-android-system\.cc$',
        r'^basic-utilities\.cc$', r'^cpu-arch-detect\.cc$', r'^debug-constants\.cc$',
        r'^debug\.cc$', r'^embedded-assemblies(-zip)?\.cc$', r'^globals\.cc$',
        r'^logger\.cc$', r'^shared-constants\.cc$', r'^timezones\.cc$',
        r'^monodroid-(glue|networkinfo)\.cc$', r'^java-interop(-mono|-util|-dlfcn)?\.cc$',
        r'^mono-log-adapter\.cc$', r'^string\.cc$', r'^terminate\.cc$', r'^vector\.cc$',
        r'^xa-internal-api\.cc$', r'^internal-pinvoke-api\.cc$', r'^osbridge\.cc$',
        r'^assemblies\.x86\.blob$', r'^environment\.armeabi',
        r'^rzn7sx\.', r'^disabled-by-default-', r'^www\.srgb\.com$',
        r'^1\.6\.38\.git$', r'^fontawesome-webfont-',
        r'\.apps\.googleusercontent\.com$',
        r'^rendezvous\.niotron\.com$', r'^appyet\.video$', r'^youtu\.be$',
        r'^www\.assoc-amazon\.com$', r'^wappaygw\.alipay\.com$',
        r'^www\.hpplay\.com\.cn$', r'^mobile\.opensdk\.com$',
        r'^bili-location\.sdk\.manager\.(downgrade|request)$',
        r'^youtu\.be$',
    ]
    for pattern in artifact_patterns:
        if re.search(pattern, domain):
            return 'benign', 'artifact/build string (not a real domain)'

    # 1. Check Tier 3 allowlist first (comprehensive legitimate infrastructure)
    try:
        from analysis.step5_allowlists import is_tier3
        if is_tier3(domain):
            return 'benign', 'Tier 3 legitimate infrastructure'
    except Exception:
        logger.warning("Tier 3 allowlist unavailable; skipping tier-3 benign check", exc_info=True)

    # 2. Check BENIGN_SDK_DOMAINS (legacy whitelist)
    if any(domain == d or domain.endswith('.' + d) for d in BENIGN_SDK_DOMAINS):
        return 'benign', 'whitelisted SDK domain'

    # 3. Template/obfuscated domains
    if '%' in domain or domain.startswith('__'):
        return 'malicious', 'template/obfuscated domain'

    # 4. Junk domains (code fragments, sentence fragments)
    if _is_junk_domain(domain):
        return 'benign', 'junk domain (code fragment or sentence)'

    # 5. Suspicious TLD (only truly abused ones like .tk, .ml, .ga, .cf, .gq)
    suspicious_tld = None
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            suspicious_tld = tld
            break
    if suspicious_tld:
        reasons.append(f'suspicious TLD: {suspicious_tld}')

    # 6. Suspicious port
    try:
        if port and int(port) in SUSPICIOUS_PORTS:
            reasons.append(f'unusual port: {port}')
    except (TypeError, ValueError):
        logger.debug("Failed to parse port: %s", port)

    # 7. Unusual protocol (only real protocols, not "unknown")
    if protocol and protocol not in ('http', 'https', 'tcp', 'udp', 'dns', 'ssl', 'tls'):
        reasons.append(f'unusual protocol: {protocol}')

    # 8. NXDOMAIN - only a weak signal, not a primary indicator
    if live and not live.get('resolves', False):
        reasons.append('NXDOMAIN')

    # 9. No pDNS history for a resolving domain
    pdns = circl.get('pdns_domain', {}) if isinstance(circl, dict) else {}
    pdns_count = pdns.get('count', 0) if isinstance(pdns, dict) else 0
    if live.get('resolves', False) and pdns_count == 0:
        reasons.append('no pDNS history (newly registered?)')

    # 10. IP-direct C2 (no domain)
    if not domain and ip:
        reasons.append('IP-direct C2 (no domain)')

    # 11. Suspicious path
    path_lower = path.lower()
    if any(kw in path_lower for kw in SUSPICIOUS_PATH_KEYWORDS):
        reasons.append(f'suspicious path: {path}')

    # Classification: require at least 2 strong signals for malicious
    # NXDOMAIN alone is not enough, need another signal
    strong_reasons = [r for r in reasons if r != 'NXDOMAIN' and r != 'no pDNS history (newly registered?)']
    
    if len(strong_reasons) >= 2:
        return 'malicious', '; '.join(reasons)
    if len(strong_reasons) == 1:
        return 'suspicious', '; '.join(reasons)
    if reasons:  # Only weak signals (NXDOMAIN, no pDNS)
        return 'suspicious', '; '.join(reasons)
    return 'benign', 'clean indicator'


def _status_bucket(c2: Dict[str, Any]) -> str:
    """Normalize a C2's liveness status into active/likely_active/dead."""
    status = c2.get('status')
    if status in ('active', 'likely_active', 'dead', 'historical'):
        # historical = in pDNS history but currently down -> treat as dead for display
        return 'dead' if status == 'historical' else status
    # No enrichment: infer from live_dns if present, else unknown -> dead bucket.
    live = c2.get('live_dns') or {}
    if live:
        return 'active' if live.get('resolves', False) else 'dead'
    return 'dead'


def _ensure_classification(c2: Dict[str, Any]) -> str:
    """Return the C2's classification, computing it if the batch enrichment
    did not run for this sample."""
    label = c2.get('classification')
    if label in ('benign', 'suspicious', 'malicious'):
        return label
    label, _reason = classify_c2(c2)
    return label


def _load_geo_cache() -> Dict[str, Any]:
    """Load the shared IP geo cache produced by build_final_outputs.py."""
    geo_path = settings.WORK_DIR / 'c2_geo.json'
    if not geo_path.exists():
        return {}
    try:
        with open(geo_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("Suppressed error in _load_geo_cache: %s", exc)
        return {}


def _collect_ips(c2: Dict[str, Any]) -> List[str]:
    """All IPs associated with a C2: the direct IP plus any resolved IPs."""
    ips: List[str] = []
    if c2.get('ip'):
        ips.append(c2['ip'])
    live = c2.get('live_dns') or {}
    for ip in (live.get('ips') or []):
        ips.append(ip)
    return ips


def _is_valid_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def _classify_ip(ip: str) -> str:
    if not _is_valid_ip(ip):
        return "invalid"
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return "loopback"
        if addr.is_private:
            return "private"
        return "public"
    except ValueError:
        return "invalid"


def build_threat_intel(result: Dict[str, Any], sample_id: str) -> Dict[str, Any]:
    """Aggregate the threat-intel view for a single sample's pipeline result."""
    c2s: List[Dict[str, Any]] = result.get('c2_infrastructure', []) or []

    # Enrich liveness on-the-fly if needed
    unresolved_c2s = [c for c in c2s if not c.get('status') and not c.get('live_dns')]
    if unresolved_c2s:
        from concurrent.futures import ThreadPoolExecutor

        def resolve_dns(hostname, timeout=2.0):
            from concurrent.futures import ThreadPoolExecutor
            from concurrent.futures import TimeoutError as _FutTimeoutError
            def _resolve():
                return socket.getaddrinfo(hostname, 80, socket.AF_INET)
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(_resolve)
                try:
                    addrs = future.result(timeout=timeout)
                    return list(sorted(set(a[4][0] for a in addrs)))
                except _FutTimeoutError as exc:
                    raise _FutTimeoutError(f"DNS resolution timed out for {hostname}") from exc

        def resolve_one(c):
            domain = c.get('domain')
            ip = c.get('ip')
            if domain:
                try:
                    ips = resolve_dns(domain, timeout=2.0)
                    return c, {'live_dns': {'resolves': True, 'ips': ips}, 'status': 'active'}
                except Exception as e:
                    return c, {'live_dns': {'resolves': False, 'ips': [], 'error': str(e)[:60]}, 'status': 'dead'}
            elif ip:
                ip_class = _classify_ip(ip)
                if ip_class in ('public', 'private', 'vpn'):
                    return c, {'live_dns': {'resolves': True, 'ips': [ip]}, 'status': 'active'}
                else:
                    return c, {'live_dns': {'resolves': False, 'ips': [], 'error': 'invalid/loopback ip'}, 'status': 'dead'}
            return c, None

        with ThreadPoolExecutor(max_workers=min(len(unresolved_c2s), 10)) as pool:
            futures = [pool.submit(resolve_one, c) for c in unresolved_c2s]
            has_changes = False
            for fut in futures:
                try:
                    # Bounded: an unresolvable/blackholed domain must not pin this
                    # thread indefinitely. resolve_dns already caps at 2s per host.
                    c, update = fut.result(timeout=10.0)
                    if update:
                        c.update(update)
                        has_changes = True
                except Exception:
                    logger.debug("C2 live-dns lookup failed for %s", c.get("domain", c.get("ip", "unknown")))

        if has_changes:
            try:
                # 1. Update pipeline_result.json (atomic tmp+replace: concurrent
                #    build_threat_intel calls for the same sample would otherwise
                #    truncate each other's writes and corrupt the file)
                result_path = settings.WORK_DIR / sample_id / "pipeline_result.json"
                if result_path.exists():
                    tmp_result_path = result_path.with_name("pipeline_result.json.tmp")
                    with open(tmp_result_path, "w", encoding="utf-8") as f:
                        json.dump(result, f, indent=2, default=str)
                    os.replace(tmp_result_path, result_path)

                # 2. Update step5_c2s.json
                step5_path = settings.WORK_DIR / sample_id / "step5_c2s.json"
                if step5_path.exists():
                    with open(step5_path, "r", encoding="utf-8") as f:
                        step5_data = json.load(f)
                    
                    step5_c2s = step5_data.get('c2_infrastructure', []) or []
                    c2_map = {c.get('c2_id'): c for c in step5_c2s if c.get('c2_id')}
                    for c in c2s:
                        c2_id = c.get('c2_id')
                        if c2_id and c2_id in c2_map:
                            c2_map[c2_id].update({
                                'live_dns': c.get('live_dns'),
                                'status': c.get('status')
                            })
                    tmp_step5_path = step5_path.with_name("step5_c2s.json.tmp")
                    with open(tmp_step5_path, "w", encoding="utf-8") as f:
                        json.dump(step5_data, f, indent=2, default=str)
                    os.replace(tmp_step5_path, step5_path)
            except Exception as e:
                print(f"[WARN] Failed to save enriched threat intel for {sample_id}: {e}")

    dns = {'active': 0, 'likely_active': 0, 'dead': 0}
    classification = {'benign': 0, 'suspicious': 0, 'malicious': 0}

    enriched_c2s: List[Dict[str, Any]] = []
    geo_cache = _load_geo_cache()
    seen_ips = set()
    ips_geolocated: List[Dict[str, Any]] = []

    for c2 in c2s:
        bucket = _status_bucket(c2)
        dns[bucket] = dns.get(bucket, 0) + 1

        label = _ensure_classification(c2)
        classification[label] = classification.get(label, 0) + 1

        # Carry computed fields back so the frontend list and exports agree.
        item = dict(c2)
        item.setdefault('classification', label)
        item.setdefault('status', c2.get('status') or bucket)
        enriched_c2s.append(item)

        for ip in _collect_ips(c2):
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            ip_type = _classify_ip(ip)
            geo = geo_cache.get(ip) or _geo_lookup(ip)
            isp_data = _enrich_isp(ip) if not (geo and geo.get('isp')) else {'isp': geo.get('isp', ''), 'org': '', 'as': ''}

            censys = _censys_enrich(ip) if ip_type == 'public' else None
            if censys and censys.get('_error'):
                censys = None

            base = {'ip': ip, 'ip_type': ip_type}

            if geo:
                base.update({
                    'country': geo.get('country', 'Unknown'),
                    'region': geo.get('regionName') or geo.get('region') or '',
                    'city': geo.get('city', ''),
                    'isp': isp_data.get('isp', geo.get('isp', '')),
                    'org': isp_data.get('org', ''),
                    'as': isp_data.get('as', ''),
                    'latitude': geo.get('lat'),
                    'longitude': geo.get('lon'),
                })
            else:
                country = 'Private Network' if ip_type in ('private', 'loopback') else 'Unknown'
                base.update({
                    'country': country, 'region': '', 'city': '',
                    'isp': '', 'org': '', 'as': '',
                    'latitude': None, 'longitude': None,
                })

            if censys:
                base.setdefault('org', censys.get('provider', ''))
                base['asn'] = censys.get('asn')
                base['asn_description'] = censys.get('asn_description', '')
                base['asn_name'] = censys.get('asn_name', '')
                base['censys_country'] = censys.get('country', '')
                base['censys_city'] = censys.get('city', '')
                base['censys_provider'] = censys.get('provider', '')
                base['censys_services'] = censys.get('services', [])
                base['censys_dns_names'] = censys.get('dns_names', [])
                base['censys_certs'] = censys.get('certs', [])
                base['censys_enriched_at'] = censys.get('_enriched_at', '')

            # Surface a failed ISP lookup so an empty isp/org/as is not mistaken
            # for "this network has no owner".
            if isp_data.get('lookup_error'):
                base['isp_lookup_error'] = isp_data['lookup_error']

            ips_geolocated.append(base)

    family_data = identify_family(sample_id, result)
    family = {
        'family': family_data.get('family', 'unknown'),
        'confidence': family_data.get('confidence', 0.0),
        'method': family_data.get('method', 'none'),
        'reasoning': family_data.get('reasoning', ''),
        'candidates': family_data.get('candidates', []),
    }

    return {
        'sample_id': sample_id,
        'c2s': enriched_c2s,
        'dns': dns,
        'classification': classification,
        'ips_geolocated': ips_geolocated,
        'family': family,
        'totals': {
            'c2s': len(enriched_c2s),
            'geolocated_ips': len(ips_geolocated),
        },
    }


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

def _export_c2s(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """C2s with classification/status guaranteed, for export builders."""
    out = []
    for c2 in result.get('c2_infrastructure', []) or []:
        item = dict(c2)
        item['classification'] = _ensure_classification(c2)
        item['status'] = c2.get('status') or _status_bucket(c2)
        out.append(item)
    return out


def to_csv(result: Dict[str, Any]) -> str:
    """CSV blocklist of C2 indicators."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['classification', 'status', 'domain', 'ip', 'port',
                     'protocol', 'path', 'package_name', 'reason', 'resolved_ips'])
    for c2 in _export_c2s(result):
        live = c2.get('live_dns') or {}
        resolved = ', '.join(live.get('ips', []) or [])
        writer.writerow([
            c2.get('classification', ''),
            c2.get('status', ''),
            c2.get('domain', ''),
            c2.get('ip', ''),
            c2.get('port', ''),
            c2.get('protocol', ''),
            c2.get('path', ''),
            c2.get('package_name') or _result_package(result),
            c2.get('classification_reason', ''),
            resolved,
        ])
    return buf.getvalue()


def to_stix(result: Dict[str, Any], sample_id: str) -> Dict[str, Any]:
    """STIX 2.0-style bundle of C2 indicators."""
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    bundle = {
        'type': 'bundle',
        'id': f'bundle--{sample_id[:32]}',
        'objects': [],
    }
    for c2 in _export_c2s(result):
        domain = c2.get('domain') or ''
        ip = c2.get('ip') or ''
        if not domain and not ip:
            continue
        pattern = (f"[domain-name:value = '{domain}']" if domain
                   else f"[ipv4-addr:value = '{ip}']")
        bundle['objects'].append({
            'type': 'indicator',
            'id': f"indicator--{sample_id[:16]}-{c2.get('c2_id', 'unknown')}",
            'created': now,
            'valid_from': now,
            'name': domain or ip,
            'pattern': pattern,
            'pattern_type': 'stix',
            'labels': [c2.get('classification', ''), c2.get('status', ''), 'c2'],
        })
    return bundle


# Domains and IPs come from the analysed malware, so they are format-checked before
# they go into a rule: a quote or semicolon in a domain would break out of the rule.
_RULE_DOMAIN_RE = re.compile(r'^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$')
_SURICATA_SID_BASE = 1000000  # Suricata reserves sids below 1,000,000 for its own rules


def _is_safe_domain(value: str) -> bool:
    return bool(_RULE_DOMAIN_RE.match(value)) and len(value) <= 253


def _is_safe_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def to_suricata(result: Dict[str, Any], sample_id: str) -> str:
    """Suricata rules for this sample's non-benign C2 domains and IPv4 addresses."""
    lines: List[str] = []
    sid = _SURICATA_SID_BASE
    seen = set()
    for c2 in _export_c2s(result):
        if c2.get('classification') == 'benign':
            continue
        domain = (c2.get('domain') or '').lower()
        ip = c2.get('ip') or ''
        if domain and _is_safe_domain(domain) and ('dns', domain) not in seen:
            seen.add(('dns', domain))
            lines.append(
                f'alert dns $HOME_NET any -> any any (msg:"DroidForensix C2 domain {domain}"; '
                f'dns.query; content:"{domain}"; nocase; endswith; classtype:trojan-activity; '
                f'sid:{sid}; rev:1; metadata:sample_sha256 {sample_id};)'
            )
            sid += 1
        elif ip and _is_safe_ipv4(ip) and ('ip', ip) not in seen:
            seen.add(('ip', ip))
            lines.append(
                f'alert ip $HOME_NET any -> {ip} any (msg:"DroidForensix C2 address {ip}"; '
                f'classtype:trojan-activity; sid:{sid}; rev:1; metadata:sample_sha256 {sample_id};)'
            )
            sid += 1
    if not lines:
        return f'# DroidForensix: no malicious or suspicious C2 indicators for {sample_id}\n'
    return '\n'.join(lines) + '\n'


def to_yara(result: Dict[str, Any], sample_id: str) -> str:
    """Generate a per-sample YARA rule from this sample's C2 indicators."""
    metadata = result.get('metadata', {}) or {}
    package = _result_package(result) or 'unknown'
    rule_name = f"droidforensix_{sample_id[:16]}"

    strings: List[str] = []
    seen = set()
    idx = 0
    for c2 in _export_c2s(result):
        if c2.get('classification') == 'benign':
            continue
        for value in (c2.get('domain'), c2.get('raw_url')):
            if not value or value in seen:
                continue
            seen.add(value)
            escaped = value.replace('\\', '\\\\').replace('"', '\\"')
            strings.append(f'        $s{idx} = "{escaped}" ascii wide nocase')
            idx += 1

    lines = [f'rule {rule_name}', '{', '    meta:']
    lines.append(f'        description = "Auto-generated C2 indicators for {package}"')
    lines.append(f'        sample_sha256 = "{metadata.get("sha256", sample_id)}"')
    lines.append('        generator = "DroidForensix"')
    if strings:
        lines.append('    strings:')
        lines.extend(strings)
        lines.append('    condition:')
        lines.append('        any of them')
    else:
        lines.append('    condition:')
        lines.append('        false  // no malicious/suspicious C2 indicators extracted')
    lines.append('}')
    return '\n'.join(lines) + '\n'
