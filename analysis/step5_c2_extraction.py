"""
Step 5: C2 Infrastructure Extraction

Parses URLs/IPs from decoded payloads and direct source strings into structured
C2 records: protocol, domain, port, path, query params, IP classification,
communication type, and confidence scores.
"""

import ipaddress
import json
import logging
import re
import socket
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs

from analysis.ip_validation import calculate_ip_legitimacy_score
from backend.config import settings

try:
    from backend.circl_client import CIRCLAuthError, CIRCLClient, CIRCLClientError
    CIRCL_AVAILABLE = True
except ImportError:
    CIRCL_AVAILABLE = False


class C2ExtractionError(Exception):
    """Raised when C2 extraction fails."""
    pass


logger = logging.getLogger(__name__)

C2_FALLBACK_CONFIDENCE_THRESHOLD = 0.3

# Bounds for optional CIRCL enrichment: cap the number of records enriched and
# the total wall-clock budget so a slow/unreachable CIRCL service cannot stall
# the pipeline step past its timeout.
C2_ENRICHMENT_MAX_RECORDS = 30
C2_ENRICHMENT_BUDGET_SECONDS = 60.0


# ---------------------------------------------------------------------------
# Patterns and constants
# ---------------------------------------------------------------------------

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

# Known benign SDK, documentation, and namespace domains that are not C2.
# These appear frequently in legitimate apps and dilute the C2 signal.
BENIGN_DOMAINS = {
    # Android / Google
    "schemas.android.com",
    "play.google.com",
    "developer.android.com",
    "issuetracker.google.com",
    "maps.google.com",
    "www.googleapis.com",
    "www.google.com",
    "google.com",
    "youtube.com",
    "android.com",
    "www.android.com",
    "gstatic.com",
    # Java / Sun / Oracle
    "java.sun.com",
    "sun.com",
    "oracle.com",
    "openjdk.java.net",
    "javaee.github.io",
    # W3C / XML
    "www.w3.org",
    "xml.org",
    "xmlpull.org",
    "www.w3.org",
    "xmlns.org",
    # Development platforms / libraries
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "www.slf4j.org",
    "apache.org",
    "www.apache.org",
    "kotlinlang.org",
    # Adobe / media
    "ns.adobe.com",
    "aomedia.org",
    # JetBrains
    "youtrack.jetbrains.com",
    "developer.apple.com",
    "docs.flutter.dev",
    # Mozilla
    "mozilla.org",
    "www.mozilla.org",
    # Common legitimate app endpoints observed in dataset
    "videolan.org",
    "www.videolan.org",
    "etesync.com",
    "etebase.com",
    "dashboard.etebase.com",
    "api.etebase.com",
    "api.etesync.com",
    "fastmail.com",
    "www.fastmail.com",
    "api.fastmail.com",
    "api.login.aol.com",
    "thunderbird.net",
    "autoconfig.thunderbird.net",
    "jrpn.jovial.com",
    "legacy.jrpn.jovial.com",
    "dmfs.org",
    "schema.dmfs.org",
    "t.me",
    # Search / portals (legitimate, often embedded in browsers or regional apps)
    "yandex.ru",
    "yandex.com",
    "yahoo.com",
    "bing.com",
    "duckduckgo.com",
    "baidu.com",
    # PDF/file converter services (legitimate, often embedded in readers)
    "cloudconvert.com",
    "www.zamzar.com",
    "zamzar.com",
    "www.pdfrotate.com",
    "pdfrotate.com",
    "rotatepdf.net",
    "www.rotatepdf.net",
    "smallpdf.com",
    "topdf.com",
    "smaltilpdf.com",
    # Browser / mail / sync app endpoints observed as false positives
    "crbug.com",
    "bugs.chromium.org",
    "oauth2.googleapis.com",
    "googleapis.com",
    "outlook.office.com",
    "office.com",
    # Social/communication APIs commonly embedded in apps
    "api.weibo.com",
    "weibo.com",
    "www.plurk.com",
    "plurk.com",
    "t.qq.com",
    "open.t.qq.com",
    "tomeet.net",
    "t.tomeet.net",
    "www.rabbitmq.com",
    "rabbitmq.com",
    # URL shortener services (legitimate)
    "bitly.com",
    "tinyurl.com",
    "ow.ly",
    "goo.gl",
    "is.gd",
    "t.co",
    # Barcode/scanning libraries
    "zxing.appspot.com",
    "zxing.org",
    # GPS/map services
    "www.gpsspg.com",
    "gpsspg.com",
    # Facebook/tracking services
    "www.facebookmobileweb.com",
    "facebookmobileweb.com",
    "connect.facebook.net",
    # SDK/additional services
    "srowen.com",
    "bsplus.srowen.com",
    "plus.me",
    "login.microsoftonline.com",
    "graph.microsoft.com",
    "dashif.org",
    "syncadapter.bitfire.at",
    "www.bitfire.at",
    "bitfire.at",
    "dnsjava.org",
    "ical4j.github.io",
    "square.github.io",
    "accounts.stage.mozaws.net",
    "stable.dev.lcip.org",
    "identity.mozilla.com",
    "accounts.firefox.com",
    "relay.firefox.com",
    "firefox.com",
    "mozilla.github.io",
    "docs.videolan.me",
    "android.googlesource.com",
    "g.co",
    "goo.gle",
    "api.flutter.dev",
    "pub.dev",
    "zulip.readthedocs.io",
    "blog.zulip.com",
    "secure.gravatar.com",
    "drift.simonbinder.eu",
    "purl.org",
    "projectlombok.org",
    "insert-koin.io",
    "k9mail.app",
    "forum.k9mail.app",
    "tb.pro",
    "auth.tb.pro",
    "auth-stage.tb.pro",
    "jsoup.org",
    "jutf7.sourceforge.net",
    "jcraft.com",
    "jcip.net",
    # PDF / ebook / converter services
    "samlib.ru",
    "toepub.com",
    "online-convert.com",
    "document.online-convert.com",
    "ebook.online-convert.com",
    "pdf2docx.com",
    "m.gutenberg.org",
    "gutenberg.org",
    "bookserver.archive.org",
    "archive.org",
    "f-droid.org",
    # Media / streaming standards
    "schemas.xmlsoap.org",
    "xmlsoap.org",
    "www.shoutcast.com",
    "xspf.org",
    "lame.sf.net",
    "www.twolame.org",
    "schemas.upnp.org",
    "upnp.org",
    "www.tvdr.de",
    "www.crunchyroll.com",
    "musicbrainz.org",
    "www.icecast.org",
    "ns.adobe.com",
    "www.brynosaurus.com",
    # Document / ebook format schemas and services
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    "openoffice.org",
    "docs.oasis-open.org",
    "schemas.openxps.org",
    "www.idpf.org",
    "www.daisy.org",
    "librera.mobi",
    "beta.librera.mobi",
    "worldswithoutend.com",
    "www.worldswithoutend.com",
    "manybooks.net",
    "idownload.manybooks.net",
    "goodreads.com",
    "www.goodreads.com",
    "amazon.com",
    "www.amazon.com",
    "issuu.com",
    "wiki.mobileread.com",
    "cdn.jsdelivr.net",
    "jsdelivr.net",
    "emma.cloud.tabdigital.eu",
    # Unicode / XML constants
    "www.unicode.org",
    "unicode.org",
    "javax.xml.xmlconstants",
    # Certificate / PKI / OCSP / CRL endpoints
    "d-trust.net",
    "www.d-trust.net",
    "crl.d-trust.net",
    "webrtc.org",
    "www.webrtc.org",
    "accv.es",
    "www.accv.es",
    "fineid.fi",
    "www.fineid.fi",
    "proxy.fineid.fi",
    "eadtrust.eu",
    "crl.eadtrust.eu",
    "ca.eadtrust.eu",
    "cert.fnmt.es",
    "www.cert.fnmt.es",
    "globaltrust.eu",
    "service.globaltrust.eu",
    "harica.gr",
    "repo.harica.gr",
    "crl.harica.gr",
    "fina.hr",
    "rdc.fina.hr",
    "anf.es",
    "www.anf.es",
    "crl.anf.es",
    "ocsp.anf.es",
    "firmaprofesional.com",
    "crl.firmaprofesional.com",
    "multicert.com",
    "pkiroot.multicert.com",
    "a-trust.at",
    "www.a-trust.at",
    "crl.a-trust.at",
    "certsign.ro",
    "www.certsign.ro",
    "halcom.si",
    "domina.halcom.si",
    "quovadisglobal.com",
    "www.quovadisglobal.com",
    "ca.gov.si",
    "www.ca.gov.si",
    "posta.si",
    "postarca.posta.si",
    "certeurope.fr",
    "www.certeurope.fr",
    "nbusr.sk",
    "ep.nbusr.sk",
    # Mozilla / Google endpoints
    "llvm.googlesource.com",
    "wikipedia.org",
    "ja.wikipedia.org",
    "tenki.jp",
    # Search engines / portals observed in browsers
    "qwant.com",
    "www.qwant.com",
    "api.qwant.com",
    "lite.qwant.com",
    "ecosia.org",
    "www.ecosia.org",
    "ac.ecosia.org",
    "brave.com",
    "search.brave.com",
    "kagi.com",
    "startpage.com",
    "www.startpage.com",
    "metager.org",
    "mojeek.com",
    "www.mojeek.com",
    "yahoo.co.jp",
    "yelp.com",
    "www.yelp.com",
    # Certificate / trust service providers observed in Fennec
    "stampit.org",
    "www.stampit.org",
    "netlock.hu",
    "crl3.netlock.hu",
    "entrust.net",
    "www.entrust.net",
    "infocert.it",
    "www.firma.infocert.it",
    "izenpe.com",
    "www.izenpe.com",
    "evrotrust.com",
    "www.evrotrust.com",
    "postsignum.cz",
    "www.postsignum.cz",
    "www2.postsignum.cz",
    "postsignum.ttc.cz",
    # Documentation / standards / libraries
    "khronos.org",
    "www.khronos.org",
    "registry.khronos.org",
    "docs.rs",
    "sqlite.org",
    "geonames.org",
    "download.geonames.org",
    "ietf.org",
    "www.ietf.org",
    "aomediacodec.github.io",
    "cairographics.org",
    "allizom.org",
    "ads.allizom.org",
    "addons.allizom.org",
    "fastly-edge.com",
    "mozilla-ohttp.fastly-edge.com",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "mzl.la",
    "firefox.com.cn",
    "accounts.firefox.com.cn",
    # Additional CA / PKI / trust providers observed in Fennec
    "digicert.com",
    "cacerts.digicert.com",
    "crl3.digicert.com",
    "globalsign.com",
    "secure.globalsign.com",
    "www.globalsign.com",
    "telesec.de",
    "tstlsrr23.crl.telesec.de",
    "tstlsrr23.ocsp.telesec.de",
    "tstlsrr23.crt.telesec.de",
    "grcl3.crl.telesec.de",
    "grcl3.ocsp.telesec.de",
    "grcl3.crt.telesec.de",
    "bank-verlag.de",
    "www.bank-verlag.de",
    "e-szigno.hu",
    "erootca2024-crl.e-szigno.hu",
    "erootca2024-ca.e-szigno.hu",
    "cp.e-szigno.hu",
    "rootca2009-crl1.e-szigno.hu",
    "rootca2009-crl2.e-szigno.hu",
    "rootca2009-crl3.e-szigno.hu",
    "rootca2009-ca1.e-szigno.hu",
    "rootca2009-ca2.e-szigno.hu",
    "rootca2009-ca3.e-szigno.hu",
    "rootca2017-crl1.e-szigno.hu",
    "rootca2017-crl2.e-szigno.hu",
    "rootca2017-crl3.e-szigno.hu",
    "rootca2017-ca1.e-szigno.hu",
    "rootca2017-ca2.e-szigno.hu",
    "rootca2017-ca3.e-szigno.hu",
    "tlsrootca2023-crl.e-szigno.hu",
    "tlsrootca2023-ca.e-szigno.hu",
    "etlsrootca2024-crl.e-szigno.hu",
    "etlsrootca2024-ca.e-szigno.hu",
    "disig.sk",
    "eidas.disig.sk",
    "nccert.pl",
    "www.nccert.pl",
    "b-trust.org",
    "www.b-trust.org",
    "certigna.fr",
    "www.certigna.fr",
    "wwww.certigna.fr",
    "autorite.certigna.fr",
    "dhimyotis.com",
    "autorite.dhimyotis.com",
    "snca.gov.sk",
    "zone.nfqes.sk",
    "globaltrustedsign.com",
    "pki02.globaltrustedsign.com",
    "pki.globaltrustedsign.com",
    "chambersign.fr",
    "pc.chambersign.fr",
    "actalis.it",
    "www.actalis.it",
    "pec.it",
    "www.pec.it",
    "infonotary.com",
    "repository.infonotary.com",
    "swisssign.com",
    "repository.swisssign.com",
    "ssl.com",
    "cert.ssl.com",
    "www.ssl.com",
    "crls.ssl.com",
    # Additional services
    "ameblo.jp",
    "mozgcp.net",
    "prod.ohttp-gateway.prod.webservices.mozgcp.net",
    "shadertoy.com",
    "www.shadertoy.com",
    "fxtf.org",
    "drafts.fxtf.org",
    "stackexchange.com",
    "math.stackexchange.com",
    "jdashg.github.io",
    "dartbug.com",
    # Indian payment gateways
    "paytm.in", "securegw.paytm.in", "easypay.paytm.in",
    "payu.in", "payumoney.com", "ccavenue.com",
    "mobikwik.com", "zaakpay.com",
    "npci.org.in",
    # Indian bank 3D Secure / ACS
    "onlinesbi.com", "hdfcbank.com", "icicibank.com",
    "citibank.co.in", "enstage.com", "idbibank.com",
    "amxvpos.com", "deutschebank.co.in",
    # Xiaomi / Mi ecosystem
    "xiaomi.com", "xiaomi.net", "mi.com",
    "xmpush.global.xiaomi.com", "appmifile.com",
    # Payment 3DS authentication providers
    "arcot.com",
    # Xiaomi POCO sub-brand
    "po.co",
    # Other legitimate services
    "cashify.in", "uber.com", "schema.org",
    "twitter.com", "worldpay.com", "apaylater.com",
    "indusguard.com", "monstat.com",
    "paysecure.ru",
    "paypal.com", "www.paypal.com",
    # Known SDK / analytics / crash-reporting domains
    "facebook.com", "www.facebook.com", "graph.facebook.com",
    "graph.facebook.net", "fbcdn.net", "cdninstagram.com",
    "appsFlyer.com", "appsflyer.com",
    "sentry.io", "sentry-cdn.com",
    "adjust.com", "app.adjust.com",
    "onesignal.com", "api.onesignal.com",
    "amplitude.com", "api.amplitude.com",
    "firebase.io", "firebaseio.com",
    "googleapis.com", "firebasestorage.googleapis.com",
    "crashlytics.com", "crashlytics.com",
    # Financial / banking SDKs
    "raiffeisen.at", "www.raiffeisen.at",
    # OCR / document scanning SDKs
    "microblink.com", "www.microblink.com", "baltazar.microblink.com", "ping.microblink.com",
    # ORM libraries
    "greenrobot.org",
    # Microsoft / Xamarin / Azure
    "app-measurement.com", "googlesyndication.com", "pagead2.googlesyndication.com",
    "docs.microsoft.com", "mobile.events.data.microsoft.com",
    "xamarin.com", "raw.githubusercontent.com",
    # Generic truncated URLs (common in Android SDK samples/debug strings)
    "www.google", "www.googleapis",
    # Reserved/testing domains
    "example.com", "www.example.com",
    # Development / testing / documentation
    "curl.haxx.se", "localhost",
    # Cloud / hosting
    "huawei.com", "appgallery.cloud.huawei.com",
    "appspot.com", "ge-map-overlays.appspot.com", "mein-elba-app.appspot.com",
    "microsoft.com", "azure.com", "appcenter.ms", "in.appcenter.ms",
    # Open source / standards
    "mono-project.com", "opengis.net", "gexf.net", "colorcombos.com",
    "aiim.org", "iec.ch", "color.org", "sRGB.com",
    "bzip.org", "memtest86.com",
    # App builder / no-code platforms (common false C2s in benign apps)
    "kodular.io", "appypie.com", "appsyonamovil.com",
    # Analytics / advertising / attribution (legitimate SDK integrations)
    "google-analytics.com", "googletagmanager.com", "appsflyer.com",
    "adjust.com", "amplitude.com", "onesignal.com",
    # Payment / commerce SDKs (legitimate, embedded in benign apps)
    "stripe.com", "paypalobjects.com", "mclient.alipay.com",
    "gauravpaypal.com", "dream11.com",
    # Social / communication APIs
    "whatsapp.com", "fb.gg", "disqus.com", "flickr.com",
    "t.me", "telegram.me",
    # Media / content / CDN
    "grofers.com", "adobe.com", "macromedia.com",
    "appscreative.info", "go360days.com",
    # Mobile platforms / OEM services
    "miui.com", "xiaomi.net", "novastar.tech",
    "aka.ms", "live.com", "xboxlive.com",
    # Open source / documentation / libraries
    "gnu.org", "openssl.org", "sil.org", "instabug.com",
    "isefeel.com", "cashdorado.de",
    # App store / publisher links
    "apple.com",
    # Utilities / SDKs
    "exoplayer.dev", "page.link",
    # Regional / misc
    "opera.com", "mail.ru", "mobi911.ru", "qq.com", "mit.edu",
    # Media / streaming
    "hulu.com", "akamaihd.net", "braze.com",
    # Mapping / location SDKs
    "mapbox.com", "www.mapbox.com",
    # Gaming
    "minecraft.net", "mojang.com",
    # Social / professional
    "linkedin.com", "passport.net",
    # CDN / cloud infrastructure
    "akamaiedge.net", "azureedge.net", "cloudfront.net",
    # Misc legitimate services
    "osgwiki.com", "s1mobilecard.co.kr",
    # No-code / cross-platform app builders
    "appybuilder.com", "appcelerator.com",
    # Iranian app store
    "cafebazaar.ir",
    # Free hosting used by app builder SDKs
    "byethost3.com", "instantaccess.io",
    # Geo/IP services used by ad SDKs
    "p3insight.de",
    # CDN / icon / font services
    "fontawesome.com",
    # Google Material Design references
    "material.io",
    # SaaS APIs commonly embedded by app builders
    "airtable.com", "qrserver.com", "ocr.space",
    # Android library author websites (embedded in library metadata)
    "mikepenz.com",
}

# TLD-like tokens produced by over-matching URL regex on code fragments.
# These are not real TLDs and should be rejected during domain validation.
INVALID_TLDS = {
    "world", "years", "recent", "icon", "css", "language", "style",
    "shortcut", "interpretation", "encodeuricomponent", "adobe",
}

BENIGN_DOMAIN_PATTERNS = {
    # Certificate / PKI infrastructure endpoints (OCSP, CRL, CRT, CA, PKI)
    r"^crl\.",
    r"^ocsp\.",
    r"^pki\.",
    r"^ca\.",
    r"^crt\.",
    r"^proxy\.",
    r"^repo\.",
    r"^rdc\.",
    r"^service\.",
    r"^postarca\.",
    r"^qcrldp\d+\.",
    r"^erootca\d+-",
    r"^rootca\d+-",
    r"^tlsrootca\d+-",
    r"^etlsrootca\d+-",
    r"^autorite\.",
    r"^r\.",
    # Service / docs subdomains that are always legitimate in this dataset
    r"\.readthedocs\.io$",
    r"\.services\.mozilla\.com$",
    r"\.mozaws\.net$",
    r"\.dev\.lcip\.org$",
    r"\.googlesource\.com$",
    r"\.stage\.mozaws\.net$",
    r"\.mozgcp\.net$",
    r"\.stackexchange\.com$",
}

BENIGN_URL_PATHS = {
    "/apk/res/android",
    "/apk/res-auto",
}

# Mobile advertising and analytics networks. These are legitimate monetization
# endpoints, but they frequently appear in adware / grayware. They should not
# be treated as high-confidence malware C2s.
AD_NETWORK_DOMAINS = {
    # Ad networks
    "airpush.com",
    "leadbolt.net",
    "leadboltapps.net",
    "searchmobileonline.com",
    "mobpartner.com",
    "tapjoy.com",
    "chartboost.com",
    "applovin.com",
    "fyber.com",
    "inneractive.com",
    "inmobi.com",
    "admob.com",
    "googleadservices.com",
    "doubleclick.net",
    "mopub.com",
    "millennialmedia.com",
    "supersonicads.com",
    "ironsource.com",
    "unity3d.com",
    "vungle.com",
    "adcolony.com",
    "startapp.com",
    "appnext.com",
    "digitalturbine.com",
    "superrewards.com",
    "flurry.com",
    "crashlytics.com",
    "appsflyer.com",
    "adjust.com",
    "kochava.com",
    # Iranian / Middle East ad networks
    "adivery.com",
    "tapsell.ir",
    "pushe.co",
    # Shorteners / redirectors commonly used by ad SDKs
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
}

# Known DTD / XML Schema / namespace URIs that are library/documentation
# references, never actual network C2 traffic.
BENIGN_URIS = {
    "http://java.sun.com/dtd/properties.dtd",
    "http://java.sun.com/xml/ns/javaee",
    "http://java.sun.com/jsp/jstl/core",
    "http://www.w3.org/2000/xmlns",
    "http://www.w3.org/2001/XMLSchema",
    "http://www.w3.org/2001/XMLSchema-instance",
    "http://www.w3.org/1999/xlink",
    "http://www.w3.org/1999/xhtml",
    "http://www.w3.org/2005/Atom",
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "http://purl.org/rss/1.0/",
    "http://www.opml.org/spec2",
    "http://www.springframework.org/schema/beans",
    "http://maven.apache.org/xsd/maven-4.0.0.xsd",
    "http://schemas.android.com/apk/res/android",
    "http://schemas.android.com/apk/res-auto",
}

# Known VPN/proxy ranges (common examples, not exhaustive)
VPN_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_benign_uri_reference(url: str) -> bool:
    """Return True if the URL is a known DTD, XML schema, or namespace URI."""
    try:
        url_lower = url.strip().lower()
        if url_lower in BENIGN_URIS:
            return True
        if any(url_lower.startswith(uri.lower()) for uri in BENIGN_URIS):
            return True
        parsed = urlparse(url)
        path = parsed.path.lower()
        if path.endswith((".dtd", ".xsd", ".xsl", ".xml")):
            return True
    except Exception:
        logger.debug("Failed to check URI reference: %s", url)
    return False


def is_benign_url(url: str) -> bool:
    """Return True if URL belongs to a known benign SDK/documentation endpoint."""
    try:
        # Strip trailing punctuation that can be captured by URL regex
        url_clean = url.strip().rstrip(".,;:!?')")
        if is_benign_uri_reference(url_clean):
            return True
        parsed = urlparse(url_clean)
        if parsed.hostname:
            hostname = parsed.hostname.lower().lstrip("www.")
            if hostname in BENIGN_DOMAINS:
                return True
            # Also match any subdomain of a benign domain
            parts = parsed.hostname.lower().split(".")
            for i in range(len(parts)):
                if ".".join(parts[i:]) in BENIGN_DOMAINS:
                    return True
            # Pattern-based matching (e.g. crl.*, ocsp.*, *.readthedocs.io)
            host_lower = parsed.hostname.lower()
            for pattern in BENIGN_DOMAIN_PATTERNS:
                if re.search(pattern, host_lower):
                    return True
        for benign_path in BENIGN_URL_PATHS:
            if benign_path in parsed.path:
                return True
    except Exception:
        logger.debug("Failed to check benign URL: %s", url)
    return False


def is_ad_network(domain: str) -> bool:
    """Return True if domain belongs to a known ad/analytics network."""
    if not domain:
        return False
    domain_lower = domain.lower().lstrip("www.")
    if domain_lower in AD_NETWORK_DOMAINS:
        return True
    # Match subdomains (e.g. api.airpush.com -> airpush.com)
    parts = domain_lower.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in AD_NETWORK_DOMAINS:
            return True
    return False


def classify_ip(ip: str) -> str:
    """Classify IP as private, loopback, vpn, or public."""
    if not is_valid_ip(ip):
        return "invalid"
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return "loopback"
        if addr.is_private:
            return "private"
        # Check known VPN ranges (redundant with is_private but explicit)
        for net in VPN_RANGES:
            if addr in net:
                return "vpn"
        return "public"
    except ValueError:
        return "invalid"


def infer_communication_type(url: str, source_location: str) -> str:
    """Infer communication type from URL scheme and source context."""
    parsed = urlparse(url)
    source_lower = source_location.lower()

    if parsed.scheme in ("http", "https"):
        return "http_request"
    if "inetaddress" in source_lower or "dns" in source_lower:
        return "dns_query"
    if "socket" in source_lower:
        return "socket"
    if parsed.scheme in ("tcp", "udp"):
        return parsed.scheme
    return "other"


# ---------------------------------------------------------------------------
# Raw string domain/IP filters (fallback C2 detection)
# ---------------------------------------------------------------------------

CODE_PACKAGE_PREFIXES = (
    "java.", "javax.", "android.", "androidx.", "kotlin.", "kotlinx.",
    "com.android.", "dalvik.", "org.apache.", "org.json.", "org.xml.",
    "org.w3c.", "org.slf4j.", "org.junit.", "org.mockito.",
    "com.google.android.", "com.google.common.", "com.squareup.",
    "okhttp3.", "okio.", "retrofit2.", "rx.", "reactivestreams.",
    "butterknife.", "dagger.", "hilt.", "junit.", "io.flutter.",
    "org.jetbrains.", "org.intellij.",
    # .NET framework namespaces
    "system.", "microsoft.", "net.", "windows.",
)


PSEUDO_TLDS = frozenset({
    # Java field/method names commonly parsed as fake TLDs
    "name", "value", "body", "length", "size", "limit", "pos", "sink", "source",
    "key", "type", "data", "mode", "path", "file", "line", "text", "hash",
    "code", "flag", "host", "port", "user", "pass", "auth", "role", "item",
    "list", "map", "set", "val", "min", "max", "sum", "avg", "idx",
    "tag", "url", "uri", "ref", "id", "by", "to", "in", "at", "of", "or",
    "class", "field", "method", "param", "args", "config", "buffer", "schema",
    "total", "count", "index", "offset", "order", "group", "scope", "level",
    "stack", "queue", "thread", "task", "job", "event", "state", "status",
    # Additional method/field names that look like TLDs
    "call", "add", "get", "set", "put", "del", "find", "next", "prev",
    "first", "last", "head", "tail", "begin", "end", "start", "stop",
    "read", "write", "send", "recv", "load", "save", "open", "close",
    "exec", "run", "do", "make", "new", "free", "bind", "join", "split",
    "enter", "exit", "init", "done", "wait", "notify", "lock", "unlock",
    "info", "meta", "args", "opts", "flags", "items", "entry", "rows",
    "cols", "cell", "node", "edge", "link", "obj", "ctx", "biz", "loop",
    "domain", "view", "form", "page", "msg", "str", "int", "bool", "arr",
    # 2-letter codes that are real TLDs but overwhelmingly code refs in APK strings
    "in", "at", "id", "pl",
})

# Known real TLDs to avoid over-filtering legitimate 2-part domains
REAL_TLDS = frozenset({
    "com", "org", "net", "edu", "gov", "mil", "io", "co", "uk", "de", "jp",
    "fr", "au", "ca", "cn", "in", "ru", "br", "kr", "it", "es", "mx", "nl",
    "se", "no", "fi", "dk", "pl", "at", "ch", "be", "ie", "nz", "sg", "hk",
    "tw", "my", "ph", "th", "vn", "id", "za", "eg", "ng", "ke", "ar", "cl",
    "co", "us", "xyz", "top", "club", "online", "site", "live", "app", "dev",
    "info", "biz", "pro", "me", "mobi", "asia", "tel", "int", "eu",
    "tech", "ai", "cloud", "shop", "store", "blog", "wiki",
    "media", "news", "video", "tv", "cc", "guru", "rocks", "world",
})


def _is_code_reference(domain: str) -> bool:
    """Return True if the domain looks like a code package/class reference, not a real domain."""
    if domain.startswith(CODE_PACKAGE_PREFIXES):
        return True
    parts = domain.split(".")
    if len(parts) < 2:
        return True
    # If any part has an uppercase letter → Java class/method naming convention
    for p in parts:
        if any(c.isupper() for c in p):
            return True
    # Likely a method reference like "foo.bar.Baz.method" (already caught by uppercase)
    # 2-part names like "builder.name", "response.body" — TLD is a pseudo-TLD
    if len(parts) == 2 and parts[-1] in PSEUDO_TLDS:
        return True
    # 2-part all-lowercase with unknown TLD → probably code, not a real domain
    if len(parts) == 2 and parts[-1] not in REAL_TLDS:
        return True
    # "com.XX" 2-part patterns (e.g., com.ar, com.au, com.br) — Java package abbreviations, not real domains
    if len(parts) == 2 and parts[0] == "com" and len(parts[-1]) <= 3 and parts[-1].isalpha():
        return True
    # 3+ part where last part is a pseudo-TLD (e.g., "msg.function.not.found.in", "msg.reserved.id")
    if len(parts) >= 3 and parts[-1] in PSEUDO_TLDS:
        return True
    # 3+ part all-lowercase: only filter if last part is NOT a known real TLD
    # Catches patterns like "msg.catchall.xyz" (not in PSEUDO_TLDS but also not in REAL_TLDS)
    if len(parts) >= 3 and all(p.isalpha() for p in parts) and parts[-1] not in REAL_TLDS:
        return True
    # 3+ part with digits/mixed chars: filter if first segment is short + alpha (package-like)
    if len(parts) >= 3 and parts[-1] not in REAL_TLDS:
        if parts[0].isalpha() and len(parts[0]) <= 6:
            return True
    # 5+ parts with short first segment → deep Java package path (subdomains with 5+ levels are virtually non-existent)
    if len(parts) >= 5 and parts[0].isalpha() and len(parts[0]) <= 6:
        return True
    # Android resource references
    if domain.startswith("com.yourpackage.") or domain.endswith(".R$") or domain.endswith(".R"):
        return True

    # .NET namespace pattern: 2-part where SLD is a common .NET namespace word
    # e.g., "system.net", "system.io", "system.web" — not real C2 domains
    _DOTNET_NAMESPACE_WORDS = frozenset({
        "system", "net", "windows", "microsoft", "mscorlib",
    })
    if len(parts) == 2 and parts[0].lower() in _DOTNET_NAMESPACE_WORDS and parts[-1] in REAL_TLDS:
        return True

    return False


_COMMON_ENGLISH_WORDS = frozenset({
    'the', 'a', 'an', 'and', 'or', 'but', 'if', 'is', 'are', 'was', 'were',
    'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did',
    'will', 'would', 'could', 'should', 'may', 'might', 'shall', 'can',
    'this', 'that', 'these', 'those', 'it', 'its', 'they', 'them', 'their',
    'what', 'which', 'who', 'whom', 'when', 'where', 'why', 'how',
    'all', 'each', 'every', 'both', 'few', 'some', 'any', 'no', 'none',
    'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very', 'just',
    'because', 'as', 'until', 'while', 'of', 'at', 'by', 'for', 'with',
    'about', 'against', 'between', 'into', 'through', 'during', 'before',
    'after', 'above', 'below', 'from', 'up', 'down', 'in', 'out', 'on',
    'off', 'over', 'under', 'again', 'further', 'then', 'once',
    'here', 'there', 'when', 'where', 'why', 'thing', 'things', 'test',
    'demo', 'sample', 'example', 'hello', 'world', 'foo', 'bar', 'baz',
    'name', 'user', 'pass', 'login', 'admin', 'root', 'home', 'page',
    'site', 'file', 'data', 'info', 'text', 'msg', 'mail',
})


def _is_likely_junk_domain(domain: str) -> bool:
    if not domain or '%' in domain:
        return True
    parts = domain.split('.')
    tld = parts[-1].lower().rstrip('.')

    # Empty TLD (trailing dot) — "books.google." — never a real domain
    if not tld:
        return True

    # File paths masquerading as domains (.so, .apk, .jar, .dex, .png, etc.)
    if tld in ('so', 'apk', 'jar', 'dex', 'png', 'jpg', 'jpeg', 'gif', 'xml', 'json', 'svg', 'ico', 'css', 'js', 'ts'):
        return True

    # Single-word www subdomains: "www.Word" or "www.word" — overwhelmingly garbled
    if len(parts) == 2 and parts[0].lower() == 'www' and len(parts[1]) <= 8 and parts[1].isalpha():
        return True

    # Common English word as second-level domain with a real TLD:
    # "the.com", "thing.org", "world.info" — these are never real C2 domains
    if len(parts) == 2:
        sld = parts[0].lower()
        if sld in _COMMON_ENGLISH_WORDS and tld in ('com', 'org', 'net', 'info', 'biz', 'world', 'site', 'live', 'online'):
            return True

    # Short 2-letter TLD with short SLD: "l.ie", "p1.p2.cl" — likely code noise
    if len(parts) == 2 and len(tld) <= 2 and len(parts[0]) <= 3:
        return True

    # Single-part domains with no dots (bare words) — already filtered by DOMAIN_RE
    # but catch truncated forms like "books.google." where TLD is empty
    if len(parts) >= 2 and all(len(p) <= 3 for p in parts) and not any(p.isdigit() for p in parts):
        return True

    return False


def _is_benign_domain(domain: str) -> bool:
    """Return True if domain is in the known benign list (including subdomain matching)."""
    domain_lower = domain.lower().lstrip("www.")
    if domain_lower in BENIGN_DOMAINS:
        return True
    parts = domain_lower.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in BENIGN_DOMAINS:
            return True
    return False


def _is_private_ip(ip: str) -> bool:
    """Return True if IP is private, loopback, or reserved."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast
    except ValueError:
        return True


def parse_url(url: str) -> Optional[Dict[str, Any]]:
    """Parse URL into components."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None

        domain = parsed.hostname
        ip = None
        if domain:
            # Check if hostname is actually an IP
            if is_valid_ip(domain):
                ip = domain
                domain = None

        port = parsed.port
        if port is None and parsed.scheme == "http":
            port = 80
        elif port is None and parsed.scheme == "https":
            port = 443

        query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}

        return {
            "protocol": parsed.scheme,
            "domain": domain,
            "ip": ip,
            "port": port,
            "path": parsed.path if parsed.path else "/",
            "query_params": query_params,
        }
    except Exception:
        logger.debug("Failed to parse URL: %s", url)
        return None


def calculate_c2_confidence(parsed: dict, source_context: str, ip_legitimacy: Optional[Dict] = None) -> float:
    """Calculate confidence score for a C2 record."""
    score = 0.5

    # Boost for valid URL structure
    if parsed["protocol"] in ("http", "https"):
        score += 0.2

    # Boost for public IP, private IP (VPN/proxy C2s), or real domain.
    # FIX: do not penalize private IPs — real C2 infrastructure frequently uses
    # them (e.g. Metasploit stagers behind VPNs).
    if parsed["ip"]:
        ip_class = classify_ip(parsed["ip"])
        if ip_class in ("public", "private", "vpn"):
            score += 0.25
        elif ip_class == "loopback":
            score -= 0.2

        # Incorporate IP legitimacy scoring
        if ip_legitimacy and ip_legitimacy.get("verdict") == "likely_malicious":
            score += 0.15
        elif ip_legitimacy and ip_legitimacy.get("verdict") == "uncertain":
            score += 0.05
    elif parsed["domain"]:
        # Only full boost for recognized real TLDs. Garbled/truncated URLs
        # (e.g. "www.icon", "www.google" without .com) get minimal boost.
        # Also require at least one dot — bare "in" or "%s" are not real domains.
        domain_parts = parsed["domain"].split(".")
        tld = domain_parts[-1].lower() if domain_parts else ""
        if "." in parsed["domain"] and tld in REAL_TLDS:
            score += 0.2
        elif "." in parsed["domain"] and len(tld) >= 2:
            score += 0.05  # partial — has TLD-like segment but not a recognized TLD

    # Boost for non-default path (suggests C2 endpoint)
    if parsed["path"] and parsed["path"] != "/":
        score += 0.15

    # Reduce confidence for known ad/analytics networks. These endpoints are
    # legitimate monetization infrastructure, but they commonly appear in
    # adware / grayware samples and should not be scored like malware C2s.
    if parsed["domain"] and is_ad_network(parsed["domain"]):
        score *= 0.5

    # Penalize template/format-string URLs (e.g. "https://%s/%s/%s").
    # These contain printf-style placeholders and are not real URLs.
    if parsed["domain"] and "%" in parsed["domain"]:
        score *= 0.5

    # Penalize URLs with no recognizable TLD (bare hostname, no dot).
    # These are often HTML fragments, localhost, or placeholder text.
    if parsed["domain"] and "." not in parsed["domain"]:
        score = min(score, 0.6)

    # Penalize malformed domains: empty TLD or trailing dot.
    # e.g. "www./div" has domain "www." with empty TLD.
    if parsed["domain"] and parsed["domain"].endswith("."):
        score = min(score, 0.6)

    # Single-character TLD: not a real domain, cap confidence.
    # e.g. "www.C//DTD" has tld "c".
    domain_parts = parsed["domain"].split(".") if parsed["domain"] else []
    if len(domain_parts) >= 1 and len(domain_parts[-1]) <= 1:
        score = min(score, 0.5)

    return round(min(1.0, max(0.0, score)), 4)


def enrich_with_circl(c2_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Optionally enrich C2 records with CIRCL pSSL/pDNS data.

    Returns the records unmodified if CIRCL is not configured or the
    enrichment fails. Enrichment is bounded by C2_ENRICHMENT_MAX_RECORDS and
    C2_ENRICHMENT_BUDGET_SECONDS so a slow/unreachable CIRCL service cannot
    stall the pipeline step.
    """
    if not CIRCL_AVAILABLE:
        return c2_records

    try:
        client = CIRCLClient()
    except CIRCLAuthError:
        # Credentials not configured; skip enrichment silently
        return c2_records

    # CIRCL client expects items with ip/domain/url/cert_sha1 keys
    enrichment_input = []
    for record in c2_records:
        enrichment_input.append({
            "ip": record.get("ip"),
            "domain": record.get("domain"),
            "url": record.get("raw_url"),
            "cert_sha1": record.get("cert_sha1"),
        })

    try:
        enriched = client.enrich_c2_infrastructure(
            enrichment_input,
            max_records=C2_ENRICHMENT_MAX_RECORDS,
            time_budget=C2_ENRICHMENT_BUDGET_SECONDS,
        )
    except CIRCLClientError:
        return c2_records

    # Merge CIRCL data back into original records
    for original, circl_data in zip(c2_records, enriched):
        original["circl"] = circl_data.get("circl", {})

    return c2_records


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------


def extract_c2_infrastructure(payloads_result: dict, strings_result: dict) -> dict:
    """
    Full Step 5: Extract C2 infrastructure from payloads and source strings.

    Args:
        payloads_result: Output dict from Step 4.
        strings_result: Output dict from Step 2.

    Returns:
        dict with C2 records.
    """
    sample_id = payloads_result["sample_id"]
    work_dir = settings.WORK_DIR / sample_id
    work_dir.mkdir(parents=True, exist_ok=True)

    c2_records = []
    c2_id = 0
    seen_urls = set()
    seen_domains = set()
    seen_ips = set()

    # Extract URLs from decoded payloads
    for payload in payloads_result.get("payloads", []):
        payload_id = payload.get("payload_id", "")
        source_location = payload.get("source_location", "unknown")

        for artifact in payload.get("artifacts", []):
            if artifact["type"] == "url":
                url = artifact["value"]
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                parsed = parse_url(url)
                if parsed is None or is_benign_url(url):
                    continue

                ip_legitimacy = None
                if parsed["ip"]:
                    ip_legitimacy = calculate_ip_legitimacy_score(
                        parsed["ip"], url, source_location
                    )

                confidence = calculate_c2_confidence(parsed, source_location, ip_legitimacy)
                record = {
                    "c2_id": f"c2_{c2_id:03d}",
                    "payload_id": payload_id,
                    "raw_url": url,
                    "protocol": parsed["protocol"],
                    "domain": parsed["domain"],
                    "ip": parsed["ip"],
                    "port": parsed["port"],
                    "path": parsed["path"],
                    "query_params": parsed["query_params"],
                    "ip_classification": classify_ip(parsed["ip"]) if parsed["ip"] else "n/a",
                    "communication_type": infer_communication_type(url, source_location),
                    "is_fallback": False,
                    "source_location": source_location,
                    "confidence": confidence,
                    "threat_category": "adware" if parsed["domain"] and is_ad_network(parsed["domain"]) else "malware",
                }
                if ip_legitimacy:
                    record["ip_legitimacy"] = ip_legitimacy
                c2_records.append(record)
                c2_id += 1

    # Also scan source strings directly for URLs not caught by payloads
    for category_name, items in strings_result.get("categories", {}).items():
        for item in items:
            value = item.get("value", "")
            if not isinstance(value, str):
                continue
            source_location = item.get("source", "unknown")

            # Pre-collect all URLs in this value to avoid double-counting
            # bare domains/IPs that appear inside an already-extracted URL.
            value_urls = set(URL_RE.findall(value))

            for url in value_urls:
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                parsed = parse_url(url)
                if parsed is None or is_benign_url(url):
                    continue
                if parsed["domain"] and _is_likely_junk_domain(parsed["domain"]):
                    continue

                ip_legitimacy = None
                if parsed["ip"]:
                    ip_legitimacy = calculate_ip_legitimacy_score(
                        parsed["ip"], url, source_location
                    )

                confidence = round(calculate_c2_confidence(parsed, source_location, ip_legitimacy), 4)
                record = {
                    "c2_id": f"c2_{c2_id:03d}",
                    "payload_id": None,
                    "raw_url": url,
                    "protocol": parsed["protocol"],
                    "domain": parsed["domain"],
                    "ip": parsed["ip"],
                    "port": parsed["port"],
                    "path": parsed["path"],
                    "query_params": parsed["query_params"],
                    "ip_classification": classify_ip(parsed["ip"]) if parsed["ip"] else "n/a",
                    "communication_type": infer_communication_type(url, source_location),
                    "is_fallback": False,
                    "source_location": source_location,
                    "confidence": confidence,
                    "threat_category": "adware" if parsed["domain"] and is_ad_network(parsed["domain"]) else "malware",
                }
                if ip_legitimacy:
                    record["ip_legitimacy"] = ip_legitimacy
                c2_records.append(record)
                c2_id += 1

            # Also scan for bare domains and IPs (no http:// prefix)
            for domain in DOMAIN_RE.findall(value):
                # Skip if this bare domain/IP is already part of an extracted URL
                if any(domain in extracted_url for extracted_url in value_urls):
                    continue
                # Filter out code package/class references (check original case first!)
                if _is_code_reference(domain):
                    continue
                # Filter out likely junk domains (file paths, single-word www, common words)
                if _is_likely_junk_domain(domain):
                    continue
                domain_lower = domain.lower()
                if domain_lower in seen_domains:
                    continue
                seen_domains.add(domain_lower)

                # Filter out known benign domains
                if _is_benign_domain(domain_lower):
                    continue

                confidence = round(calculate_c2_confidence(
                    {"domain": domain_lower, "ip": None, "protocol": "unknown", "port": None, "path": None, "query_params": None},
                    source_location, None
                ), 4)
                if confidence < C2_FALLBACK_CONFIDENCE_THRESHOLD:
                    continue

                record = {
                    "c2_id": f"c2_{c2_id:03d}",
                    "payload_id": None,
                    "raw_url": domain,
                    "protocol": "unknown",
                    "domain": domain_lower,
                    "ip": None,
                    "port": None,
                    "path": None,
                    "query_params": None,
                    "ip_classification": "n/a",
                    "communication_type": infer_communication_type(domain, source_location),
                    "is_fallback": True,
                    "source_location": source_location,
                    "confidence": confidence,
                    "threat_category": "adware" if is_ad_network(domain_lower) else "malware",
                }
                c2_records.append(record)
                c2_id += 1

            for ip_match in IP_RE.findall(value):
                if ip_match in seen_ips:
                    continue
                # Skip if this bare IP is already part of an extracted URL
                if any(ip_match in extracted_url for extracted_url in value_urls):
                    continue
                if _is_private_ip(ip_match):
                    continue
                seen_ips.add(ip_match)

                confidence = round(calculate_c2_confidence(
                    {"domain": None, "ip": ip_match, "protocol": "unknown", "port": None, "path": None, "query_params": None},
                    source_location, None
                ), 4)
                if confidence < C2_FALLBACK_CONFIDENCE_THRESHOLD:
                    continue

                record = {
                    "c2_id": f"c2_{c2_id:03d}",
                    "payload_id": None,
                    "raw_url": ip_match,
                    "protocol": "unknown",
                    "domain": None,
                    "ip": ip_match,
                    "port": None,
                    "path": None,
                    "query_params": None,
                    "ip_classification": classify_ip(ip_match),
                    "communication_type": infer_communication_type(ip_match, source_location),
                    "is_fallback": True,
                    "source_location": source_location,
                    "confidence": confidence,
                    "threat_category": "malware",
                }
                c2_records.append(record)
                c2_id += 1

    # Optional CIRCL enrichment (pSSL/pDNS) — never fail the pipeline
    c2_records = enrich_with_circl(c2_records)

    result = {
        "sample_id": sample_id,
        "total_c2s": len(c2_records),
        "c2_infrastructure": c2_records,
    }

    # Save intermediate result
    result_path = work_dir / "step5_c2s.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python step5_c2_extraction.py <step4_payloads.json> <step2_strings.json>")
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        payloads = json.load(f)
    with open(sys.argv[2], "r", encoding="utf-8") as f:
        strings = json.load(f)
    print(json.dumps(extract_c2_infrastructure(payloads, strings), indent=2))
