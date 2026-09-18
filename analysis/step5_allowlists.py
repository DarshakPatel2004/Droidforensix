"""
Tier 3 Allowlist: Legitimate infrastructure that should not be scored as C2.
Populated from FP analysis (evaluation/c2_analysis/fp_domains.csv) + known OAuth/CDN/library docs.
See analysis/step5_c2_extraction.py for usage.
"""

# OAuth / SaaS identity providers - legitimate API endpoints often embedded in apps
OAUTH_DOMAINS = {
    # Google / Firebase
    "accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com",
    "firebaseio.com", "firebaseapp.com", "firebasestorage.googleapis.com",
    # Facebook
    "graph.facebook.com", "connect.facebook.net", "www.facebook.com",
    # Snapchat (the FP case)
    "accounts.snapchat.com", "app.snapchat.com", "snapchat.com",
    # Twitter/X
    "api.twitter.com", "accounts.twitter.com", "t.co",
    # Apple / Microsoft / Spotify
    "appleid.apple.com", "login.microsoftonline.com", "accounts.spotify.com",
    "accounts.microsoft.com", "graph.microsoft.com",
    # GitHub
    "github.com", "api.github.com",
}

# CDN / cloud providers - legitimate hosting
CDN_PROVIDERS = {
    # Cloudflare
    "cloudflare.com", "cloudflare.net",
    # AWS
    "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "cloudfront.amazonaws.com",
    # GCP
    "googleapis.com", "storage.googleapis.com", "appspot.com",
    # Azure
    "azureedge.net", "blob.core.windows.net", "azure.com",
    # Akamai / Fastly / CDN
    "akamai.net", "akamaihd.net", "akamaiedge.net", "fastly.net", "fastly-edge.com",
    "cloudfront.net", "jsdelivr.net", "cdn.jsdelivr.net",
    # Map / tile CDNs observed in FP
    "openstreetmap.org", "overlay.openstreetmap.nl", "basemap.nationalmap.gov",
    "openhab.org", "tile.openstreetmap.org",
}

# Library documentation / developer portals - never C2
LIBRARY_DOCS = {
    # From FP top 20
    "logback.qos.ch", "www.qos.ch", "qos.ch",
    "jabber.org", "www.jabber.org",
    "tasks.org", "www.tasks.org",
    "ankiweb.net", "docs.ankiweb.net", "docs.ankidroid.org", "ankidroid.org",
    "wms.chartbundle.com", "chartbundle.com",
    "bandcamp.com", "www.bandcamp.com",
    "ccil.org", "www.ccil.org",
    "soundcloud.com", "api-v2.soundcloud.com",
    "gmail.com", "www.gmail.com",
    "newpipe.net", "www.newpipe.net",
    "media.ccc.de", "ccc.de",
    "json.schemastore.org", "schemastore.org",
    "ktor.io", "www.ktor.io",
    "eightbitwonders.gitlab.io", "gitlab.io",
    # General docs
    "maven.org", "repo.maven.apache.org", "docs.gradle.org", "gradle.org",
    "square.github.io", "kotlinlang.org", "developer.android.com",
    "w3.org", "www.w3.org", "schemas.android.com",
    "feederapp.nononsenseapps.com", "nononsenseapps.com",
    # Round 2 FP (retest 446: top benign C2 domains, all library/docs/donation/tiles)
    "link.adtidy.org", "adtidy.org",
    "liberapay.com", "www.liberapay.com",
    "www.aelf.org", "aelf.org",
    "linphone.org", "www.linphone.org",
    "a.tile.opentopomap.org", "b.tile.opentopomap.org", "c.tile.opentopomap.org",
    "opentopomap.org",
    "opencollective.com", "www.opencollective.com",
    "auroraoss.com", "www.auroraoss.com",
    "json-schema.org", "www.json-schema.org",
    "codedead.com", "www.codedead.com",
    "addismaptransit.com", "www.addismaptransit.com",
    "addy.io", "www.addy.io",
    "opds-spec.org", "www.opds-spec.org",
    "dropbox.com", "www.dropbox.com",
}

# Union for quick check
TIER3_ALLOWLIST = OAUTH_DOMAINS | CDN_PROVIDERS | LIBRARY_DOCS

# Also include all BENIGN_DOMAINS from step5 as Tier 3 (568 entries) - import at runtime to avoid circular
def is_tier3(domain: str) -> bool:
    """Check if domain is Tier 3 legitimate infrastructure."""
    if not domain:
        return False
    d = domain.lower().lstrip("www.")
    if d in TIER3_ALLOWLIST:
        return True
    # Subdomain match: e.g. api.ktor.io -> ktor.io
    parts = d.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in TIER3_ALLOWLIST:
            return True
    # Also check against step5 BENIGN_DOMAINS (568) at runtime
    try:
        from analysis.step5_c2_extraction import BENIGN_DOMAINS
        if d in BENIGN_DOMAINS:
            return True
        for i in range(len(parts)):
            if ".".join(parts[i:]) in BENIGN_DOMAINS:
                return True
    except Exception:
        pass
    return False
