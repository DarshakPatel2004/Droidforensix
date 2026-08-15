#!/usr/bin/env python3
"""
Classify C2 domains from FP samples into categories:
- ad_network: known ad SDK domains
- legitimate: known services (Google, etc.)
- suspicious: potentially malicious
- unknown: needs further analysis

Uses DNS resolution + known domain patterns.
"""
import json
import csv
import re
import socket
from pathlib import Path
from collections import defaultdict

import dns.resolver

GAP_CACHE = Path("D:/DroidForensix/analysis/gap_features_cache.json")
RESULTS = Path("D:/DroidForensix/analysis/test_draft_signatures_results.json")
GROUND_TRUTH = Path("D:/DroidForensix/ground_truth_all.csv")
OUTPUT = Path("D:/DroidForensix/analysis/c2_domain_classification.json")

# Known ad network domain patterns (substring match)
AD_NETWORKS = {
    "domob.cn", "domob.com", "domob.mobi",
    "mobclix.com",
    "adsmogo.com", "adsmogo.mobi",
    "mydas.mobi", "mydas.cn",
    "youmi.net", "youmi.com",
    "vpon.com",
    "adwo.com",
    "adsage.com", "adsage.cn",
    "installs.com",
    "apperhand.com",
    "leadbolt.com", "leadbolt.net", "leadboltads.com",
    "airpush.com",
    "mopub.com",
    "inmobi.com",
    "chartboost.com",
    "startapp.com",
    "applovin.com",
    "unity3d.com",
    "facebook.com",
    "googleads", "googlesyndication",
    "doubleclick.net",
    "amazon-adsystem.com",
    "tapjoy.com",
    "millennialmedia.com",
    "jumptap.com",
    "smaato.net",
    "nexage.com",
    "hookmobile.com",
    "mobfox.com",
    "padsdel.com",
    "bounceim.com",
    "cdns.com",
}

# Known legitimate service patterns
LEGITIMATE = {
    "google.com", "google.cn", "googleapis.com", "gstatic.com",
    "gmail.com", "youtube.com",
    "umeng.com", "umeng.co",
    "91.com",
    "soso.com",
    "baidu.com",
    "tencent.com",
    "qq.com",
    "alibaba.com", "aliyun.com",
    "huawei.com",
    "xiaomi.com",
    "miui.com",
    "mixpanel.com",
    "firebase.io", "firebaseio.com",
    "crashlytics.com",
    "fabric.io",
    "appsflyer.com",
    "adjust.com",
    "branch.io",
    "amplitude.com",
    "segment.com",
}

# Known suspicious patterns (malware C2 infrastructure)
SUSPICIOUS_PATTERNS = [
    r"loseyourip\.com",  # NFC emulator
    r"go108\.",  # premium SMS
    r"icittys\.com",  # ad fraud
    r"guohead\.com",  # GinMaster C2
    r"phonego8\.com",  # premium SMS
    r"coolcode\.org",  # suspicious
    r"huanhaola\.com",  # suspicious
    r"ju6666\.com",  # suspicious
    r"sproutinc\.com",  # suspicious
    r"sellaring\.com",  # suspicious
    r"youdraw\.cn",  # suspicious
    r"droidsettings\.com",  # settings hijack
    r"forbes-droidsettings",  # settings hijack
]


def classify_domain(domain: str) -> dict:
    """Classify a single domain using pattern matching and DNS."""
    domain_lower = domain.lower().strip()

    # Check ad networks (substring match)
    for ad in AD_NETWORKS:
        if ad in domain_lower:
            return {"category": "ad_network", "matched_pattern": ad, "confidence": 0.9}

    # Check legitimate services (substring match)
    for legit in LEGITIMATE:
        if legit in domain_lower:
            return {"category": "legitimate", "matched_pattern": legit, "confidence": 0.9}

    # Check suspicious patterns (regex)
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, domain_lower):
            return {"category": "suspicious", "matched_pattern": pattern, "confidence": 0.8}

    # Check if it's a known TLD that's often used for legit services
    if domain_lower.endswith((".google.com", ".google.cn", ".gstatic.com")):
        return {"category": "legitimate", "matched_pattern": "google subdomain", "confidence": 0.95}

    # Check if it's an IP address or garbage
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain_lower):
        return {"category": "unknown", "matched_pattern": "IP address", "confidence": 0.5}

    # Check for garbage domains (non-URL patterns)
    garbage_patterns = [r"^app$", r"^ads$", r"^clk$", r"^;https$", r"^\{0\}$", r"^cloud-rpc-$"]
    for gp in garbage_patterns:
        if re.match(gp, domain_lower):
            return {"category": "garbage", "matched_pattern": "non-URL pattern", "confidence": 0.9}

    # Try DNS resolution
    try:
        answers = dns.resolver.resolve(domain_lower, "A", lifetime=5)
        ip = str(answers[0])
        # Check if it's a CDN/Cloudflare IP (often legit)
        return {"category": "unknown", "matched_pattern": None, "confidence": 0.3, "ip": ip, "dns_resolves": True}
    except dns.resolver.NXDOMAIN:
        return {"category": "unknown", "matched_pattern": "NXDOMAIN (dead)", "confidence": 0.6, "dns_resolves": False}
    except dns.resolver.NoAnswer:
        return {"category": "unknown", "matched_pattern": "no A record", "confidence": 0.4, "dns_resolves": False}
    except Exception as e:
        return {"category": "unknown", "matched_pattern": f"DNS error: {type(e).__name__}", "confidence": 0.3, "dns_resolves": False}


def main():
    # Load data
    with open(GAP_CACHE) as f:
        gap = json.load(f)
    with open(RESULTS) as f:
        results = json.load(f)
    gt = {}
    with open(GROUND_TRUTH) as f:
        for row in csv.DictReader(f):
            gt[row["sha256"].lower()] = row["family"]

    # Get FP samples
    fps = [s for s in results["samples"] if s["status"] == "fp"]

    # Collect all unique domains
    all_domains = set()
    domain_to_samples = defaultdict(list)
    for fp in fps:
        sha = fp["sha256"]
        domains = gap.get(sha, {}).get("domains", [])
        for d in domains:
            all_domains.add(d)
            domain_to_samples[d].append({
                "sha256": sha,
                "gt_family": fp["gt_family"],
                "predicted_family": fp["matched_family"],
            })

    print(f"Classifying {len(all_domains)} unique domains from {len(fps)} FP samples...")

    # Classify each domain
    classifications = {}
    for domain in sorted(all_domains):
        result = classify_domain(domain)
        classifications[domain] = {
            **result,
            "used_by_samples": domain_to_samples[domain],
        }

    # Summary
    cats = defaultdict(int)
    for d, c in classifications.items():
        cats[c["category"]] += 1

    print("\nClassification summary:")
    for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"  {cat:15s}: {count}")

    # Show samples by category
    print("\nFP samples by domain category:")
    sample_categories = defaultdict(list)
    for fp in fps:
        sha = fp["sha256"]
        domains = gap.get(sha, {}).get("domains", [])
        categories = set()
        for d in domains:
            cat = classifications.get(d, {}).get("category", "unknown")
            categories.add(cat)
        # Use the most "specific" category
        if "suspicious" in categories:
            sample_categories["suspicious"].append(fp)
        elif "unknown" in categories:
            sample_categories["unknown"].append(fp)
        elif "ad_network" in categories:
            sample_categories["ad_network"].append(fp)
        elif "legitimate" in categories:
            sample_categories["legitimate"].append(fp)
        elif "garbage" in categories:
            sample_categories["garbage"].append(fp)
        else:
            sample_categories["no_domains"].append(fp)

    for cat in ["ad_network", "legitimate", "suspicious", "unknown", "garbage", "no_domains"]:
        samples = sample_categories.get(cat, [])
        if samples:
            print(f"\n  {cat} ({len(samples)} samples):")
            for s in samples[:5]:
                print(f"    {s['sha256'][:12]} gt={s['gt_family']:15s} pred={s['matched_family']}")
            if len(samples) > 5:
                print(f"    ... and {len(samples) - 5} more")

    # Save
    output = {
        "total_domains": len(all_domains),
        "total_fp_samples": len(fps),
        "classifications": {k: {kk: vv for kk, vv in v.items() if kk != "used_by_samples"} for k, v in classifications.items()},
        "summary": dict(cats),
        "sample_categories": {k: [s["sha256"] for s in v] for k, v in sample_categories.items()},
    }
    with open(OUTPUT, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to {OUTPUT}")


if __name__ == "__main__":
    main()
