"""Option C Phase 1: Extract cert issuer/subject for all 359 APKs and profile by GT family.

For each GT family with ≥3 samples, measures:
  - top_issuer: the most common issuer string
  - top_issuer_coverage: fraction of samples sharing that issuer
  - stability: HIGH (≥70%), MEDIUM (40-70%), LOW (<40%)

Outputs analysis/cert_profiles.json.

Run: python analysis/cert_profiles.py
"""

import csv
import json
import logging
import sys
from collections import Counter, defaultdict
from pathlib import Path

logging.disable(logging.DEBUG)
logging.getLogger("androguard").setLevel(logging.ERROR)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

GT_PATH  = ROOT / "ground_truth_all.csv"
OUT_PATH = ROOT / "analysis" / "cert_profiles.json"

HIGH_THRESHOLD   = 0.70
MEDIUM_THRESHOLD = 0.40
MIN_SAMPLES      = 2   # include families with ≥2 samples for completeness


def extract_cert_issuer(apk_path: str) -> str | None:
    """Return the signing cert issuer string, or None on failure.

    Uses androguard's APK() zip/manifest reader only — no DEX parsing.
    AnalyzeAPK would build the full Dalvik cross-reference graph per sample
    (20-90s each); the signing cert is read from META-INF/*.RSA and needs
    none of that. This path takes milliseconds per APK.
    """
    try:
        from androguard.core.apk import APK
        a = APK(apk_path)
        certs = a.get_certificates()
        if certs:
            return certs[0].issuer.human_friendly
    except Exception:
        pass
    return None


def stability(coverage: float) -> str:
    if coverage >= HIGH_THRESHOLD:
        return "HIGH"
    if coverage >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def main() -> None:
    rows = list(csv.DictReader(open(GT_PATH, encoding="utf-8")))
    by_family: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_family[row["family"]].append(row)

    total = len(rows)
    print(f"Extracting certs from {total} APKs across {len(by_family)} families...")

    results: dict[str, dict] = {}
    for idx, row in enumerate(rows, 1):
        sha = row["sha256"].lower()
        apk = row["apk_path"]
        fam = row["family"]
        issuer = extract_cert_issuer(apk)
        if sha not in results:
            results[sha] = {"family": fam, "issuer": issuer}
        if idx % 50 == 0 or idx == total:
            done = sum(1 for v in results.values() if v["issuer"])
            print(f"  {idx}/{total}  extracted={done}")

    # Build per-family profiles
    issuer_by_family: dict[str, list[str]] = defaultdict(list)
    for sha, info in results.items():
        if info["issuer"]:
            issuer_by_family[info["family"]].append(info["issuer"])

    profiles: dict[str, dict] = {}
    for fam, family_rows in sorted(by_family.items()):
        n = len(family_rows)
        if n < MIN_SAMPLES:
            continue
        issuers = issuer_by_family.get(fam, [])
        if not issuers:
            profiles[fam] = {
                "sample_count": n, "cert_extracted": 0,
                "top_issuer": None, "top_issuer_coverage": 0.0,
                "issuer_patterns": [], "stability": "UNKNOWN",
            }
            continue
        counter = Counter(issuers)
        top_issuer, top_count = counter.most_common(1)[0]
        coverage = top_count / n
        profiles[fam] = {
            "sample_count": n,
            "cert_extracted": len(issuers),
            "top_issuer": top_issuer,
            "top_issuer_coverage": round(coverage, 3),
            "issuer_patterns": sorted(counter.keys()),
            "stability": stability(coverage),
        }

    # Sort by coverage descending for easy review
    ranked = sorted(
        profiles.items(),
        key=lambda x: x[1]["top_issuer_coverage"],
        reverse=True,
    )

    print("\n=== CERT PROFILE RESULTS ===")
    print(f"{'Family':<20} {'n':>4}  {'stab':<8}  {'cov':>6}  top_issuer")
    for fam, p in ranked:
        stab = p["stability"]
        cov  = p["top_issuer_coverage"]
        top  = (p["top_issuer"] or "none")[:60]
        print(f"  {fam:<18} {p['sample_count']:>4}  {stab:<8}  {cov:>6.3f}  {top}")

    high = [(f, p) for f, p in ranked if p["stability"] == "HIGH"]
    print(f"\nHIGH-stability families ({len(high)}): {[f for f, _ in high]}")
    print(f"Useful for cert-based boosting: {len(high)} / {len(profiles)} families")

    output = {
        "summary": {
            "total_apks": total,
            "families_profiled": len(profiles),
            "high_stability": len(high),
            "thresholds": {"high": HIGH_THRESHOLD, "medium": MEDIUM_THRESHOLD},
        },
        "profiles": {fam: p for fam, p in ranked},
    }
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nWritten to {OUT_PATH}")


if __name__ == "__main__":
    main()
