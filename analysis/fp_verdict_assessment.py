#!/usr/bin/env python3
"""
Cross-reference domain classification + temporal results with FP samples.
Produces per-FP verdicts:
- confirmed_fp: domain is ad network/legitimate, our engine is wrong
- gt_label_issue: domain is malicious/suspicious, GT label may be wrong
- documented_limitation: domain is shared infrastructure, can't separate
- inconclusive: insufficient data
"""
import json
import csv
from pathlib import Path
from collections import defaultdict

GAP_CACHE = Path("D:/DroidForensix/analysis/gap_features_cache.json")
RESULTS = Path("D:/DroidForensix/analysis/test_draft_signatures_results.json")
GROUND_TRUTH = Path("D:/DroidForensix/ground_truth_all.csv")
CLASSIFICATION = Path("D:/DroidForensix/analysis/c2_domain_classification.json")
TEMPORAL = Path("D:/DroidForensix/analysis/temporal_c2_results.json")
OUTPUT = Path("D:/DroidForensix/analysis/fp_verdicts.json")


def main():
    # Load all data
    with open(GAP_CACHE) as f:
        gap = json.load(f)
    with open(RESULTS) as f:
        results = json.load(f)
    gt = {}
    with open(GROUND_TRUTH) as f:
        for row in csv.DictReader(f):
            gt[row["sha256"].lower()] = row
    with open(CLASSIFICATION) as f:
        classifications = json.load(f)
    with open(TEMPORAL) as f:
        temporal = json.load(f)

    # Get FP samples
    fps = [s for s in results["samples"] if s["status"] == "fp"]

    verdicts = []
    summary = defaultdict(list)

    for fp in fps:
        sha = fp["sha256"]
        domains = gap.get(sha, {}).get("domains", [])
        gt_info = gt.get(sha, {})

        # Analyze each domain
        domain_verdicts = []
        for d in domains:
            cat = classifications.get("classifications", {}).get(d, {})
            temp = temporal.get(d, {})

            dv = {
                "domain": d,
                "category": cat.get("category", "unknown"),
                "temporal_verdict": temp.get("verdict", "UNKNOWN"),
                "dns_resolves": temp.get("dns", {}).get("resolves", None),
                "urlhaus_listed": temp.get("urlhaus", {}).get("listed", False),
                "vt_malicious": temp.get("virustotal", {}).get("malicious", 0),
            }
            domain_verdicts.append(dv)

        # Determine overall FP verdict
        if not domains:
            verdict = "no_domains"
            reasoning = "No C2 domains extracted; match is on strings/permissions only"
        else:
            categories = [dv["category"] for dv in domain_verdicts]
            temporal_verdicts = [dv["temporal_verdict"] for dv in domain_verdicts]

            # Check for malicious domains
            has_malicious = any(v == "MALICIOUS" for v in temporal_verdicts)
            has_suspicious = any(cat == "suspicious" for cat in categories)
            all_dead = all(v == "DEAD" for v in temporal_verdicts)
            all_ad_network = all(cat == "ad_network" for cat in categories)
            all_legitimate = all(cat == "legitimate" for cat in categories)

            if has_malicious:
                verdict = "gt_label_issue"
                reasoning = f"Domain confirmed malicious in URLhaus/VT; GT label may be wrong"
            elif has_suspicious and not all_dead:
                verdict = "gt_label_issue"
                reasoning = f"Suspicious domain pattern; GT label may be too generic"
            elif all_ad_network:
                verdict = "confirmed_fp"
                reasoning = f"All domains are ad networks; signature matched on ad SDK, not malware C2"
            elif all_legitimate:
                verdict = "confirmed_fp"
                reasoning = f"All domains are legitimate services; signature matched on benign infrastructure"
            elif all_dead:
                verdict = "documented_limitation"
                reasoning = f"All C2 domains are dead; can't verify intent"
            else:
                verdict = "inconclusive"
                reasoning = f"Mixed domain categories; needs further analysis"

        fp_verdict = {
            "sha256": sha,
            "gt_family": fp["gt_family"],
            "gt_source": gt_info.get("source", "?"),
            "predicted_family": fp["matched_family"],
            "confidence": fp["confidence"],
            "domains": domains,
            "domain_verdicts": domain_verdicts,
            "verdict": verdict,
            "reasoning": reasoning,
        }
        verdicts.append(fp_verdict)
        summary[verdict].append(sha)

    # Print summary
    print("FP VERDICT SUMMARY")
    print("=" * 60)
    for v in ["confirmed_fp", "gt_label_issue", "documented_limitation", "inconclusive", "no_domains"]:
        samples = summary.get(v, [])
        if samples:
            print(f"\n{v.upper()} ({len(samples)} samples):")
            for sha in samples[:10]:
                fv = next((x for x in verdicts if x["sha256"] == sha), None)
                if fv:
                    print(f"  {sha[:12]} gt={fv['gt_family']:15s} pred={fv['predicted_family']:12s} domains={fv['domains'][:2]}")
            if len(samples) > 10:
                print(f"  ... and {len(samples) - 10} more")

    # Detailed breakdown
    print("\n" + "=" * 60)
    print("RECOMMENDED ACTIONS:")
    print("=" * 60)

    confirmed = summary.get("confirmed_fp", [])
    if confirmed:
        print(f"\n1. CONFIRMED FALSE POSITIVES ({len(confirmed)}):")
        print("   These samples match on ad SDK or legitimate infrastructure.")
        print("   Action: Document as ad-network overlap limitation.")

    gt_issues = summary.get("gt_label_issue", [])
    if gt_issues:
        print(f"\n2. GT LABEL ISSUES ({len(gt_issues)}):")
        print("   These samples have malicious domains; GT label may be wrong.")
        print("   Action: Flag for GT label review.")

    limitations = summary.get("documented_limitation", [])
    if limitations:
        print(f"\n3. DOCUMENTED LIMITATIONS ({len(limitations)}):")
        print("   C2 domains are dead; can't verify intent.")
        print("   Action: Document as known limitation.")

    inconclusive = summary.get("inconclusive", [])
    if inconclusive:
        print(f"\n4. INCONCLUSIVE ({len(inconclusive)}):")
        print("   Mixed signals; needs dynamic analysis.")
        print("   Action: Keep as FP; note in documentation.")

    no_domains = summary.get("no_domains", [])
    if no_domains:
        print(f"\n5. NO DOMAINS ({len(no_domains)}):")
        print("   Match is on strings/permissions only.")
        print("   Action: Review string/permission discriminators.")

    # Save
    output = {
        "total_fps": len(fps),
        "verdicts": verdicts,
        "summary": {k: v for k, v in summary.items()},
        "counts": {k: len(v) for k, v in summary.items()},
    }
    with open(OUTPUT, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to {OUTPUT}")


if __name__ == "__main__":
    main()
