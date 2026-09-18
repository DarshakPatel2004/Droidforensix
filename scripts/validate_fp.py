"""
False Positive Validation Script for DroidForensix C2 Indicators.

Scans pipeline results, presents C2 indicators for manual classification,
persists results, and generates FP summary reports.
"""

import argparse
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "1.0"
ANALYSIS_WORK = Path("analysis/work")
RESULTS_PATH = Path("evaluation/fp_validation_results.json")

COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"

IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

PRIVATE_IP_PATTERNS = [
    re.compile(r"^10\..*"),
    re.compile(r"^192\.168\..*"),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\..*"),
    re.compile(r"^127\..*"),
    re.compile(r"^169\.254\..*"),
]

KNOWN_BENIGN_PATTERNS = [
    re.compile(r"(.*\.)?googleapis\.com", re.IGNORECASE),
    re.compile(r"(.*\.)?gstatic\.com", re.IGNORECASE),
    re.compile(r"(.*\.)?googleadservices\.com", re.IGNORECASE),
    re.compile(r"(.*\.)?googlesyndication\.com", re.IGNORECASE),
    re.compile(r"(.*\.)?doubleclick\.net", re.IGNORECASE),
    re.compile(r"(.*\.)?facebook\.com", re.IGNORECASE),
    re.compile(r"(.*\.)?fbcdn\.net", re.IGNORECASE),
    re.compile(r"(.*\.)?amazonaws\.com", re.IGNORECASE),
    re.compile(r"(.*\.)?cloudfront\.net", re.IGNORECASE),
    re.compile(r"(.*\.)?azure\.com", re.IGNORECASE),
    re.compile(r"(.*\.)?windows\.net", re.IGNORECASE),
    re.compile(r"(.*\.)?trafficmanager\.net", re.IGNORECASE),
    re.compile(r"(.*\.)?akamaihd\.net", re.IGNORECASE),
    re.compile(r"(.*\.)?akamaiedge\.net", re.IGNORECASE),
    re.compile(r"(.*\.)?cloudflare\.com", re.IGNORECASE),
    re.compile(r"(.*\.)?fastly\.net", re.IGNORECASE),
    re.compile(r"(.*\.)?bootstrapcdn\.com", re.IGNORECASE),
    re.compile(r"(.*\.)?cdnjs\.cloudflare\.com", re.IGNORECASE),
    re.compile(r"(.*\.)?stackpathcdn\.com", re.IGNORECASE),
    re.compile(r"(.*\.)?jquery\.com", re.IGNORECASE),
]

KNOWN_SDK_DOMAINS = [
    "googleadservices.com",
    "doubleclick.net",
    "google-analytics.com",
    "googlesyndication.com",
    "googleapis.com",
    "gstatic.com",
    "google.com",
    "googleusercontent.com",
    "googlevideo.com",
    "googletagmanager.com",
    "googletagservices.com",
    "googleoptimize.com",
    "googlecommerce.com",
    "2mdn.net",
    "app-measurement.com",
    "firebaseio.com",
    "crashlytics.com",
    "fabric.io",
    "admob.com",
    "facebook.com",
    "graph.facebook.com",
    "facebook.net",
    "fbcdn.net",
    "messenger.com",
    "instagram.com",
    "whatsapp.com",
    "amazonaws.com",
    "cloudfront.net",
    "amazon.com",
    "amazon-adsystem.com",
    "akamai.net",
    "akamaihd.net",
    "akamaiedge.net",
    "akamaitechnologies.com",
    "fastly.net",
    "cloudflare.com",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "bootstrapcdn.com",
    "stackpathcdn.com",
    "maxcdn.com",
    "keycdn.com",
    "edgekey.net",
    "edgesuite.net",
    "azure.com",
    "windows.net",
    "trafficmanager.net",
    "microsoft.com",
    "live.com",
    "office.com",
    "office365.com",
    "onedrive.com",
    "sharepoint.com",
    "outlook.com",
    "bing.com",
    "aspnetcdn.com",
    "visualstudio.com",
    "github.com",
    "githubusercontent.com",
    "bitbucket.org",
    "gitlab.com",
    "sourceforge.net",
    "nuget.org",
    "pypi.org",
    "npmjs.com",
    "rubygems.org",
    "maven.org",
    "gradle.org",
    "jfrog.io",
    "flurry.com",
    "mixpanel.com",
    "amplitude.com",
    "segment.io",
    "hotjar.com",
    "optimizely.com",
    "fullstory.com",
    "appdynamics.com",
    "newrelic.com",
    "datadoghq.com",
    "sentry.io",
    "rollbar.com",
    "bugsnag.com",
    "loggly.com",
    "sumologic.com",
    "pubmatic.com",
    "openx.net",
    "rubiconproject.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    "twitter.com",
    "twimg.com",
    "linkedin.com",
    "pinterest.com",
    "reddit.com",
    "tiktok.com",
    "youtube.com",
    "ytimg.com",
    "jquery.com",
    "w3.org",
    "whatwg.org",
    "mozilla.org",
    "apache.org",
    "python.org",
    "nodejs.org",
    "stripe.com",
    "paypal.com",
    "braintreepayments.com",
    "salesforce.com",
    "zendesk.com",
    "adobe.com",
    "ibm.com",
]


def color(text, code):
    return f"{code}{text}{COLOR_RESET}"


def classify_color(label):
    if label == "malicious":
        return color(label, COLOR_GREEN)
    if label == "benign":
        return color(label, COLOR_RED)
    if label == "uncertain":
        return color(label, COLOR_YELLOW)
    return label


def indicator_type(value):
    if IP_RE.match(value):
        return "ip"
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    if "." in value:
        return "domain"
    return "unknown"


def is_private_ip(ip):
    for pat in PRIVATE_IP_PATTERNS:
        if pat.match(ip):
            return True
    return False


def auto_classify(indicator, itype):
    if itype == "ip":
        if is_private_ip(indicator):
            return "benign", "private_ip_range"
        return None, None

    if itype in ("domain", "url"):
        target = indicator.lower().strip()
        if target.startswith("http://"):
            target = target[7:].split("/")[0].split(":")[0]
        elif target.startswith("https://"):
            target = target[8:].split("/")[0].split(":")[0]

        for known in KNOWN_SDK_DOMAINS:
            if target == known or target.endswith("." + known):
                return "benign", known

        for pat in KNOWN_BENIGN_PATTERNS:
            if pat.match(target) or pat.match(indicator):
                return "benign", pat.pattern

    return None, None


def find_pipeline_results(work_dir):
    return sorted(Path(work_dir).rglob("pipeline_result.json"))


def load_pipeline(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def extract_indicators(data):
    sample_id = data.get("sample_id", "unknown")
    family = "unknown"
    fi = data.get("family_identification")
    if fi and isinstance(fi, dict):
        family = fi.get("family", "unknown")

    threat_chains = data.get("threat_chains", [])
    chain_contexts = {}
    if isinstance(threat_chains, list):
        for tc in threat_chains:
            steps = tc.get("steps", [])
            context_parts = []
            for step in steps:
                atype = step.get("type", "")
                artifact = step.get("artifact", "")
                if artifact:
                    context_parts.append(f"{atype}: {artifact[:120]}")
            if context_parts:
                chain_contexts[tc.get("chain_id", "?")] = " | ".join(
                    context_parts
                )

    indicators = []
    c2_list = data.get("c2_infrastructure", [])
    if not isinstance(c2_list, list):
        c2_list = []

    for c2 in c2_list:
        indicator = (
            c2.get("domain")
            or c2.get("ip")
            or c2.get("raw_url")
            or ""
        )
        if not indicator:
            continue
        itype = indicator_type(indicator)
        confidence = c2.get("confidence", 0.0) or 0.0
        source = c2.get("source_location", "unknown")
        comm_type = c2.get("communication_type", "unknown")
        threat_category = c2.get("threat_category", "unknown")

        # Gather threat chain references linking to this indicator
        chain_refs = []
        for chain_id, ctx in chain_contexts.items():
            if indicator in ctx or (
                c2.get("raw_url") and c2["raw_url"] in ctx
            ):
                chain_refs.append({"chain_id": chain_id, "context": ctx})

        indicators.append(
            {
                "indicator": indicator,
                "type": itype,
                "sample_id": sample_id,
                "family": family,
                "confidence": round(confidence, 4),
                "source": source,
                "communication_type": comm_type,
                "threat_category": threat_category,
                "raw_url": c2.get("raw_url", ""),
                "protocol": c2.get("protocol", ""),
                "port": c2.get("port"),
                "chain_contexts": chain_refs[:3] if chain_refs else [],
            }
        )
    return indicators


def load_existing_results(path):
    if not path.exists():
        return {}, []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}, []
    results = data.get("results", [])
    by_indicator = {}
    for r in results:
        key = (r.get("indicator", ""), r.get("sample_id", ""))
        by_indicator[key] = r
    return by_indicator, results


def save_results(path, results):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def display_indicator(ctx, idx, total):
    print()
    print(color(f"{'='*70}", COLOR_CYAN))
    print(
        color(
            f"Indicator {idx}/{total} — {ctx['sample_id'][:16]}...",
            COLOR_BOLD + COLOR_CYAN,
        )
    )
    print(color(f"{'='*70}", COLOR_CYAN))
    print(f"  {color('Indicator:', COLOR_BOLD)}   {ctx['indicator']}")
    print(f"  {color('Type:', COLOR_BOLD)}       {ctx['type']}")
    print(
        f"  {color('Confidence:', COLOR_BOLD)}  {ctx['confidence']}"
    )
    print(f"  {color('Source:', COLOR_BOLD)}     {ctx['source']}")
    print(f"  {color('Family:', COLOR_BOLD)}     {ctx['family']}")
    print(
        f"  {color('Comm Type:', COLOR_BOLD)}  {ctx['communication_type']}"
    )
    print(
        f"  {color('Category:', COLOR_BOLD)}   {ctx['threat_category']}"
    )
    if ctx["chain_contexts"]:
        print(f"  {color('Threat Chains:', COLOR_BOLD)}")
        for cc in ctx["chain_contexts"]:
            print(f"    [{cc['chain_id']}] {cc['context'][:150]}")


def prompt_classification():
    while True:
        print()
        print(
            "  "
            + color("(M)", COLOR_GREEN)
            + "alicious  "
            + color("(B)", COLOR_RED)
            + "enign  "
            + color("(U)", COLOR_YELLOW)
            + "ncertain  "
            + "(S)kip  "
            + "(Q)uit"
        )
        try:
            choice = input("  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return "QUIT"
        if choice in ("m", "malicious"):
            return "malicious"
        if choice in ("b", "benign"):
            return "benign"
        if choice in ("u", "uncertain"):
            return "uncertain"
        if choice in ("s", "skip"):
            return "skip"
        if choice in ("q", "quit"):
            return "QUIT"
        print("  Invalid choice. Enter M, B, U, S, or Q.")


def interactive_classify(
    all_indicators, existing_map, results,
    auto_enabled=False, batch_mode=False, by_band=False,
):
    to_classify = []
    for ctx in all_indicators:
        key = (ctx["indicator"], ctx["sample_id"])
        if key not in existing_map:
            to_classify.append(ctx)

    print(
        f"\n{color('Found', COLOR_BOLD)} {len(all_indicators)} total indicators"
        f" ({len(results)} already classified, {len(to_classify)} new)\n"
    )

    if not to_classify:
        print(color("All indicators already classified.", COLOR_YELLOW))
        return results, 0, Counter()

    auto_count = 0
    benign_matches = Counter()

    if by_band:
        bands = [
            (">= 0.8", lambda c: c.get("confidence", 0) >= 0.8),
            ("0.6 - 0.8", lambda c: 0.6 <= c.get("confidence", 0) < 0.8),
            ("< 0.6", lambda c: c.get("confidence", 0) < 0.6),
        ]
        ordered = []
        for label, pred in bands:
            group = [c for c in to_classify if pred(c)]
            if group:
                ordered.append((label, group))
    else:
        ordered = [(None, to_classify)]

    overall_idx = 0
    for band_label, group in ordered:
        if band_label and not batch_mode:
            print(
                color(
                    f"\n  --- Confidence Band: {band_label} ---",
                    COLOR_BOLD + COLOR_CYAN,
                )
            )
        for ctx in group:
            overall_idx += 1

            if auto_enabled or batch_mode:
                auto_result, matched = auto_classify(
                    ctx["indicator"], ctx["type"]
                )
                if auto_result is not None:
                    auto_count += 1
                    if matched:
                        benign_matches[matched] += 1
                    record = {
                        "indicator": ctx["indicator"],
                        "type": ctx["type"],
                        "sample_id": ctx["sample_id"],
                        "family": ctx["family"],
                        "confidence": ctx["confidence"],
                        "source": ctx["source"],
                        "user_classification": auto_result,
                        "classification_source": "auto",
                        "matched_pattern": matched,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    results.append(record)
                    save_results(RESULTS_PATH, results)
                    if not batch_mode:
                        print(
                            f"  [{overall_idx}/{len(to_classify)}] "
                            f"Auto-classified {ctx['indicator'][:60]} "
                            f"as {classify_color(auto_result)}"
                            + (f" ({matched})" if matched else "")
                        )
                    continue
                elif batch_mode:
                    record = {
                        "indicator": ctx["indicator"],
                        "type": ctx["type"],
                        "sample_id": ctx["sample_id"],
                        "family": ctx["family"],
                        "confidence": ctx["confidence"],
                        "source": ctx["source"],
                        "user_classification": "uncertain",
                        "classification_source": "auto",
                        "matched_pattern": None,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    results.append(record)
                    save_results(RESULTS_PATH, results)
                    if overall_idx % 50 == 0:
                        print(
                            f"  Batch progress: {overall_idx}/{len(to_classify)} "
                            f"processed ({auto_count} auto-classified)"
                        )
                    continue

            if not batch_mode:
                display_indicator(ctx, overall_idx, len(to_classify))
                decision = prompt_classification()
                if decision == "QUIT":
                    return results, auto_count, benign_matches
                record = {
                    "indicator": ctx["indicator"],
                    "type": ctx["type"],
                    "sample_id": ctx["sample_id"],
                    "family": ctx["family"],
                    "confidence": ctx["confidence"],
                    "source": ctx["source"],
                    "user_classification": decision,
                    "classification_source": "manual",
                    "matched_pattern": None,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                if decision != "skip":
                    results.append(record)
                save_results(RESULTS_PATH, results)
                print(
                    f"  {color('Saved.', COLOR_CYAN)}"
                    + (
                        f" ({classify_color(decision)})"
                        if decision != "skip"
                        else " (skipped)"
                    )
                )

    return results, auto_count, benign_matches


def compute_fp_rate(classifications):
    total = len(classifications)
    if total == 0:
        return 0.0, 0, 0, 0
    malicious = sum(
        1 for c in classifications if c.get("user_classification") == "malicious"
    )
    benign = sum(
        1 for c in classifications if c.get("user_classification") == "benign"
    )
    uncertain = sum(
        1 for c in classifications if c.get("user_classification") == "uncertain"
    )
    denominator = malicious + benign
    fp_rate = (benign / denominator * 100) if denominator > 0 else 0.0
    return fp_rate, malicious, benign, uncertain


def generate_report(results, prev_fp_rate=None, auto_stats=None):
    print()
    print(color("=" * 60, COLOR_CYAN))
    print(
        color(
            "   FALSE POSITIVE VALIDATION REPORT",
            COLOR_BOLD + COLOR_CYAN,
        )
    )
    print(color("=" * 60, COLOR_CYAN))

    if not results:
        print(color("\n  No classifications found.", COLOR_YELLOW))
        return

    total = len(results)
    fp_rate, malicious, benign, uncertain = compute_fp_rate(results)

    auto_count = (auto_stats or {}).get("count", 0)
    benign_matches = (auto_stats or {}).get("matches", Counter())

    print(f"\n  {color('Summary', COLOR_BOLD)}")
    print(f"  {'Total classified:':<28} {total}")
    print(
        f"  {'Malicious (genuine C2):':<28} {malicious}"
    )
    print(f"  {'Benign (FP):':<28} {benign}")
    print(f"  {'Uncertain:':<28} {uncertain}")
    print(
        f"  {'Overall FP rate:':<28} {fp_rate:.1f}%"
    )

    # Auto-classification stats
    if auto_count > 0:
        print(
            f"\n  {color('Auto-Classification', COLOR_BOLD)}"
        )
        print(
            f"  {'Auto-classified as benign:':<28} {auto_count}"
        )
        print(
            f"  {'(based on known patterns)':<28}"
        )
        uncertain_auto = sum(
            1 for r in results
            if r.get("classification_source") == "auto"
            and r.get("user_classification") == "uncertain"
        )
        if uncertain_auto > 0:
            print(
                f"  {'Auto-classified as uncertain:':<28} {uncertain_auto}"
            )

    # Known benign pattern matches
    if benign_matches:
        print(
            f"\n  {color('Known Benign Pattern Matches', COLOR_BOLD)}"
        )
        for pattern, count in benign_matches.most_common(15):
            print(f"  {pattern:<50} {count}×")

    # Trend analysis
    if prev_fp_rate is not None:
        delta = fp_rate - prev_fp_rate
        print(f"\n  {color('Trend Analysis', COLOR_BOLD)}")
        print(
            f"  {'Previous session FP rate:':<28} {prev_fp_rate:.1f}%"
        )
        print(
            f"  {'Current FP rate:':<28} {fp_rate:.1f}%"
        )
        print(
            f"  {'Change:':<28} "
            f"{'+' if delta >= 0 else ''}{delta:.1f}%"
            + (" (worsened)" if delta > 0 else "")
            + (" (improved)" if delta < 0 else "")
            + (" (unchanged)" if delta == 0 else "")
        )

    # By confidence band
    print(f"\n  {color('FP Rate by Confidence Band', COLOR_BOLD)}")
    bands = [
        (">= 0.8", lambda c: c.get("confidence", 0) >= 0.8),
        (
            "0.6 - 0.8",
            lambda c: 0.6 <= c.get("confidence", 0) < 0.8,
        ),
        ("< 0.6", lambda c: c.get("confidence", 0) < 0.6),
    ]
    for label, pred in bands:
        subset = [c for c in results if pred(c)]
        if subset:
            rate, m, b, u = compute_fp_rate(subset)
            print(
                f"  {label:<28} {rate:.1f}%  "
                f"({b} benign / {m + b} classified)"
            )
        else:
            print(f"  {label:<28} N/A")

    # By family
    print(f"\n  {color('FP Rate by Malware Family', COLOR_BOLD)}")
    families = {}
    for c in results:
        f = c.get("family", "unknown")
        families.setdefault(f, []).append(c)
    for fname, flist in sorted(
        families.items(), key=lambda x: len(x[1]), reverse=True
    ):
        rate, m, b, u = compute_fp_rate(flist)
        print(
            f"  {fname:<28} {rate:.1f}%  "
            f"({len(flist)} indicators, {b} benign)"
        )

    # Top 10 benign indicators
    print(f"\n  {color('Top 10 Benign Indicators', COLOR_BOLD)}")
    benign_indicators = [
        c["indicator"]
        for c in results
        if c.get("user_classification") == "benign"
    ]
    if benign_indicators:
        for i, (ind, cnt) in enumerate(
            Counter(benign_indicators).most_common(10), 1
        ):
            print(f"  {i:>2}. {ind:<50} {cnt}×")
    else:
        print("  (none)")

    # Sample-level breakdown
    print(
        f"\n  {color('Samples with Most False Positives', COLOR_BOLD)}"
    )
    sample_fps = Counter(
        c.get("sample_id", "unknown")
        for c in results
        if c.get("user_classification") == "benign"
    )
    if sample_fps:
        for i, (sid, cnt) in enumerate(
            sample_fps.most_common(10), 1
        ):
            print(f"  {i:>2}. {sid[:50]:<52} {cnt} FP indicators")
    else:
        print("  (none)")

    # Pie chart (text)
    print(f"\n  {color('Classification Distribution', COLOR_BOLD)}")
    bar_max = 40
    counts = [
        ("Malicious", malicious, COLOR_GREEN),
        ("Benign", benign, COLOR_RED),
        ("Uncertain", uncertain, COLOR_YELLOW),
    ]
    max_count = max((c[1] for c in counts), default=1)
    for label, count, col in counts:
        bar_len = int(count / max_count * bar_max) if max_count else 0
        bar = color("#" * bar_len, col)
        pct = (count / total * 100) if total else 0
        print(f"  {label:<12} {count:>6} ({pct:5.1f}%) {bar}")

    print()


def quick_stats(results_path):
    _, results = load_existing_results(results_path)
    total_found = sum(
        1 for f in find_pipeline_results(ANALYSIS_WORK)
        if load_pipeline(f).get("c2_infrastructure")
    )
    print(
        f"Indicators classified: {len(results)} across {total_found} samples"
    )
    if results:
        fp_rate, mal, ben, unc = compute_fp_rate(results)
        print(f"FP rate: {fp_rate:.1f}% ({ben} benign / {mal + ben} classified)")
    else:
        print("No classifications yet.")


def main():
    parser = argparse.ArgumentParser(
        description="Validate C2 indicators from pipeline results for false positive analysis."
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate summary report from existing classifications",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from last session (skip already-classified indicators)",
    )
    parser.add_argument(
        "--quick-stats",
        action="store_true",
        help="Quick summary without interaction",
    )
    parser.add_argument(
        "--auto-classify",
        action="store_true",
        help="Auto-classify known benign indicators; only prompt for uncertain ones",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Non-interactive batch mode: auto-classify all indicators, no prompts",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Minimum confidence threshold (default: 0.0)",
    )
    parser.add_argument(
        "--max-confidence",
        type=float,
        default=1.0,
        help="Maximum confidence threshold (default: 1.0)",
    )
    parser.add_argument(
        "--by-band",
        action="store_true",
        help="Group indicators by confidence band before classification",
    )
    args = parser.parse_args()

    if args.quick_stats:
        quick_stats(RESULTS_PATH)
        return

    existing_map, results = load_existing_results(RESULTS_PATH)

    prev_fp_rate = None
    if results:
        prev_fp_rate, _, _, _ = compute_fp_rate(results)

    if args.report:
        generate_report(results, prev_fp_rate=prev_fp_rate)
        return

    pipeline_files = find_pipeline_results(ANALYSIS_WORK)
    total_files = len(pipeline_files)
    print(
        f"\nScanning {total_files} pipeline result files in {ANALYSIS_WORK}..."
    )

    all_indicators = []
    samples_with_c2 = 0
    for i, pf in enumerate(pipeline_files, 1):
        data = load_pipeline(pf)
        indicators = extract_indicators(data)
        if indicators:
            samples_with_c2 += 1
            all_indicators.extend(indicators)
        if i % 50 == 0 or i == total_files:
            print(
                f"  Progress: {i}/{total_files} files, "
                f"{samples_with_c2} with C2, "
                f"{len(all_indicators)} indicators extracted"
            )

    print(
        f"\n{color('Done scanning.', COLOR_CYAN)} "
        f"{samples_with_c2} samples with C2, "
        f"{len(all_indicators)} total indicators"
    )

    if not all_indicators:
        print(color("No C2 indicators found in any sample.", COLOR_YELLOW))
        return

    # Apply confidence filter
    min_conf = args.min_confidence
    max_conf = args.max_confidence
    if min_conf > 0.0 or max_conf < 1.0:
        before = len(all_indicators)
        all_indicators = [
            i for i in all_indicators
            if min_conf <= i.get("confidence", 0) <= max_conf
        ]
        print(
            f"{color('Confidence filter:', COLOR_CYAN)} "
            f"{before} -> {len(all_indicators)} indicators "
            f"(min={min_conf}, max={max_conf})"
        )

    if not all_indicators:
        print(color("No indicators match confidence criteria.", COLOR_YELLOW))
        return

    if args.batch:
        results, auto_count, benign_matches = interactive_classify(
            all_indicators, existing_map, results,
            auto_enabled=True, batch_mode=True, by_band=args.by_band,
        )
        auto_stats = {"count": auto_count, "matches": benign_matches}
        print(
            f"\n{color('Batch complete.', COLOR_CYAN)} "
            f"{auto_count} auto-classified as benign, "
            f"{sum(1 for r in results if r.get('classification_source') == 'auto' and r.get('user_classification') == 'uncertain')} uncertain"
        )
        save_results(RESULTS_PATH, results)
        generate_report(results, prev_fp_rate=prev_fp_rate, auto_stats=auto_stats)
        return

    results, auto_count, benign_matches = interactive_classify(
        all_indicators, existing_map, results,
        auto_enabled=args.auto_classify, batch_mode=False,
        by_band=args.by_band,
    )
    auto_stats = {"count": auto_count, "matches": benign_matches}
    generate_report(results, prev_fp_rate=prev_fp_rate, auto_stats=auto_stats)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(
            color(
                "\n\nInterrupted. Progress saved to "
                f"{RESULTS_PATH}",
                COLOR_YELLOW,
            )
        )
        sys.exit(1)
