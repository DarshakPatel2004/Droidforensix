"""Campaign graph over a malware corpus + purity vs ground truth.

Usage: python scripts/measure_campaign_purity.py <gt_csv> <out.json>

Resumable: per-APK features are cached in the output JSON by sha256, so a
re-run only extracts new samples before rebuilding the graph.
"""

import glob
import json
import logging
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logging.disable(logging.CRITICAL)
try:
    from loguru import logger as _loguru

    _loguru.remove()
except Exception:
    pass

from analysis.campaign_clustering import (
    FEATURE_VERSION,
    build_campaign_graph,
    campaign_evidence,
    detect_campaigns,
    extract_sample_features,
    load_ground_truth,
    strict_tier_summary,
    summarize,
)


def resolve_apk_path(sha: str, hint: str) -> Optional[str]:
    """GT apk_path if it exists, else a samples/ file carrying the sha."""
    if hint and os.path.exists(hint):
        return hint
    matches = glob.glob(f"samples/*/*{sha}*.apk") + glob.glob(f"samples/*/*/*{sha}*.apk")
    return matches[0] if matches else None


def main() -> None:
    gt_csv, out_path = sys.argv[1], sys.argv[2]
    out_file = Path(out_path)
    cached: dict = {}
    if out_file.exists():
        try:
            cached = json.loads(out_file.read_text(encoding="utf-8")).get("features_by_sha", {})
        except Exception:
            cached = {}

    gt = load_ground_truth(gt_csv)
    print(f"GT malware samples: {len(gt)}; cached features: {len(cached)}", flush=True)

    import csv

    hints = {}
    with open(gt_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("is_malware") == "yes":
                hints[(row.get("sha256") or "").strip().lower()] = row.get("apk_path", "")

    features = []
    started = time.time()
    for _index, (sha, _) in enumerate(gt.items()):
        hit = cached.get(sha)
        if hit and hit.get("feature_version") == FEATURE_VERSION:
            features.append(hit)
            continue
        apk_path = resolve_apk_path(sha, hints.get(sha, ""))
        if not apk_path:
            record = {"sample_id": sha, "apk_path": "", "error": "apk not found"}
            cached[sha] = record
            features.append(record)
            continue
        try:
            record = extract_sample_features(apk_path)
            record["sample_id"] = sha  # join key is the GT sha
        except Exception as exc:
            record = {
                "sample_id": sha,
                "apk_path": apk_path,
                "error": f"{type(exc).__name__}: {exc}",
                "trace": traceback.format_exc()[-300:],
            }
        cached[sha] = record
        features.append(record)
        if len(cached) % 25 == 0:
            out_file.write_text(json.dumps({"features_by_sha": cached}, indent=1), encoding="utf-8")
            print(
                f"  extracted {len(cached)}/{len(gt)} "
                f"({time.time() - started:.0f}s)",
                flush=True,
            )

    graph = build_campaign_graph([f for f in features if f.get("sample_id")])
    campaigns = detect_campaigns(graph)
    report = {
        "summary": summarize(features, graph, campaigns, gt),
        "strict_tier": strict_tier_summary(
            [f for f in features if f.get("sample_id")], gt
        ),
        "campaigns": campaign_evidence(campaigns, features)[:50],
        "features_by_sha": cached,
    }
    out_file.write_text(json.dumps(report, indent=1), encoding="utf-8")
    summary = report["summary"]
    print(f"nodes={summary['nodes']} edges={summary['edges']} failed={summary['failed']}")
    for key in ("purity_all", "purity_high_conf"):
        block = summary[key]
        print(
            f"{key}: purity={block['purity']} "
            f"non_singleton={block['non_singleton_purity']} "
            f"coverage={block['coverage']} labeled={block['labeled_samples']} "
            f"multi={block['multi_sample_campaigns']}/{block['total_campaigns']}"
        )
    strict = report["strict_tier"]
    print(
        f"strict_tier(w>={strict['min_edge_weight']}): "
        f"purity={strict['purity_all']['purity']} "
        f"nonsingle={strict['purity_all']['non_singleton_purity']} "
        f"cov={strict['purity_all']['coverage']} "
        f"edges={strict['edges']}"
    )


if __name__ == "__main__":
    main()
