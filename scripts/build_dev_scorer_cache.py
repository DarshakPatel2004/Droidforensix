"""Build a dev-only FamilyConfidenceScorer cache without holdout access.

The scorer needs static strings/domains for a row. The historical gap-feature
cache covers most, but not all, dev rows. This utility fills missing entries
from completed validation pipeline results while filtering the membership
before opening any per-sample artifact.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.family_confidence_scorer import SampleSignals
from analysis.labels import is_catch_all

DEFAULT_GT = ROOT / "ground_truth_all.csv"
DEFAULT_SPLIT = ROOT / "evaluation" / "holdout_split_v1.csv"
DEFAULT_PIPELINE_DIR = ROOT / "evaluation" / "validation_359"
DEFAULT_BASE_CACHE = ROOT / "analysis" / "gap_features_cache.json"
DEFAULT_OUTPUT = ROOT / "evaluation" / "validation_359" / "dev_scorer_cache.json"
DEFAULT_REPORT = ROOT / "evaluation" / "validation_359" / "dev_scorer_cache_report.json"


def load_membership(path: Path) -> dict[str, str]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return {
            row["sha256"].lower(): row["split"]
            for row in csv.DictReader(handle)
        }


def load_cache(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {sha.lower(): entry for sha, entry in data.items() if sha}


def usable(entry: dict[str, Any]) -> bool:
    return bool(
        not entry.get("parse_error") and (entry.get("strings") or entry.get("domains"))
    )


def pipeline_entry(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    result = json.loads(path.read_text(encoding="utf-8"))
    sample = SampleSignals.from_pipeline_result(result)
    entry = {
        "permissions": sample.permissions,
        "strings": sample.strings,
        "class_count": sample.class_count,
        "native_libs": sample.native_libs,
        "domains": sample.domains,
        "source": "dev_pipeline_result",
    }
    return entry if usable(entry) else None


def build_cache(
    ground_truth: Path,
    split_file: Path,
    pipeline_dir: Path,
    base_cache: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    with ground_truth.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    membership = load_membership(split_file)
    base = load_cache(base_cache)
    dev_scorable = {
        row["sha256"].lower()
        for row in rows
        if membership.get(row["sha256"].lower()) == "dev"
        and not is_catch_all(row.get("family", ""))
    }

    output: dict[str, dict[str, Any]] = {}
    filled = 0
    missing: list[str] = []
    for sha in sorted(dev_scorable):
        if sha in base and usable(base[sha]):
            output[sha] = base[sha]
            continue
        entry = pipeline_entry(pipeline_dir / sha / "pipeline_result.json")
        if entry is None:
            missing.append(sha)
            continue
        output[sha] = entry
        filled += 1

    report = {
        "dev_scorable_rows": len(dev_scorable),
        "cache_rows": len(output),
        "filled_from_dev_pipeline": filled,
        "missing_after_fill": len(missing),
        "missing_sha256": missing,
        "split": "dev",
        "source": "ground_truth_all.csv + evaluation/holdout_split_v1.csv",
    }
    return output, report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GT)
    parser.add_argument("--split-file", type=Path, default=DEFAULT_SPLIT)
    parser.add_argument("--pipeline-dir", type=Path, default=DEFAULT_PIPELINE_DIR)
    parser.add_argument("--base-cache", type=Path, default=DEFAULT_BASE_CACHE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    cache, report = build_cache(
        args.ground_truth,
        args.split_file,
        args.pipeline_dir,
        args.base_cache,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(
        f"dev scorable={report['dev_scorable_rows']} "
        f"cache={report['cache_rows']} filled={report['filled_from_dev_pipeline']} "
        f"missing={report['missing_after_fill']}"
    )
    print(f"Cache: {args.output}")
    print(f"Report: {args.report}")


if __name__ == "__main__":
    main()
