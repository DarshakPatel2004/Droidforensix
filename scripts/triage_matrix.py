#!/usr/bin/env python3
"""Regenerate the FULL_KNOWLEDGE_TRANSFER section 15 triage matrix.

Usage:
    .venv/Scripts/python.exe scripts/triage_matrix.py
    .venv/Scripts/python.exe scripts/triage_matrix.py --limit 3   # smoke

Writes analysis/ac4/triage_matrix.json (gitignored). Sample set matches
the doc's 100 goodware / 32 malware counts:

  goodware: samples/goodware/benign_eval/*.apk              (100)
  malware:  data/triage_locklist_m0.csv buckets gt_packed_suspect (6)
            + gt_malware_unpacked (4) + reserve_realworld (4)  (14)
            + ground_truth_all.csv source=pendrive            (18)
            RTO.apk (packed_custom_positive) is the AC1 calibration
            positive and stays excluded.

Kali paths (/home/kali/DroidForensix/...) remap to the repo root; missing
files and triage errors are recorded in the JSON, never silently dropped.
Delta vs the doc's numbers is reported honestly - inputs are never tuned
to make the claim reproduce.
"""

import argparse
import csv
import json
import pathlib
import sys
from collections import Counter
from datetime import datetime, timezone

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.triage import (ALLOWLIST_PATH, MARKERS_PATH, expected_flag,
                            load_json, triage_apk)

KALI_PREFIX = "/home/kali/DroidForensix/"
LOCKLIST_MALWARE_BUCKETS = ("gt_packed_suspect", "gt_malware_unpacked",
                            "reserve_realworld")
OUT_PATH = REPO / "analysis" / "ac4" / "triage_matrix.json"

# docs/FULL_KNOWLEDGE_TRANSFER.md section 15 (2026-08-28): the claim this
# script exists to reproduce. Mismatches are surfaced, never tuned away.
DOC_CLAIM = {
    "goodware": {"total": 100, "clean": 95, "brand_or_allowlisted": 5,
                 "suspect": 0, "fp": 0},
    "malware": {"total": 32, "clean_unpacked": 13, "flagged": 19,
                "suspect": 4, "fn": 0},
}


def resolve_path(raw):
    """Kali absolute -> repo-relative; Windows absolute -> as-is;
    relative (pendrive rows) -> repo join."""
    normalized = raw.replace("\\", "/")
    if normalized.startswith(KALI_PREFIX):
        return REPO / normalized[len(KALI_PREFIX):]
    path = pathlib.Path(raw)
    if path.is_absolute():
        return path
    return REPO / raw


def classify(verdict):
    """Map a triage verdict to a section-15 matrix column."""
    if "suspect:dropper-shape" in verdict:
        return "suspect"
    if verdict.startswith("packed_known"):
        return "brand_matched"
    if verdict.startswith(("packed_custom", "obfuscated_native")):
        return "allowlisted" if "allowlisted-benign" in verdict else "flagged"
    if verdict.startswith("indeterminate"):
        return "allowlisted" if "allowlisted-benign" in verdict \
            else "indeterminate"
    if verdict.startswith("clean_static"):
        return "allowlisted" if "allowlisted-benign" in verdict else "clean"
    return "unexpected"


def _rel(path):
    try:
        return str(path.relative_to(REPO))
    except ValueError:
        return str(path)


def _console(text):
    """Progress output must never crash a batch run: cp1252 consoles
    cannot encode some pendrive sample names (sample 130/132 killed a
    full run before the JSON was written). JSON keeps the raw names."""
    return str(text).encode("ascii", "replace").decode("ascii")


def collect_samples(limit=None):
    """{source_key: [sample dict]}; limit applies per source (smoke runs)."""
    def cap(items):
        return items[:limit] if limit else items

    goodware = [{"path": p, "source": "goodware", "bucket": "known_clean",
                 "expected": "", "csv_sha256": ""}
                for p in sorted((REPO / "samples/goodware/benign_eval")
                                .glob("*.apk"))]

    locklist = []
    with open(REPO / "data" / "triage_locklist_m0.csv", newline="",
              encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row["bucket"] in LOCKLIST_MALWARE_BUCKETS:
                locklist.append({
                    "path": resolve_path(row["path"]),
                    "source": "locklist",
                    "bucket": row["bucket"],
                    "expected": row["expected"],
                    "csv_sha256": row["sha256"],
                })

    pendrive = []
    with open(REPO / "ground_truth_all.csv", newline="",
              encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row["source"] == "pendrive":
                pendrive.append({
                    "path": resolve_path(row["apk_path"]),
                    "source": "pendrive",
                    "bucket": "pendrive_" + row["family"],
                    "expected": "",  # pendrive GT rows carry no expect_flag
                    "csv_sha256": row["sha256"],
                })

    return {"goodware": cap(goodware), "locklist": cap(locklist),
            "pendrive": cap(pendrive)}


def run_matrix(args):
    markers = load_json(MARKERS_PATH)
    allowlist = load_json(ALLOWLIST_PATH)
    sources = collect_samples(args.limit or None)
    rows, missing, errors = [], [], []
    total = sum(len(v) for v in sources.values())
    index = 0
    for source_key, samples in sources.items():
        for sample in samples:
            index += 1
            if not sample["path"].exists():
                missing.append({"source": source_key,
                                "path": str(sample["path"]),
                                "csv_sha256": sample["csv_sha256"]})
                print("[missing] %s" % _console(sample["path"]),
                      file=sys.stderr)
                continue
            try:
                report = triage_apk(sample["path"], markers, allowlist)
            except Exception as exc:
                errors.append({"source": source_key,
                               "path": str(sample["path"]),
                               "error": "%s: %s" % (type(exc).__name__, exc)})
                print("[error] %s: %s" % (_console(sample["path"].name),
                                          _console(exc)),
                      file=sys.stderr)
                continue
            rows.append({
                "source": source_key,
                "bucket": sample["bucket"],
                "expected": sample["expected"],
                "sha256": report["apk_sha256"],
                "path": _rel(sample["path"]),
                "verdict": report["verdict"],
                "verdict_class": classify(report["verdict"]),
                "confidence": report["confidence"],
                "suspect_reasons": report["suspect_reasons"],
                "encrypted_assets_skipped":
                    report["heuristics"]["H2"].get("encrypted_skipped", 0),
                "dex_encrypted":
                    report["heuristics"]["H3"].get("reason") == "dex_encrypted",
                "h_hits": [hid for hid, res in report["heuristics"].items()
                           if res.get("hit")],
                "duration_seconds": report["duration_seconds"],
            })
            print("[%d/%d] %-34s conf=%.2f %5.1fs  %s" % (
                index, total, report["verdict"], report["confidence"],
                report["duration_seconds"], _console(sample["path"].name)))

    goodware = [r for r in rows if r["source"] == "goodware"]
    malware = [r for r in rows if r["source"] != "goodware"]
    gw = dict(Counter(r["verdict_class"] for r in goodware))
    mw = dict(Counter(r["verdict_class"] for r in malware))

    # Doc column semantics: goodware FP = anything not clean/brand/
    # allowlisted; malware "clean (unpacked)" = not flagged and not
    # suspect; malware "flagged" = packing detected (triage's job per
    # the doc's semantics note).
    gw_fp = (gw.get("flagged", 0) + gw.get("indeterminate", 0)
             + gw.get("suspect", 0))
    mw_nonflagged = mw.get("clean", 0) + mw.get("indeterminate", 0)
    mw_flagged = (mw.get("flagged", 0) + mw.get("brand_matched", 0)
                  + mw.get("allowlisted", 0))
    expected_rows = [r for r in malware
                     if expected_flag(r["bucket"], r["expected"])]
    mw_fn = sum(1 for r in expected_rows
                if r["verdict_class"] not in ("flagged", "brand_matched",
                                              "allowlisted"))

    computed = {
        "goodware": {"total": len(goodware), "clean": gw.get("clean", 0),
                     "brand_or_allowlisted": gw.get("brand_matched", 0)
                     + gw.get("allowlisted", 0),
                     "suspect": gw.get("suspect", 0), "fp": gw_fp},
        "malware": {"total": len(malware), "clean_unpacked": mw_nonflagged,
                    "flagged": mw_flagged, "suspect": mw.get("suspect", 0),
                    "fn": mw_fn},
    }
    delta = {side: {key: computed[side][key] - DOC_CLAIM[side][key]
                    for key in DOC_CLAIM[side]}
             for side in ("goodware", "malware")}
    reproduced = all(v == 0 for side in delta.values() for v in side.values())

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(
            timespec="seconds"),
        "generator": "scripts/triage_matrix.py",
        "doc_claim": {
            "source": "docs/FULL_KNOWLEDGE_TRANSFER.md section 15 "
                      "(2026-08-28)",
            "table": DOC_CLAIM,
        },
        "sample_set": {
            "requested": {k: len(v) for k, v in sources.items()},
            "triaged": len(rows),
            "missing": missing,
            "errors": errors,
        },
        "goodware": {"classes": gw, "computed": computed["goodware"]},
        "malware": {"classes": mw, "computed": computed["malware"],
                    "fn_scope": "locklist expect_* rows only; pendrive GT "
                                "rows carry no expect_flag - adjudicate via "
                                "rows[]"},
        "delta_vs_doc": delta,
        "doc_claim_reproduced": reproduced,
        "rows": rows,
    }
    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2))

    print("\n=== FULL_KT section 15 matrix (recomputed) ===")
    print("goodware: %d triaged | clean %d | brand+allowlisted %d | "
          "indeterminate %d | suspect %d | FP %d"
          % (computed["goodware"]["total"], gw.get("clean", 0),
             computed["goodware"]["brand_or_allowlisted"],
             gw.get("indeterminate", 0), gw.get("suspect", 0), gw_fp))
    print("malware:  %d triaged | non-flagged %d | flagged %d | suspect %d "
          "| FN(locked expect_*) %d"
          % (computed["malware"]["total"], mw_nonflagged, mw_flagged,
             computed["malware"]["suspect"], mw_fn))
    print("missing=%d errors=%d" % (len(missing), len(errors)))
    print("delta vs doc (computed - claimed): %s" % json.dumps(delta))
    print("doc claim reproduced: %s" % ("YES" if reproduced else "NO"))
    print("json -> %s" % out_path)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Regenerate the FULL_KT section 15 triage matrix.")
    parser.add_argument("--out", default=str(OUT_PATH),
                        help="output JSON path (default: %(default)s)")
    parser.add_argument("--limit", type=int, default=0,
                        help="max samples per source for smoke runs")
    args = parser.parse_args(argv)
    return run_matrix(args)


if __name__ == "__main__":
    sys.exit(main())
