#!/usr/bin/env python3
"""Abusee.ch ground-truth label audit for the family-identification chapter.

Isolates abusech-sourced rows from the corrected ground truth, classifies each
label as catch-all or specific (using analysis.labels.is_catch_all), merges
campaign-cluster relabel proposals from reports/label_review_queue.csv, and
writes an audit CSV plus a prioritized 20-sample manual-review queue.

Optional --vt mode queries VirusTotal per queued sha256 and records the most
frequent plausible (non-catch-all) AV family label as a relabel candidate.

Usage:
    python scripts/audit_abusech_labels.py                 # offline audit
    python scripts/audit_abusech_labels.py --vt            # + VT candidates for queue
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Importing analysis.labels is stdlib-only (module docstring guarantees it).
from analysis.labels import is_catch_all  # noqa: E402

GT_PATH = PROJECT_ROOT / "ground_truth_all_corrected.csv"
REVIEW_QUEUE_PATH = PROJECT_ROOT / "reports" / "label_review_queue.csv"
AUDIT_OUT = PROJECT_ROOT / "reports" / "abusech_label_audit.csv"
QUEUE_OUT = PROJECT_ROOT / "reports" / "abusech_review_queue.csv"
VT_OUT = PROJECT_ROOT / "reports" / "abusech_vt_candidates.csv"
VT_CACHE = PROJECT_ROOT / "reports" / ".vt_abusech_cache.json"

REVIEW_LIMIT = 20
VT_BASE = "https://www.virustotal.com/api/v3/files/{sha}"

# AV engines that reliably emit a family/lineage label rather than generics.
VT_ENGINE_WINDOW = 15


def load_ground_truth() -> list[dict]:
    with GT_PATH.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def load_review_queue() -> dict[str, dict]:
    proposals: dict[str, dict] = {}
    if not REVIEW_QUEUE_PATH.exists():
        return proposals
    with REVIEW_QUEUE_PATH.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            sha = (row.get("sha") or "").strip().lower()
            if sha:
                proposals[sha] = {
                    "proposed": row.get("proposed", ""),
                    "campaign_size": row.get("campaign_size", ""),
                    "shared_c2": row.get("shared_c2", ""),
                    "shared_certs": row.get("shared_certs", ""),
                }
    return proposals


def classify_labels(rows: list[dict]) -> tuple[int, int, Counter, Counter]:
    catch_all_labels: Counter = Counter()
    specific_labels: Counter = Counter()
    n_catch_all = 0
    n_specific = 0
    for r in rows:
        fam = r["family"]
        (catch_all_labels if is_catch_all(fam) else specific_labels)[fam] += 1
        if is_catch_all(fam):
            n_catch_all += 1
        else:
            n_specific += 1
    return n_catch_all, n_specific, catch_all_labels, specific_labels


def extract_vt_family(vt_json: dict) -> str:
    results = (vt_json.get("data", {}).get("attributes", {})
               .get("last_analysis_results", {}))
    votes: Counter = Counter()
    for engine, r in results.items():
        label = (r or {}).get("result", "")
        if not label:
            continue
        if is_catch_all(label):
            continue
        votes[label] += 1
    if not votes:
        return ""
    best_label, _ = votes.most_common(1)[0]
    return best_label


def cache_vt(sha: str, result: dict) -> None:
    cache = {}
    if VT_CACHE.exists():
        try:
            cache = json.loads(VT_CACHE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            cache = {}
    cache[sha] = result
    VT_CACHE.write_text(json.dumps(cache, indent=1), encoding="utf-8")


def load_vt_cache() -> dict:
    if VT_CACHE.exists():
        try:
            return json.loads(VT_CACHE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def run_vt(rows: list[dict]) -> list[dict]:
    import time

    import requests
    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / ".env")
    import os

    key = os.environ.get("VT_KEY", "")
    if not key:
        print("[vt] VT_KEY not set -- skipping VT relabel", file=sys.stderr)
        return rows

    cache = load_vt_cache()
    headers = {"x-apikey": key}
    for row in rows:
        sha = row["sha256"]
        if sha in cache:
            row["vt_top_family"] = cache[sha]
            continue
        try:
            resp = requests.get(VT_BASE.format(sha=sha), headers=headers, timeout=40)
            if resp.status_code != 200:
                print(f"[vt] {sha[:12]} HTTP {resp.status_code}", file=sys.stderr)
                cache[sha] = ""
                continue
            fam = extract_vt_family(resp.json())
            cache[sha] = fam
            row["vt_top_family"] = fam
            print(f"[vt] {sha[:12]} -> {fam or '(no specific label)'}")
        except Exception as exc:  # network errors must not abort the audit
            print(f"[vt] {sha[:12]} error: {exc}", file=sys.stderr)
            cache[sha] = ""
        time.sleep(1.2)
        if (hash(sha) % 5) == 0:
            time.sleep(3)  # spread load for free-quota tiers
    VT_CACHE.write_text(json.dumps(cache, indent=1), encoding="utf-8")
    return rows


# VT labels that are still vendor-generic even with a fingerprint suffix.
_GENERIC_MARKERS = (
    "generickd.", "generic.325", "generic",
    "evo-gen", "troj_frs", "frs.", "not-virus", "not-a-virus",
    "pua.", "riskware.", "sarspy", "mobtes", "smsreg",
)
# Substring → project-canonical family (specific evidence, GT side).
_SPECIFIC_TOKENS = {
    "bankbot": "BankBot",
    "hqwar": "Hqwar",
    "beatbanker": "BeatBanker",
    "mirax": "Mirax",
    "spymax": "SpyMax",
    "smsgate": "SmsSend",
    "ngate": "NGate",
    "fakeinst": "FakeInst",
    "mspy": "MSpy",
    "kinfos": "Kinfos",
}


def normalize_vt_family(label: str) -> str:
    """Map a VT label to a project-canonical family, or '' if still generic."""
    if not label:
        return ""
    if is_catch_all(label):
        return ""
    key = label.lower()
    if any(g in key for g in _GENERIC_MARKERS):
        return ""
    from analysis.labels import VENDOR_ALIASES
    for alias_from, alias_to in VENDOR_ALIASES.items():
        if alias_from.lower() in key:
            return alias_to
    for token, fam in _SPECIFIC_TOKENS.items():
        if token in key:
            return fam
    cleaned = re.sub(r"^(android:?|androidos\.?|trojan[-.:]?|heur:?|trj[_.]|troj[_.])", "", label, flags=re.I)
    cleaned = re.sub(r"\.[a-z!c]+$", "", cleaned.strip())
    return cleaned.strip(" .:;") or ""


RELABEL_SOURCES = ("campaign", "vt", "conflict", "none")


def resolve_relabel(row: dict, vt_cache: dict) -> tuple[str, str, str]:
    """Return (new_family, source, note).  Conflict => '' family for reviewer."""
    camp = (row.get("campaign_proposal") or "").strip()
    vt_fam = normalize_vt_family(vt_cache.get(row["sha256"], ""))
    camp_specific = bool(camp and not is_catch_all(camp))
    conflict = bool(camp_specific and vt_fam and camp.lower() != vt_fam.lower())
    if conflict:
        return "", "conflict", f"campaign={camp} vs vt={vt_fam or '(none)'}"
    if camp_specific:
        return camp, "campaign", "campaign_clustering (shared cert/C2)"
    if vt_fam:
        return vt_fam, "vt", "virustotal_second_opinion"
    return "", "none", "verified_generic"


def build_patch(rows: list[dict]) -> None:
    cache = load_vt_cache()
    patch_path = PROJECT_ROOT / "reports" / "abusech_relabel_patch.csv"
    reviewed = [r for r in rows if r["sha256"] in cache or r.get("campaign_proposal")]
    with patch_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["sha256", "old_family", "new_family", "source", "note"])
        for r in sorted(reviewed, key=lambda x: x["sha256"]):
            new_fam, source, note = resolve_relabel(r, cache)
            if new_fam == "" and source not in ("conflict",):
                continue  # verified generic: leave GT untouched
            w.writerow([r["sha256"], r["family"], new_fam, source, note])
    print(f"Relabel patch -> {patch_path}  ({sum(1 for r in reviewed if resolve_relabel(r, load_vt_cache())[1] in ('campaign','vt','conflict'))} actionable rows)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vt", action="store_true", help="query VirusTotal for queue candidates")
    parser.add_argument("--patch", action="store_true", help="emit relabel patch from cached VT + campaign proposals")
    args = parser.parse_args()

    rows = [r for r in load_ground_truth() if (r.get("source") or "").strip().lower() == "abusech"]
    if not rows:
        print("No abusech rows found in ground truth", file=sys.stderr)
        raise SystemExit(1)

    proposals = load_review_queue()
    for r in rows:
        p = proposals.get(r["sha256"].strip().lower())
        r["campaign_proposal"] = (p or {}).get("proposed", "")
        r["campaign_size"] = (p or {}).get("campaign_size", "")
        r["shared_c2"] = (p or {}).get("shared_c2", "")
        r["shared_certs"] = (p or {}).get("shared_certs", "")

    n_catch_all, n_specific, catch_all_labels, specific_labels = classify_labels(rows)

    with AUDIT_OUT.open("w", newline="", encoding="utf-8") as fh:
        cols = ["sha256", "family", "is_catch_all", "confidence", "vt_detections",
                "gt_reason", "campaign_proposal", "campaign_size", "shared_c2", "shared_certs"]
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in sorted(rows, key=lambda x: x["sha256"]):
            w.writerow({**r, "is_catch_all": int(is_catch_all(r["family"]))})

    # Queue: catch-alls without a campaign proposal first (manual review priority),
    # then catch-alls with a proposal.  Sort by vt_detections desc, then confidence.
    rows_reviewable = [r for r in rows if is_catch_all(r["family"])]
    rows_reviewable.sort(
        key=lambda r: (
            int(r.get("campaign_proposal") != ""),
            int(r["vt_detections"] or 0),
            (r.get("confidence") or "low"),
        ),
        reverse=True,
    )
    queue = rows_reviewable[:REVIEW_LIMIT]

    if args.vt:
        queue = run_vt(queue)

    if args.patch:
        build_patch(rows)

    with QUEUE_OUT.open("w", newline="", encoding="utf-8") as fh:
        cols = ["sha256", "family", "vt_detections", "confidence", "campaign_proposal", "vt_top_family"]
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in queue:
            w.writerow(r)

    print(f"abusech rows: {len(rows)}  |  catch-all labels: {n_catch_all} ({n_catch_all/len(rows):.1%})  |  specific: {n_specific}")
    print("Top catch-all labels:", ", ".join(f"{k}={v}" for k, v in catch_all_labels.most_common(8)))
    print("Top specific labels:", ", ".join(f"{k}={v}" for k, v in specific_labels.most_common(8)))
    print(f"Campaign-cluster proposals available for {sum(1 for r in rows if r['campaign_proposal'])}/{len(rows)} rows")
    print(f"Queue ({len(queue)}): {QUEUE_OUT}")
    print(f"Audit: {AUDIT_OUT}")


if __name__ == "__main__":
    main()