"""Mine family-specific discriminators for the 33 outcompeted samples.

For each outcompeted family (GT family beaten by a wrong family in the current
signature engine), compare its feature set against:
  1. The beater family's features   — what the target family has that the beater
                                      does NOT (candidate discriminators)
  2. The full 359-sample corpus     — prune candidates that appear in >5% of
                                      non-target samples (FP risk check)

Outputs analysis/discriminators_36.json with per-family discriminator candidates
and a commit_ready flag when FP risk < 5%.

Run: python analysis/mine_discriminators.py
"""

import collections
import csv
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RESULTS_PATH  = ROOT / "analysis" / "test_draft_signatures_results.json"
CACHE_PATH    = ROOT / "analysis" / "gap_features_cache.json"
GT_PATH       = ROOT / "ground_truth_all.csv"
OUT_PATH      = ROOT / "analysis" / "discriminators_36.json"

# A candidate string must appear in this fraction of the target family's
# samples to be considered a family signal.
TARGET_COVERAGE_MIN = 0.5

# A candidate must appear in fewer than this fraction of ALL non-target
# samples to be considered low-FP-risk (the 5% threshold).
CORPUS_FP_MAX = 0.05

# Minimum string length — skip pure whitespace / single-char tokens.
STRING_MIN_LEN = 4


def load_ground_truth(path: Path) -> dict[str, str]:
    gt: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            sha = (row.get("sha256") or "").strip().lower()
            fam = (row.get("family") or "").strip()
            if sha and fam:
                gt[sha] = fam
    return gt


def normalise_string(s: str) -> str:
    return s.strip().lower()


def string_tokens(entry: dict[str, Any]) -> list[str]:
    """Return normalised, length-filtered strings for one sample."""
    raw = entry.get("strings") or []
    return [
        normalise_string(s)
        for s in raw
        if isinstance(s, str) and len(s.strip()) >= STRING_MIN_LEN
    ]


def perm_tokens(entry: dict[str, Any]) -> list[str]:
    """Return short permission names (after the last dot)."""
    return [p.split(".")[-1] for p in (entry.get("permissions") or [])]


def domain_tokens(entry: dict[str, Any]) -> list[str]:
    return list(entry.get("domains") or [])


def find_unique_tokens(
    target_entries: list[dict],
    beater_entries: list[dict],
    corpus_entries: list[dict],
    token_fn,
    label: str,
) -> list[dict[str, Any]]:
    """Find tokens present in ≥TARGET_COVERAGE_MIN of target but not in beaters
    and in < CORPUS_FP_MAX of the non-target corpus.

    Returns a list of candidate dicts sorted by descending coverage.
    """
    if not target_entries:
        return []

    # Token frequency across target samples
    target_counter: collections.Counter = collections.Counter()
    for entry in target_entries:
        for tok in set(token_fn(entry)):
            target_counter[tok] += 1

    # Token sets for beater samples (union — must be absent from ALL beaters)
    beater_tokens: set[str] = set()
    for entry in beater_entries:
        beater_tokens.update(token_fn(entry))

    # Corpus occurrence count (all non-target samples)
    corpus_counter: collections.Counter = collections.Counter()
    corpus_total = len(corpus_entries)
    for entry in corpus_entries:
        for tok in set(token_fn(entry)):
            corpus_counter[tok] += 1

    results = []
    n_target = len(target_entries)
    for tok, count in target_counter.items():
        coverage = count / n_target
        if coverage < TARGET_COVERAGE_MIN:
            continue
        if tok in beater_tokens:
            # Present in the beater family — not a discriminator against it
            continue
        corpus_hits = corpus_counter.get(tok, 0)
        fp_rate = corpus_hits / corpus_total if corpus_total else 0.0
        results.append({
            "token": tok,
            "kind": label,
            "target_coverage": round(coverage, 3),
            "target_hits": count,
            "target_total": n_target,
            "corpus_hits": corpus_hits,
            "corpus_total": corpus_total,
            "fp_rate": round(fp_rate, 4),
            "commit_ready": fp_rate < CORPUS_FP_MAX,
        })

    return sorted(results, key=lambda x: (-x["target_coverage"], x["fp_rate"]))


def analyse_family(
    gt_family: str,
    beater_families: list[str],
    by_family: dict[str, list[dict]],
    all_entries: list[dict],
) -> dict[str, Any]:
    """Mine discriminators for one outcompeted GT family."""
    target_entries = by_family.get(gt_family, [])
    beater_entries: list[dict] = []
    for bf in beater_families:
        beater_entries.extend(by_family.get(bf, []))

    # Corpus = every sample that is NOT the target family
    corpus_entries = [e for e in all_entries if e.get("_family") != gt_family]

    strings  = find_unique_tokens(target_entries, beater_entries, corpus_entries, string_tokens,  "string")
    perms    = find_unique_tokens(target_entries, beater_entries, corpus_entries, perm_tokens,    "permission")
    domains  = find_unique_tokens(target_entries, beater_entries, corpus_entries, domain_tokens,  "domain")

    all_cands = strings + perms + domains
    commit_ready = [c for c in all_cands if c["commit_ready"]]
    has_discriminator = bool(commit_ready)

    return {
        "gt_family": gt_family,
        "target_count": len(target_entries),
        "beater_families": beater_families,
        "beater_count": len(beater_entries),
        "has_discriminator": has_discriminator,
        "commit_ready_count": len(commit_ready),
        "candidates": {
            "strings":     strings[:20],
            "permissions": perms[:10],
            "domains":     domains[:10],
        },
        "top_commit_ready": commit_ready[:10],
    }


def main() -> None:
    results_data = json.load(open(RESULTS_PATH, encoding="utf-8"))
    cache = json.load(open(CACHE_PATH, encoding="utf-8"))
    gt = load_ground_truth(GT_PATH)

    # Attach family label to every cache entry for corpus exclusion
    by_family: dict[str, list[dict]] = collections.defaultdict(list)
    all_entries: list[dict] = []
    for sha, entry in cache.items():
        fam = gt.get(sha, "unknown")
        tagged = {**entry, "_family": fam, "_sha": sha}
        by_family[fam].append(tagged)
        all_entries.append(tagged)

    # Build beater map from the outcompeted diagnosis
    diag = results_data["diagnosis_misses"]
    outcomp = [d for d in diag if d["category"] == "outcompeted"]

    beater_map: dict[str, set[str]] = collections.defaultdict(set)
    for d in outcomp:
        beater_map[d["gt_family"]].add(d["baseline_match"])

    print(f"Outcompeted families: {len(beater_map)}")
    print(f"Total outcompeted samples: {len(outcomp)}")
    print(f"Corpus size: {len(all_entries)} samples\n")

    analyses: list[dict] = []
    for gt_family, beaters in sorted(beater_map.items()):
        result = analyse_family(gt_family, sorted(beaters), by_family, all_entries)
        analyses.append(result)
        status = "COMMIT-READY" if result["has_discriminator"] else "NO-DISCRIMINATOR"
        print(
            f"  {gt_family:<18} beaten by {sorted(beaters)!s:<35}"
            f" -> {result['commit_ready_count']:>2} commit-ready  [{status}]"
        )
        for cand in result["top_commit_ready"][:3]:
            print(
                f"      {cand['kind']:<12} {repr(cand['token']):<40}"
                f" cov={cand['target_coverage']:.2f}  fp={cand['fp_rate']:.4f}"
            )

    summary = {
        "total_outcompeted_families": len(beater_map),
        "total_outcompeted_samples": len(outcomp),
        "families_with_discriminator": sum(1 for a in analyses if a["has_discriminator"]),
        "families_without_discriminator": sum(1 for a in analyses if not a["has_discriminator"]),
        "thresholds": {
            "target_coverage_min": TARGET_COVERAGE_MIN,
            "corpus_fp_max": CORPUS_FP_MAX,
            "string_min_len": STRING_MIN_LEN,
        },
    }

    output = {"summary": summary, "families": analyses}
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nSummary:")
    print(f"  families with discriminator: {summary['families_with_discriminator']} / {summary['total_outcompeted_families']}")
    print(f"  families without:            {summary['families_without_discriminator']}")
    print(f"\nWritten to {OUT_PATH}")


if __name__ == "__main__":
    main()
