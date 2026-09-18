"""Validate the 14 draft family signatures against the production matching engine.

Runs backend/family_id._match_family_signatures — the exact production code path —
over all 359 samples in gap_features_cache.json, once with the current signature set
and once with the 14 drafts appended. Writes test_draft_signatures_results.json with:

- per-draft firing/FP statistics (isolated and in-combination) for commit decisions
- per-sample predictions before/after the drafts
- a root-cause diagnosis of every specific-family miss: below_threshold
  (signature exists, cannot reach its threshold), outcompeted (a wrong family
  signature won), or signature_gap (no signature exists for the family)

Native JNI symbol matching is skipped (metadata.apk_path is empty): it only affects
BaseBridge/DroidKungFu, requires the APK corpus on disk, and no draft uses a native
API pattern.

Run: python analysis/test_draft_signatures.py
"""

import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend import family_id as fid
from analysis.draft_signatures import COMMITTED_FAMILIES, DRAFT_SIGNATURES

CACHE_PATH = ROOT / "analysis" / "gap_features_cache.json"
GT_PATH = ROOT / "ground_truth_all.csv"
METRICS_PATH = ROOT / "evaluation" / "metrics" / "metrics.json"
OUT_PATH = ROOT / "analysis" / "test_draft_signatures_results.json"

# Status assigned per signature in the draft_signatures.py docstring.
DRAFT_STATUS: Dict[str, str] = {
    "Secapk": "STRONG",
    "Adsms": "STRONG",
    "FaceNiff": "STRONG",
    "SmForw": "STRONG",
    "Typstu": "STRONG",
    "NickiSpy": "MEDIUM",
    "Boogr": "MEDIUM",
    "Hamob": "MEDIUM",
    "SpyHasb": "MEDIUM",
    "Dougalek": "MEDIUM",
    "Lemon": "WEAK",
    "Nandrobox": "WEAK",
    "Stiniter": "WEAK",
    "FakeTimer": "WEAK",
}


def load_ground_truth(path: Path) -> Dict[str, str]:
    if not path.exists():
        raise FileNotFoundError(f"ground truth not found: {path}")
    mapping: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            sha = (row.get("sha256") or "").strip().lower()
            family = (row.get("family") or "").strip()
            if sha and family:
                mapping[sha] = family
    return mapping


def load_catch_all_families(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    with open(path, "r", encoding="utf-8") as f:
        metrics = json.load(f)
    return {
        entry["family"]
        for entry in metrics.get("per_family_breakdown", [])
        if entry.get("catch_all")
    }


def to_pipeline_result(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Reconstruct the pipeline result shape the engine consumes.

    The engine reads strings.string_literals, manifest.uses_permissions,
    c2_infrastructure[].domain, extraction.decompiled_classes /
    extraction.native_libs_found and metadata.apk_path. The gap cache stores the
    lean equivalents; apk_path stays empty so JNI symbol extraction — which needs
    the APK corpus on disk — is skipped.
    """
    return {
        "manifest": {"uses_permissions": entry.get("permissions", []) or []},
        "strings": {
            "string_literals": [
                {"value": s} for s in (entry.get("strings", []) or [])
            ]
        },
        "c2_infrastructure": [
            {"domain": d} for d in (entry.get("domains", []) or [])
        ],
        "extraction": {
            "decompiled_classes": entry.get("class_count", 0),
            "native_libs_found": entry.get("native_libs", []) or [],
        },
        "metadata": {
            "apk_path": "",
            "certificate_issuer": entry.get("certificate_issuer", ""),
        },
    }


def run_engine(
    samples: Dict[str, Dict[str, Any]],
    signatures: List[fid.FamilySignature],
) -> Dict[str, Dict[str, Any]]:
    """Score every sample against one signature set using the production engine."""
    fid.FAMILY_SIGNATURES = signatures
    results: Dict[str, Dict[str, Any]] = {}
    for sha, entry in samples.items():
        best = fid._match_family_signatures(to_pipeline_result(entry))
        if best is None:
            results[sha] = {
                "family": "unknown",
                "confidence": 0.0,
                "reasoning": "",
                "signals_matched": 0,
            }
        else:
            candidate = best["candidates"][0]
            results[sha] = {
                "family": best["family"],
                "confidence": best["confidence"],
                "reasoning": best.get("reasoning", ""),
                "signals_matched": candidate.get("signals_matched", 0),
            }
    return results


def parse_signals(reasoning: str) -> List[str]:
    if not reasoning:
        return []
    body = reasoning.split("matched: ", 1)[-1]
    return [part.strip() for part in body.split(";") if part.strip()]


def classify(gt_family: str, matched: str, catch_all: Set[str]) -> str:
    if matched == gt_family:
        return "correct"
    if matched == "unknown":
        if gt_family == "unknown" or gt_family in catch_all:
            return "abstention"
        return "gap"
    return "fp"


def diagnose_misses(
    baseline: Dict[str, Dict[str, Any]],
    samples: Dict[str, Dict[str, Any]],
    gt: Dict[str, str],
    catch_all: Set[str],
    current_signatures: List[fid.FamilySignature],
) -> List[Dict[str, Any]]:
    """Root-cause every specific-family miss in the baseline run."""
    current_by_name = {sig.family_name: sig for sig in current_signatures}
    diagnosis: List[Dict[str, Any]] = []

    for sha, pred in baseline.items():
        gt_family = gt.get(sha, "unknown")
        # Catch-all GT labels (AndroidOS, Agent, ...) have no family to match;
        # a named prediction for them is an over-claim, not a miss against a
        # specific family's signature, so they are excluded here.
        if gt_family == "unknown" or gt_family in catch_all:
            continue
        if classify(gt_family, pred["family"], catch_all) not in ("gap", "fp"):
            continue

        entry: Dict[str, Any] = {
            "sha256": sha,
            "gt_family": gt_family,
            "baseline_match": pred["family"],
            "baseline_confidence": pred["confidence"],
            "baseline_signals": pred["signals_matched"],
        }

        if pred["family"] != "unknown":
            entry["category"] = "outcompeted"
            entry["reason"] = (
                f"wrong family won: {pred['family']} @ {pred['confidence']:.2f} "
                f"with {pred['signals_matched']} signals"
            )
            gt_sig = current_by_name.get(gt_family)
            if gt_sig:
                entry["fix"] = (
                    f"add a discriminator string/C2 to the {gt_family} signature "
                    f"(currently {len(gt_sig.string_patterns)} strings, "
                    f"{len(gt_sig.c2_patterns)} C2 patterns)"
                )
            else:
                entry["fix"] = f"no signature exists for {gt_family}"
            diagnosis.append(entry)
            continue

        gt_sig = current_by_name.get(gt_family)
        if gt_sig is None:
            entry["category"] = "signature_gap"
            entry["reason"] = "no signature exists for the family"
            entry["fix"] = "candidate for the draft signature list, or unsignable"
            diagnosis.append(entry)
            continue

        isolated = run_engine({sha: samples[sha]}, [gt_sig])[sha]
        if isolated["family"] == gt_family:
            entry["category"] = "below_threshold"
            entry["reason"] = (
                f"signature exists but reached {isolated['signals_matched']} signals "
                f"against min_matches={gt_sig.min_matches}"
            )
            entry["fix"] = (
                f"lower min_matches {gt_sig.min_matches} -> {isolated['signals_matched']} "
                f"or widen string_patterns / c2_patterns"
            )
        else:
            entry["category"] = "insufficient_signal"
            entry["reason"] = (
                f"signature exists but its evidence is absent: "
                f"strings={gt_sig.string_patterns}, c2={[p.pattern for p in gt_sig.c2_patterns]}"
            )
            entry["fix"] = "needs new evidence mined from the sample, or unsignable"
        diagnosis.append(entry)

    return diagnosis


def main() -> None:
    if not CACHE_PATH.exists():
        raise FileNotFoundError(f"gap features cache not found: {CACHE_PATH}")

    with open(CACHE_PATH, "r", encoding="utf-8") as f:
        samples: Dict[str, Dict[str, Any]] = json.load(f)
    gt = load_ground_truth(GT_PATH)
    catch_all = load_catch_all_families(METRICS_PATH)

    # Only the held (uncommitted) drafts are tested: committed ones now live
    # in FAMILY_SIGNATURES and would trip the overlap guard.
    held_drafts = [sig for sig in DRAFT_SIGNATURES if sig.family_name not in COMMITTED_FAMILIES]
    draft_names = {sig.family_name for sig in held_drafts}
    current_names = {sig.family_name for sig in fid.FAMILY_SIGNATURES}
    overlap = draft_names & current_names
    if overlap:
        raise ValueError(f"draft names collide with current signatures: {overlap}")

    current_signatures = list(fid.FAMILY_SIGNATURES)
    combined_signatures = current_signatures + list(held_drafts)

    print(f"scoring {len(samples)} samples: baseline + {len(held_drafts)} held drafts ...")
    baseline = run_engine(samples, current_signatures)
    combined = run_engine(samples, combined_signatures)

    diagnosis = diagnose_misses(baseline, samples, gt, catch_all, current_signatures)

    draft_names_combined = set(draft_names)
    per_family: Dict[str, Dict[str, Any]] = {}
    for sig in held_drafts:
        isolated = run_engine(samples, [sig])
        # Strict correctness: the draft fired on its own family's sample(s).
        # classify() would also count abstentions on GT-unknown samples as
        # "correct" (unknown == unknown), which is right for refusal metrics
        # but meaningless for per-draft accuracy.
        isolated_correct = sum(
            1 for sha, pred in isolated.items()
            if pred["family"] == sig.family_name and gt.get(sha) == sig.family_name
        )
        isolated_fps = sum(
            1 for sha, pred in isolated.items()
            if classify(gt.get(sha, "unknown"), pred["family"], catch_all) == "fp"
        )
        isolated_matches = sum(1 for pred in isolated.values() if pred["family"] == sig.family_name)

        claimed = [
            sha for sha, pred in combined.items() if pred["family"] == sig.family_name
        ]
        correct = sum(1 for sha in claimed if gt.get(sha) == sig.family_name)
        fps = len(claimed) - correct
        gt_count = sum(1 for fam in gt.values() if fam == sig.family_name)

        status = DRAFT_STATUS.get(sig.family_name, "UNRATED")
        commit = (
            status in ("STRONG", "MEDIUM")
            and isolated_fps == 0
            and isolated_correct >= 1
        )
        per_family[sig.family_name] = {
            "status": status,
            "gt_count": gt_count,
            "combined_matches": len(claimed),
            "combined_correct": correct,
            "combined_fps": fps,
            "isolated_matches": isolated_matches,
            "isolated_correct": isolated_correct,
            "isolated_fps": isolated_fps,
            "commit": commit,
        }

    def count(rows: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
        counts = {name: 0 for name in ("correct", "fp", "gap", "abstention")}
        for sha, pred in rows.items():
            status = classify(gt.get(sha, "unknown"), pred["family"], catch_all)
            counts[status] += 1
        return counts

    baseline_counts = count(baseline)
    combined_counts = count(combined)
    new_correct = sum(
        1 for sha in samples
        if classify(gt.get(sha, "unknown"), baseline[sha]["family"], catch_all) != "correct"
        and classify(gt.get(sha, "unknown"), combined[sha]["family"], catch_all) == "correct"
    )
    new_fps = sum(
        1 for sha in samples
        if classify(gt.get(sha, "unknown"), baseline[sha]["family"], catch_all) != "fp"
        and classify(gt.get(sha, "unknown"), combined[sha]["family"], catch_all) == "fp"
    )

    samples_out = []
    for sha in samples:
        gt_family = gt.get(sha, "unknown")
        pred = combined[sha]
        before = baseline[sha]
        samples_out.append({
            "sha256": sha,
            "gt_family": gt_family,
            "matched_family": pred["family"],
            "confidence": pred["confidence"],
            "via_draft": pred["family"] in draft_names_combined,
            "fired_signals": parse_signals(pred["reasoning"]),
            "status": classify(gt_family, pred["family"], catch_all),
            "baseline_family": before["family"],
            "baseline_confidence": before["confidence"],
        })

    by_status: Dict[str, Dict[str, Any]] = {}
    for status in ("STRONG", "MEDIUM", "WEAK"):
        members = [sig.family_name for sig in held_drafts if DRAFT_STATUS.get(sig.family_name) == status]
        by_status[status] = {
            "drafts": len(members),
            "combined_correct": sum(per_family[m]["combined_correct"] for m in members),
            "combined_fps": sum(per_family[m]["combined_fps"] for m in members),
            "commit_ready": [m for m in members if per_family[m]["commit"]],
        }

    report = {
        "summary": {
            "total_samples": len(samples),
            "drafts_tested": len(held_drafts),
            "baseline_correct": baseline_counts["correct"],
            "combined_correct": combined_counts["correct"],
            "new_correct": new_correct,
            "new_fps": new_fps,
            "baseline_counts": baseline_counts,
            "combined_counts": combined_counts,
            "by_status": by_status,
            "diagnosis_counts": {
                cat: sum(1 for d in diagnosis if d["category"] == cat)
                for cat in ("below_threshold", "outcompeted", "insufficient_signal", "signature_gap")
            },
            "note": (
                "isolated = draft scored alone over all 359 samples (FP risk of the "
                "draft itself); combined = drafts appended after current signatures "
                "(current wins ties, drafts only win when stronger)"
            ),
        },
        "per_family": per_family,
        "samples": samples_out,
        "diagnosis_misses": diagnosis,
    }

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\nbaseline correct: {baseline_counts['correct']} / {len(samples)}")
    print(f"with drafts:      {combined_counts['correct']} / {len(samples)} "
          f"(+{new_correct} correct, +{new_fps} false positives)")
    print("\nper-draft (combined_correct / combined_fps | isolated_correct / isolated_fps):")
    for name, stats in sorted(per_family.items()):
        verdict = "COMMIT" if stats["commit"] else ("SKIP" if stats["status"] == "WEAK" else "TUNE")
        print(
            f"  {name:<12} {stats['status']:<6} "
            f"{stats['combined_correct']:>2}/{stats['combined_fps']:<2} | "
            f"{stats['isolated_correct']:>2}/{stats['isolated_fps']:<2} "
            f"(gt:{stats['gt_count']})  {verdict}"
        )
    print(f"\nmiss diagnosis ({len(diagnosis)}):")
    for cat in ("below_threshold", "outcompeted", "insufficient_signal", "signature_gap"):
        n = sum(1 for d in diagnosis if d["category"] == cat)
        print(f"  {cat}: {n}")
    print(f"\nreport written to {OUT_PATH}")


if __name__ == "__main__":
    main()