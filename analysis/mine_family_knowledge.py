"""Mine family knowledge base from corrected ground truth + feature cache.

For each family with >= 2 labeled malware samples, find discriminating tokens
(strings, domains, permissions) that appear in the family and are rare in the
rest of the corpus.

Features are extracted from the androguard feature cache
(analysis/gap_features_cache.json), which holds the full DEX string set per
sample — far richer than the lossy pipeline result strings. backend/family_id.py
extracts runtime features from the same cache keyed by sha256, falling back to
pipeline-result features when a sample is absent from the cache, so mining and
matching stay consistent.

Output: analysis/family_knowledge_base.json — used by backend/family_id.py's
knowledge-base matcher and by the LLM prompt as a candidate+evidence list.

Run: python analysis/mine_family_knowledge.py
"""

import collections
import csv
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CACHE_PATH = ROOT / "analysis" / "gap_features_cache.json"
GT_CHECK = ROOT / "ground_truth_check_all.csv"
OUT_PATH = ROOT / "analysis" / "family_knowledge_base.json"

# Token must appear in this fraction of the family's samples.
TARGET_COVERAGE_MIN = 0.35
# Token must appear in <= this fraction of non-family samples.
CORPUS_FP_MAX = 0.05
# For small families (n < 4) require stricter FP to avoid single-sample luck.
SMALL_FAMILY_FP_MAX = 0.02
STRING_MIN_LEN = 4
TOKEN_RE = re.compile(r"^[A-Za-z0-9_./: @\[\]\(\)\-#&%]{4,120}$")

# Generic tokens that appear everywhere (framework noise, uninformative).
STOP_TOKENS = frozenset({
    "android", "android.app", "android.content", "android.os", "android.view",
    "android.widget", "android.util", "java.lang", "java.io", "java.util",
    "android.permission", "internet", "access network state", "access",
    "java", "com.android", "androidx", "getapplicationcontext",
    "getsystemservice", "oncreate", "onclick", "setcontentview",
    "findviewbyid", "activity", "service", "receiver", "provider",
    "http", "https", "utf-8", "default", "exception", "null", "true", "false",
})


def load_rows() -> list[dict]:
    with GT_CHECK.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_cache_features() -> dict[str, dict[str, Any]]:
    """Extract features from the androguard cache: readable strings, C2 domains,
    permissions, class count."""
    cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    features: dict[str, dict[str, Any]] = {}
    for sha, entry in cache.items():
        if entry.get("parse_error"):
            continue
        features[sha] = {
            "strings": tokenize(entry.get("strings", []) or []),
            "domains": {
                (d or "").lower() for d in (entry.get("domains", []) or [])
                if isinstance(d, str) and len(d) >= 4
            },
            "permissions": {p.split(".")[-1] for p in (entry.get("permissions", []) or [])},
            "class_count": entry.get("class_count"),
        }
    return features


def tokenize(strings: list[str]) -> set[str]:
    """Extract readable, informative tokens from raw strings."""
    tokens: set[str] = set()
    for value in strings:
        if not isinstance(value, str):
            continue
        value = value.strip()
        if len(value) < STRING_MIN_LEN or len(value) > 120:
            continue
        if not TOKEN_RE.match(value):
            continue
        lowered = value.lower()
        if lowered in STOP_TOKENS:
            continue
        tokens.add(lowered)
    return tokens


def main() -> None:
    rows = load_rows()
    cache_features = load_cache_features()

    # Only malware with a resolved family and a feature-cache entry.
    labeled: dict[str, str] = {}  # sha -> family
    for row in rows:
        fam = (row.get("family_corrected") or "").strip()
        if row["class"].startswith("malware") and fam and fam != "unknown":
            labeled[row["sha256"].lower()] = fam

    # Per-sample feature sets.
    sample_features: dict[str, dict[str, Any]] = {}
    for sha, fam in labeled.items():
        features = cache_features.get(sha)
        if not features:
            continue
        features = dict(features)
        features["family"] = fam
        sample_features[sha] = features

    corpus_size = len(sample_features)
    families: dict[str, list[dict]] = collections.defaultdict(list)
    for features in sample_features.values():
        families[features["family"]].append(features)
    print(f"Corpus: {corpus_size} labeled samples, {len(families)} families")

    def prune(features_for_family: list[dict], key: str, token: str,
              min_coverage: float, max_fp: float) -> dict | None:
        hits = sum(1 for f in features_for_family if token in f[key])
        coverage = hits / len(features_for_family)
        if coverage < min_coverage:
            return None
        other_hits = sum(
            1 for sha, f in sample_features.items()
            if f["family"] != features_for_family[0]["family"] and token in f[key]
        )
        fp = other_hits / max(corpus_size - len(features_for_family), 1)
        if fp > max_fp:
            return None
        return {"token": token, "coverage": round(coverage, 3), "fp": round(fp, 4)}

    knowledge: dict[str, dict[str, Any]] = {}
    for family, members in sorted(families.items(), key=lambda item: -len(item[1])):
        if len(members) < 2:
            continue  # single-sample families need manual review, not mined tokens
        fp_limit = SMALL_FAMILY_FP_MAX if len(members) < 4 else CORPUS_FP_MAX

        string_tokens = []
        union_strings = set().union(*(f["strings"] for f in members))
        for token in union_strings:
            found = prune(members, "strings", token, TARGET_COVERAGE_MIN, fp_limit)
            if found:
                string_tokens.append(found)
        string_tokens.sort(key=lambda t: (-t["coverage"], t["fp"]))

        domain_tokens = []
        union_domains = set().union(*(f["domains"] for f in members))
        for token in union_domains:
            found = prune(members, "domains", token, 0.35, fp_limit)
            if found:
                domain_tokens.append(found)
        domain_tokens.sort(key=lambda t: (-t["coverage"], t["fp"]))

        perm_tokens = []
        union_perms = set().union(*(f["permissions"] for f in members))
        for token in union_perms:
            found = prune(members, "permissions", token, 0.5, fp_limit)
            if found:
                perm_tokens.append(found)
        perm_tokens.sort(key=lambda t: (-t["coverage"], t["fp"]))

        knowledge[family] = {
            "samples": len(members),
            "strings": string_tokens[:25],
            "domains": domain_tokens[:15],
            "permissions": perm_tokens[:15],
        }

    OUT_PATH.write_text(json.dumps(knowledge, indent=2), encoding="utf-8")
    with_discriminator = sum(
        1 for fam in knowledge.values()
        if fam["strings"] or fam["domains"] or fam["permissions"]
    )
    print(f"Knowledge base: {len(knowledge)} families, "
          f"{with_discriminator} with >=1 discriminator -> {OUT_PATH}")
    for family, fam in sorted(knowledge.items(), key=lambda item: -item[1]["samples"])[:15]:
        sig = (
            f"{len(fam['strings'])}s/{len(fam['domains'])}d/"
            f"{len(fam['permissions'])}p"
        )
        print(f"  {family:<18} n={fam['samples']:>3} discriminators: {sig}")


if __name__ == "__main__":
    main()