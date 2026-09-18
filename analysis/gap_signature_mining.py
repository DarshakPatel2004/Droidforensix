"""
Gap-signature mining for the 48 no-signature family-ID misses.

The 359-sample lock showed 84 specific-family gaps; 48 of them belong to 36
families the signature engine (backend/family_id.py) does not model at all, or
whose existing signature misses. This module:

  1. Extracts lean static features (permissions, DEX strings, class counts,
     native libs, filtered C2 domains) for every sample in ground_truth_all.csv
     using androguard only - no apktool/jadx - into a resumable JSON cache.
  2. Mines per-family shared signals for those gap families, so signature
     rules can be drafted on evidence (not guessing).
  3. Validates drafted rules: targets caught, no false positives that flip a
     previously-correct match, and the corpus-level accuracy delta.

Run:
    python analysis/gap_signature_mining.py --features   # all 359 -> cache JSON
    python analysis/gap_signature_mining.py --mine       # per-family signal report
    python analysis/gap_signature_mining.py --validate   # baseline vs drafted sigs

The drafted signature rules themselves live in analysis/draft_signatures.py.
"""

import argparse
import concurrent.futures
import csv
import json
import logging
import os
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logging.disable(logging.CRITICAL)  # androguard DEBUG spam

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from androguard.core.apk import APK
from androguard.core.dex import DEX

from analysis.step5_c2_extraction import (
    DOMAIN_RE,
    URL_RE,
    _is_benign_domain,
    _is_code_reference,
    _is_likely_junk_domain,
    is_ad_network,
    is_benign_url,
    parse_url,
)

GT_CSV = ROOT / "ground_truth_all.csv"
PREDICTIONS_JSON = ROOT / "evaluation" / "validation_359_fixed" / "predictions.json"
FAMILY_BREAKDOWN_CSV = ROOT / "evaluation" / "metrics" / "per_family_breakdown.csv"
FEATURES_CACHE = ROOT / "analysis" / "gap_features_cache.json"
SIGNAL_REPORT = ROOT / "analysis" / "gap_signal_report.json"

# String prefixes that are framework / SDK boilerplate, never family signal.
BENIGN_STRING_PREFIXES = (
    "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.",
    "com.android.", "com.google.", "com.google.android.", "com.google.firebase.",
    "com.firebase.", "com.facebook.", "com.bumptech.glide.", "com.squareup.",
    "com.appsflyer.", "com.adjust.", "com.onesignal.", "com.amplitude.",
    "com.sentry.", "io.sentry.", "io.flutter.", "org.apache.", "org.json.",
    "org.xml.", "org.w3c.", "org.slf4j.", "org.junit.", "org.mockito.",
    "org.jetbrains.", "okhttp3.", "okio.", "retrofit2.", "rx.", "io.reactivex.",
    "dalvik.", "junit.", "butterknife.", "dagger.", "hilt.", "org.intellij.",
    "com.crashlytics.", "com.newrelic.", "com.tencent.", "com.baidu.",
    "com.alibaba.", "com.taobao.", "com.aliyun.", "com.qq.", "com.tencent.",
    "com.huawei.", "com.xiaomi.", "com.oppo.", "com.vivo.", "com.meizu.",
    "com.umeng.", "cn.jpush.", "com.igexin.", "com.netease.", "com.bytedance.",
    "com.kuaishou.", "com.unity3d.", "com.ironsource.", "com.applovin.",
    "com.adcolony.", "com.vungle.", "com.chartboost.", "com.inmobi.",
    "com.mopub.", "com.startapp.", "com.tapjoy.", "com.unity.",
    "system.", "microsoft.", "mono.", "net.", "windows.",
)

# Families with zero correct matches but an existing signature (diagnose, do
# not double-sign).
EXISTING_SIG_FAMILIES = {"BankBot", "Zsone", "FakeRun", "DroidDream", "Adrd"}


# ---------------------------------------------------------------------------
# 1. Feature extraction
# ---------------------------------------------------------------------------


def _extract_c2_domains(strings: List[str]) -> Dict[str, List[str]]:
    """URL + bare-domain extraction reusing step5 filters. Returns
    {"domains": [...], "ad_domains": [...]}."""
    domains: List[str] = []
    ad_domains: List[str] = []
    seen = set()
    for value in strings:
        if not isinstance(value, str):
            continue
        for url in URL_RE.findall(value):
            parsed = parse_url(url)
            if parsed is None or is_benign_url(url):
                continue
            host = (parsed.get("domain") or "").lower()
            if not host or host in seen:
                continue
            seen.add(host)
            (ad_domains if is_ad_network(host) else domains).append(host)
        for domain in DOMAIN_RE.findall(value):
            dl = domain.lower()
            if dl in seen:
                continue
            if _is_code_reference(domain) or _is_likely_junk_domain(domain):
                continue
            if _is_benign_domain(dl):
                continue
            seen.add(dl)
            (ad_domains if is_ad_network(dl) else domains).append(dl)
    return {"domains": sorted(set(domains)), "ad_domains": sorted(set(ad_domains))}


def extract_sample_features(apk_path: str) -> Dict[str, Any]:
    """Lean static features from an APK (androguard only)."""
    out: Dict[str, Any] = {
        "permissions": [],
        "strings": [],
        "class_count": 0,
        "native_libs": [],
        "domains": [],
        "ad_domains": [],
        "parse_error": "",
    }
    
    # Use APK class for primary extraction (manifest, permissions)
    try:
        a = APK(apk_path)
        
        # Native libs from APK
        try:
            out["native_libs"] = sorted(
                n.split("/")[-1] for n in a.get_files() if n.endswith(".so")
            )
        except Exception:
            pass
        
        # Permissions
        try:
            out["permissions"] = sorted(set(a.get_permissions()))
        except Exception as exc:
            if not out["parse_error"]:
                out["parse_error"] = f"manifest: {exc}"
                
    except Exception as exc:
        out["parse_error"] = f"apk: {exc}"
    
    # Parse DEX files from ZIP for class count and strings (more reliable)
    try:
        with zipfile.ZipFile(apk_path) as zf:
            out["native_libs"] = sorted(
                n.split("/")[-1] for n in zf.namelist() if n.endswith(".so")
            )
            for name in zf.namelist():
                if not name.endswith(".dex"):
                    continue
                raw = zf.read(name)
                if len(raw) < 8:
                    continue
                # Verify DEX magic
                if not raw.startswith(b"dex\n"):
                    continue
                try:
                    d = DEX(bytearray(raw))
                    classes = list(d.get_classes())
                    out["class_count"] += len(classes)
                    for s in d.get_strings():
                        if s:
                            out["strings"].append(s)
                except Exception as exc:
                    out["parse_error"] = f"dex {name}: {exc}"
    except Exception as exc:
        if not out["parse_error"]:
            out["parse_error"] = f"zip: {exc}"
    
    # C2 domain extraction from all collected strings
    c2 = _extract_c2_domains(out["strings"])
    out["domains"] = c2["domains"]
    out["ad_domains"] = c2["ad_domains"]
    return out


def _feature_row(sha256: str, apk_path: str) -> Dict[str, Any]:
    f = extract_sample_features(apk_path)
    f["sha256"] = sha256
    f["apk_path"] = apk_path
    return f


def extract_corpus(gt_csv: Path, cache: Path, workers: int = 8) -> Path:
    with open(gt_csv, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    cache_data: Dict[str, Any] = {}
    if cache.exists():
        try:
            cache_data = json.loads(cache.read_text(encoding="utf-8"))
        except Exception:
            cache_data = {}
    pending = [r for r in rows if r["sha256"] not in cache_data]
    print(f"feature cache: {len(cache_data)} done, {len(pending)} pending", flush=True)
    if pending:
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(_feature_row, r["sha256"], r["apk_path"]): r["sha256"]
                for r in pending
            }
            for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
                sha = futures[fut]
                try:
                    cache_data[sha] = fut.result()
                except Exception as exc:
                    cache_data[sha] = {"sha256": sha, "parse_error": str(exc)}
                if i % 25 == 0 or i == len(pending):
                    cache.write_text(json.dumps(cache_data), encoding="utf-8")
                    print(f"features: {len(cache_data)}/{len(rows)}", flush=True)
    cache.write_text(json.dumps(cache_data), encoding="utf-8")
    print(f"features written: {cache} ({len(cache_data)} samples)", flush=True)
    return cache


# ---------------------------------------------------------------------------
# 2. Signal mining
# ---------------------------------------------------------------------------


def _load_predictions() -> Dict[str, Dict[str, str]]:
    data = json.loads(PREDICTIONS_JSON.read_text(encoding="utf-8"))
    return {str(p.get("sha256") or "").lower(): p for p in data}


def _load_target_families() -> Set[str]:
    """Specific families with zero correct matches in the lock."""
    targets = set()
    with open(FAMILY_BREAKDOWN_CSV, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if (r.get("Catch-all") or "").strip().lower() == "true":
                continue
            if int(r.get("Correct") or 0) == 0 and int(r.get("GT Count") or 0) > 0:
                targets.add((r.get("Family") or "").strip())
    return targets


def _background_rate(strings_all: List[str]) -> Counter:
    """How often each string appears across the whole corpus (lowercased)."""
    c: Counter = Counter()
    for s in strings_all:
        v = str(s).lower()
        if v:
            c[v] += 1
    return c


def _is_benign_string(value: str) -> bool:
    v = value.lower()
    if len(v) < 5:
        return True
    if v.startswith(BENIGN_STRING_PREFIXES):
        return True
    if re.fullmatch(r"[0-9a-f]{8,}|[0-9]+|0x[0-9a-f]+", v):
        return True
    return False


def mine_signals(features: Dict[str, Any]) -> Dict[str, Any]:
    preds = _load_predictions()
    targets = _load_target_families()
    by_family: Dict[str, List[str]] = {}
    for p in preds.values():
        gt = (p.get("ground_truth") or "").strip()
        if gt in targets:
            by_family.setdefault(gt, []).append(str(p.get("sha256") or "").lower())

    bg = _background_rate([s for f in features.values() for s in (f.get("strings") or [])])
    total_samples = len(features)

    report: Dict[str, Any] = {}
    for family, shas in sorted(by_family.items()):
        fam_features = [features[s] for s in shas if s in features]
        if not fam_features:
            report[family] = {"samples": shas, "note": "features missing"}
            continue
        # shared strings (present in >= 50% of family samples, rare elsewhere)
        str_counter: Counter = Counter()
        for f in fam_features:
            for s in set(f.get("strings") or []):
                v = str(s).lower()
                if v:
                    str_counter[v] += 1
        n = len(fam_features)
        shared = []
        for v, cnt in str_counter.most_common(60):
            if cnt * 2 < n:  # >= 50% of family samples
                continue
            if _is_benign_string(v):
                continue
            if bg[v] > max(2, total_samples * 0.08):  # present in >8% of corpus
                continue
            shared.append({"string": v, "family_coverage": f"{cnt}/{n}", "corpus_occurrences": bg[v]})
        # permissions shared by >= 50%
        perm_counter: Counter = Counter()
        for f in fam_features:
            for p in set(f.get("permissions") or []):
                perm_counter[p.split(".")[-1]] += 1
        perms = [{"permission": k, "family_coverage": f"{v}/{n}"} for k, v in perm_counter.most_common() if v * 2 >= n]
        # domains shared by >= 50%
        dom_counter: Counter = Counter()
        ad_counter: Counter = Counter()
        for f in fam_features:
            for d in set(f.get("domains") or []):
                dom_counter[d] += 1
            for d in set(f.get("ad_domains") or []):
                ad_counter[d] += 1
        domains = [{"domain": k, "family_coverage": f"{v}/{n}"} for k, v in dom_counter.most_common() if v * 2 >= n]
        ad_domains = [{"domain": k, "family_coverage": f"{v}/{n}"} for k, v in ad_counter.most_common() if v * 2 >= n]
        class_counts = sorted(f.get("class_count", 0) for f in fam_features)
        native = [sorted(f.get("native_libs") or []) for f in fam_features]
        report[family] = {
            "samples": [{"sha256": s, "classes": features[s].get("class_count", 0),
                         "native": features[s].get("native_libs", []),
                         "has_c2_domain": bool(features[s].get("domains"))} for s in shas if s in features],
            "class_range": [class_counts[0], class_counts[-1]] if class_counts else [],
            "class_median": class_counts[len(class_counts) // 2] if class_counts else 0,
            "any_native": any(native),
            "native_libs": sorted({lib for libs in native for lib in libs}),
            "shared_strings": shared[:20],
            "shared_permissions": perms,
            "shared_domains": domains[:10],
            "shared_ad_domains": ad_domains[:10],
        }
    return report


# ---------------------------------------------------------------------------
# 3. Validation harness
# ---------------------------------------------------------------------------


def _to_pipeline_result(f: Dict[str, Any]) -> Dict[str, Any]:
    """Shape lean features like the pipeline result dict family_id consumes."""
    return {
        "manifest": {"uses_permissions": f.get("permissions") or []},
        "strings": {
            "string_literals": [{"value": s} for s in (f.get("strings") or [])],
            "native_strings": [],
        },
        "c2_infrastructure": [{"domain": d} for d in (f.get("domains") or [])],
        "extraction": {
            "decompiled_classes": f.get("class_count", 0),
            "native_libs_found": f.get("native_libs") or [],
        },
        "metadata": {"apk_path": f.get("apk_path", "")},
    }


def _accuracy(features: Dict[str, Any], signatures: List[Any]) -> Dict[str, Any]:
    """Exact-match accuracy over parsed samples using a signature list."""
    from backend.family_id import _match_family_signatures

    preds = _load_predictions()
    catch_all = set()
    with open(FAMILY_BREAKDOWN_CSV, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if (r.get("Catch-all") or "").strip().lower() == "true":
                catch_all.add((r.get("Family") or "").strip().lower())
    import backend.family_id as fid

    original = fid.FAMILY_SIGNATURES
    fid.FAMILY_SIGNATURES = list(signatures)
    correct = 0
    specific_total = 0
    specific_correct = 0
    evaluated = 0
    flipped_correct = 0  # samples that were correct with baseline and lost it
    flipped_wrong = 0  # samples that were wrong and became correct
    try:
        for sha, f in features.items():
            if f.get("parse_error"):
                continue
            p = preds.get(sha.lower())
            if not p:
                continue
            gt = (p.get("ground_truth") or "").strip().lower()
            pred = (_match_family_signatures(_to_pipeline_result(f)) or {}).get("family", "unknown").lower()
            norm_gt = gt
            if norm_gt in ("kungfu",):
                norm_gt = "droidkungfu"
            if norm_gt == "andr/ngate-g":
                norm_gt = "ngate"
            evaluated += 1
            if pred == norm_gt:
                correct += 1
            if not gt or gt in catch_all:
                continue
            specific_total += 1
            if pred == norm_gt:
                specific_correct += 1
    finally:
        fid.FAMILY_SIGNATURES = original
    return {
        "evaluated": evaluated,
        "overall_correct": correct,
        "specific_total": specific_total,
        "specific_correct": specific_correct,
        "specific_accuracy": round(specific_correct / specific_total, 4) if specific_total else 0,
    }


def _per_draft_capture(features: Dict[str, Any], draft: Any) -> Dict[str, Any]:
    """How often a single drafted signature fires, split by its own GT family
    (targets) vs every other sample (false-positive candidates)."""
    from backend.family_id import _match_family_signatures

    preds = _load_predictions()
    fam = draft.family_name
    matched = []
    for sha, f in features.items():
        if f.get("parse_error"):
            continue
        p = preds.get(sha.lower())
        if not p:
            continue
        import backend.family_id as fid

        original = fid.FAMILY_SIGNATURES
        fid.FAMILY_SIGNATURES = [draft]
        try:
            hit = (_match_family_signatures(_to_pipeline_result(f)) or {}).get("family")
        finally:
            fid.FAMILY_SIGNATURES = original
        if hit == fam:
            matched.append(sha)
    own = [(p.get("ground_truth") or "").strip() for p in preds.values() if str(p.get("sha256") or "").lower() in matched]
    targets = sum(1 for g in own if g == fam)
    others = [sha for sha in matched if (preds.get(sha, {}).get("ground_truth") or "").strip() != fam]
    return {
        "family": fam,
        "matches": len(matched),
        "own_family_hits": targets,
        "other_sample_hits": len(others),
        "other_samples": sorted(others)[:10],
    }


def validate(features: Dict[str, Any]) -> Dict[str, Any]:
    from backend.family_id import FAMILY_SIGNATURES

    try:
        from analysis.draft_signatures import DRAFT_SIGNATURES
    except ImportError as exc:
        print(f"analysis/draft_signatures.py not importable: {exc}")
        sys.exit(1)

    base = _accuracy(features, FAMILY_SIGNATURES)
    combined = _accuracy(features, list(FAMILY_SIGNATURES) + list(DRAFT_SIGNATURES))
    per_draft = [_per_draft_capture(features, d) for d in DRAFT_SIGNATURES]
    return {"baseline": base, "with_drafts": combined, "per_draft": per_draft}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", action="store_true", help="extract features for all 359 samples")
    parser.add_argument("--mine", action="store_true", help="mine per-family signals for gap families")
    parser.add_argument("--validate", action="store_true", help="baseline vs drafted-signature accuracy")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 8)
    args = parser.parse_args()

    if args.features:
        extract_corpus(GT_CSV, FEATURES_CACHE, workers=args.workers)
        return
    if not FEATURES_CACHE.exists():
        print("no features cache - run: python analysis/gap_signature_mining.py --features")
        sys.exit(1)
    features = json.loads(FEATURES_CACHE.read_text(encoding="utf-8"))
    if args.mine:
        report = mine_signals(features)
        SIGNAL_REPORT.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print(json.dumps(report, indent=2, default=str)[:60000])
        print(f"\nsignal report written: {SIGNAL_REPORT}")
        return
    if args.validate:
        print(json.dumps(validate(features), indent=2))
        return
    parser.print_help()


if __name__ == "__main__":
    main()
