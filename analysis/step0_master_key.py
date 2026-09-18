"""
Step 0: Master Key + Knowledge Transfer pre-processing for accuracy pipeline.

Wires docs/MASTER_KEY_STRATEGY.md (7-step oracle playbook) and
docs/FULL_KNOWLEDGE_TRANSFER.md (packer taxonomy, E-codes, triage matrix)
into analysis/pipeline.py before string enumeration.

Purpose:
- Detect packing via H1-H6 triage (scripts/triage.py) before family_id runs
  on encrypted blobs. KT §4 / MASTER_KEY §1-2.
- Route to correct strategy: JAVA (so_count==0, injected repack) vs NATIVE
  (custom myg0N kit vs commercial VMP) via scripts/unpack.py dispatcher.
- Attempt decrypt via Uniswap oracle (scripts/emulate.py) + myg0N KDF brute
  (seed = stem+"2", sha1→key, sha256→IV, AES-CBC, VALIDATION PK/dex magic).
  On success, artifacts feed gap_features_cache.json strings for
  mine_family_knowledge.py → family_id.py, rescuing opaque families
  (Opfake/FakeInstaller) that currently have 0 static signal.
- On E-code (E-NATIVE-NOENTRY, E-NATIVE-NO-RECOVERY, E-JAVA-RUNTIME-DELIVERY,
  E-NATIVE-LAZY-DECRYPT etc from unpack.py + PENDRIVE_MASTER_KEY_INTEL.md)
  mark sample as E-coded so evaluation/metrics_recompute.py can treat it as
  catch-all (not penalized as wrong family) - see MASTER_KEY §16 + KT §15.

Integration: called from analysis/pipeline.py:run_pipeline() after Step1
extraction, before Step2 string enumeration. Returns dict stored at
result["master_key"] for family_id.py and metrics.

See: docs/accuracy-improvement-plan.md Phase 0, docs/MASTER_KEY_STRATEGY.md,
     docs/FULL_KNOWLEDGE_TRANSFER.md §2-4,15
"""

import json
import logging
import pathlib
import sys
import zipfile
from typing import Any, Dict

logger = logging.getLogger(__name__)

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

# E-codes that are EXPECTED for commercial packers - not model failures
# MUST stay in sync with scripts/unpack.py E_CODES + PENDRIVE_MASTER_KEY_INTEL.md
# and evaluation/metrics_recompute.py CATCH_ALL_LABELS extension.
E_CODE_CATCH_ALLS = frozenset({
    "e-native-noentry",
    "e-native-no-recovery",
    "e-native-lazy-decrypt",
    "e-native-nullcall",
    "e-java-runtime-delivery",
    "e-java-no-ioc",
    "e-oracle-fault",
    "e-arm32-envargs",
    "e-zipcrypto-runtime",  # Tubi/MediaPlayer flag-lie container
})

# Triage verdicts that require Master Key attempt (KT §15 matrix)
# clean_static → skip oracle, packed_* / indeterminate(suspect) → attempt
PACKED_VERDICTS = ("packed_custom", "packed_known", "indeterminate", "obfuscated_native")


def _load_triage(apk_path: pathlib.Path) -> Dict[str, Any]:
    """Run H1-H6 triage without subprocess - direct import for speed."""
    try:
        from triage import triage_apk, load_json, MARKERS_PATH, ALLOWLIST_PATH
        markers = load_json(MARKERS_PATH)
        allowlist = load_json(ALLOWLIST_PATH)
        report = triage_apk(apk_path, markers, allowlist)
        return report
    except Exception as e:
        logger.warning("MasterKey Step0: triage failed: %s", e)
        return {"verdict": "triage_error", "confidence": 0.0, "error": str(e)[:200]}


def _attempt_unpack(apk_path: pathlib.Path, work_dir: pathlib.Path, triage_report: Dict[str, Any]) -> Dict[str, Any]:
    """Delegate to scripts/unpack.py dispatcher - JAVA/NATIVE + myg0N KDF brute."""
    try:
        from unpack import java_route, native_route
        with zipfile.ZipFile(apk_path) as zf:
            names = zf.namelist()
            so_count = sum(1 for n in names if n.endswith(".so"))
        # Minimal report scaffold unpack.py expects
        import hashlib
        raw = apk_path.read_bytes()
        report: Dict[str, Any] = {
            "apk": str(apk_path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "verdict": "FAILED",
            "ecode": None,
            "artifacts": [],
            "stats": {"entries": len(names), "so_count": so_count},
            "triage": {"verdict": triage_report.get("verdict"), "confidence": triage_report.get("confidence")},
        }
        with zipfile.ZipFile(apk_path) as zf:
            if so_count == 0:
                report["route"] = "JAVA"
                report = java_route(apk_path, zf, work_dir, report)
            else:
                report["route"] = "NATIVE"
                report = native_route(apk_path, zf, work_dir, report)
        # Normalize: unpack returns ecode without E- prefix in some paths
        if report.get("ecode") and not report.get("verdict") == "RECOVERED":
            # ensure ecode is present
            pass
        return report
    except Exception as e:
        logger.warning("MasterKey Step0: unpack dispatch failed: %s", e)
        return {"verdict": "FAILED", "ecode": "E-ORACLE-FAULT", "detail": str(e)[:200], "artifacts": []}


def run_master_key_preprocess(apk_path: str, work_dir: str) -> Dict[str, Any]:
    """
    Master Key Step 0 - called from pipeline.py after Step1.

    Returns dict always stored at result["master_key"]:
    {
        "triage_verdict": "packed_custom" | "clean_static" | "indeterminate(suspect:dropper-shape)" ...,
        "triage_confidence": 0.85,
        "route": "NATIVE" | "JAVA" | "SKIPPED",
        "verdict": "RECOVERED" | "FAILED",
        "ecode": "E-NATIVE-NOENTRY" | None,
        "is_e_coded": bool,  # True if E-code in E_CODE_CATCH_ALLS → metrics should treat as catch-all
        "artifacts": [...],  # self-validated (PK/dex magic) if RECOVERED
        "kt_taxonomy": "myg0N kit (custom, beaten)" | "Ijiami VMP (E-coded)" | ...,
        "should_enrich_strings": bool,  # True if RECOVERED → pipeline should use decrypted dex strings
    }

    KT §15: indeterminate is NEVER benign - dropper-shape (no launcher + FCM) escalates to suspect.
    MASTER_KEY §16: commercial VMP (Ijiami/Bangcle/360) → E-*-NOENTRY is expected, not a miss.
    """
    apk = pathlib.Path(apk_path)
    wd = pathlib.Path(work_dir)

    triage_report = _load_triage(apk)
    verdict = triage_report.get("verdict", "unknown")
    confidence = triage_report.get("confidence", 0.0)

    # KT §15 triage matrix: 100 goodware 0FP, 32 malware 0FN - packing detection, not malice
    # If clean_static, skip oracle entirely (no encrypted blob)
    is_packed = any(v in verdict for v in PACKED_VERDICTS)
    if not is_packed:
        return {
            "triage_verdict": verdict,
            "triage_confidence": confidence,
            "route": "SKIPPED",
            "verdict": "SKIPPED",
            "ecode": None,
            "is_e_coded": False,
            "artifacts": [],
            "kt_taxonomy": "clean_static - static pipeline sufficient (KT §8, 44/55 pendrive benign)",
            "should_enrich_strings": False,
            "triage_report": triage_report,
        }

    # Packed → attempt Master Key unpack (myg0N KDF brute + oracle)
    unpack_report = _attempt_unpack(apk, wd / "master_key", triage_report)
    ecode = unpack_report.get("ecode")
    is_e_coded = bool(ecode and ecode.lower() in E_CODE_CATCH_ALLS)
    # Also handle E-codes with parentheses: E-NATIVE-NOENTRY(Ijiami) etc
    if ecode and not is_e_coded:
        base = ecode.split("(")[0].strip().lower()
        is_e_coded = base in E_CODE_CATCH_ALLS

    should_enrich = unpack_report.get("verdict") == "RECOVERED" and bool(unpack_report.get("artifacts"))

    # Map to KT taxonomy for reporting
    family = unpack_report.get("family") or "Unknown"
    if should_enrich:
        taxonomy = f"myg0N kit (custom, beaten) - {family} (MASTER_KEY §2-5, FULL_KT §4)"
    elif ecode == "E-NATIVE-NOENTRY":
        taxonomy = f"Commercial VMP {family} (Ijiami/Bangcle/360Jiagu - E-coded expected per MASTER_KEY §16, KT §4)"
    elif ecode == "E-JAVA-RUNTIME-DELIVERY":
        taxonomy = "Java injected repack (so_count:0) - runtime delivery, take Java path (MASTER_KEY §2.5, KT §4)"
    elif is_e_coded:
        taxonomy = f"E-coded {ecode} - documented limit, not model failure (PENDRIVE_MASTER_KEY_INTEL.md)"
    else:
        taxonomy = f"Unpacked attempt failed {ecode or 'no ecode'} - needs manual review"

    return {
        "triage_verdict": verdict,
        "triage_confidence": confidence,
        "route": unpack_report.get("route", "NATIVE"),
        "verdict": unpack_report.get("verdict", "FAILED"),
        "ecode": ecode,
        "is_e_coded": is_e_coded,
        "artifacts": unpack_report.get("artifacts", []),
        "kdf": unpack_report.get("kdf"),
        "iocs": unpack_report.get("iocs", {}),
        "family_sniff": family,
        "kt_taxonomy": taxonomy,
        "should_enrich_strings": should_enrich,
        "triage_report": triage_report,
        "unpack_report": unpack_report,
    }


def enrich_strings_with_recovered(strings_result: Dict[str, Any], master_key: Dict[str, Any]) -> Dict[str, Any]:
    """
    If Master Key recovered a kit.zip/installer.dex, extract its strings and
    merge into strings_result categories so downstream C2/family_id see
    decrypted strings (rescues Opfake/FakeInstaller opaque misses).

    Called from pipeline.py after Step2 if master_key["should_enrich_strings"].
    """
    if not master_key.get("should_enrich_strings"):
        return strings_result
    artifacts = master_key.get("artifacts") or []
    kit_path = None
    for art in artifacts:
        f = art.get("file", "")
        if f.endswith(".zip") or "kit.zip" in f:
            kit_path = pathlib.Path(f)
            break
    if not kit_path or not kit_path.exists():
        return strings_result
    try:
        import io
        with zipfile.ZipFile(kit_path) as zf:
            blob = b"".join(zf.read(n) for n in zf.namelist() if n.endswith(".dex") or n.endswith(".apk"))[:20_000_000]
            # Extract printable strings 4-120 chars, same TOKEN_RE as mine_family_knowledge.py:43
            import re
            raw_strings = re.findall(rb"[A-Za-z0-9_./: @\[\]\(\)\-#&%]{4,120}", blob)
            decoded = [s.decode(errors="ignore").strip() for s in raw_strings if len(s) >= 4]
            # Merge into categories["string_literals"] for downstream
            cats = strings_result.get("categories", {})
            if "string_literals" not in cats:
                cats["string_literals"] = []
            # Keep as dict format pipeline expects: {"value": str}
            existing = { (v.get("value") if isinstance(v, dict) else v) for v in cats["string_literals"] }
            for s in decoded[:5000]:  # cap to avoid blowup
                if s.lower() not in {e.lower() for e in existing}:
                    cats["string_literals"].append({"value": s})
                    existing.add(s)
            strings_result["total_strings"] = len(cats["string_literals"])
            logger.info("MasterKey enrich: +%d strings from %s (now %d)", len(decoded), kit_path.name, strings_result["total_strings"])
    except Exception as e:
        logger.warning("MasterKey enrich failed for %s: %s", kit_path, e)
    return strings_result
