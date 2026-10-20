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
- Second chance (breaker follow-up, plan doc 2026-10-15): when the dispatcher fails, one
  bounded master key breaker sweep (packers/breaker/, BREAKER_ATTEMPTS_CAP attempts per
  APK) runs over at-rest asset blobs. A hit is materialised into the same
  <work_dir>/<sha16>/kit.zip layout, so enrichment is unchanged; a miss leaves the
  unpack verdict/ecode untouched and is reported only in result["breaker"].
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

import hashlib
import json
import logging
import pathlib
import sys
import zipfile
from typing import Any, Dict, Optional

from analysis.payload_evidence import collect_payload_evidence

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

# Master key breaker second chance: runs only after the unpack dispatcher failed.
# The cap is per APK (packers.breaker.engine), so it bounds the added wall clock of
# one packed sample; the name-prior tier runs first and normally lands in ~1 second.
BREAKER_ATTEMPTS_CAP = 20_000
BREAKER_BUDGET_S = 120.0
# breaker hit.json carries key material, so evidence may only be written to a
# local-only path (analysis/master_key_breaker/ is gitignored - verified).
BREAKER_EVIDENCE_DIR = REPO / "analysis" / "master_key_breaker"


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


def _load_breaker():
    """Import the breaker lazily so step0 never fails to import without it."""
    from packers.breaker.engine import break_apk
    return break_apk


def _payload_name(payload: bytes) -> str:
    """On-disk name for a recovered payload; ``kit.zip`` is what enrichment reads."""
    if payload[:4] == b"PK\x03\x04":
        return "kit.zip"
    if payload[:4] == b"dex\n":
        return "_recovered.dex"
    return "_recovered.bin"


def _materialize_payload(apk_path: pathlib.Path, hit: Any) -> bytes | None:
    """Re-decrypt one breaker hit into bytes, or None when it cannot be replayed.

    The engine keeps no payload bytes (it records hashes), but ``hit.scheme`` carries
    every ``Scheme`` field, so ``Scheme(**hit.scheme)`` + ``decrypt`` reproduces the
    plaintext exactly. Nested container children are skipped: enrichment mines the
    top-level ``kit.zip``, and a child adds nothing to it.
    """
    from packers.breaker.blobs import collect_from_zip
    from packers.breaker.schemes import Scheme, decrypt

    if "!" in hit.member:
        return None
    collection = collect_from_zip(apk_path.read_bytes(), depth=0)
    blob = next((b for b in collection.blobs if b.member == hit.member), None)
    if blob is None:
        return None
    return decrypt(Scheme(**hit.scheme), blob.data)


def _materialize_hits(apk_path: pathlib.Path, hits: list[Any]) -> list[tuple[Any, bytes]]:
    """Replay every hit once, analysis only: nothing is ever written to disk."""
    materialized: list[tuple[Any, bytes]] = []
    for hit in hits:
        payload = _materialize_payload(apk_path, hit)
        if payload is not None:
            materialized.append((hit, payload))
    return materialized


def _breaker_second_chance(
    apk_path: pathlib.Path,
    work_dir: pathlib.Path,
    attempts_cap: int = BREAKER_ATTEMPTS_CAP,
    evidence_dir: Any = None,
) -> Dict[str, Any]:
    """One bounded breaker run after the unpack dispatcher failed.

    Returns a report in the unpack shape on a hit, a FAILED report otherwise. Either
    way ``diagnostics`` is the only place the typed outcome (E-KDF-* / E-ENGINE-FAULT)
    is recorded, so a breaker run can never rewrite the ecode unpack produced.
    """
    diagnostics: Dict[str, Any] = {
        "outcome": "E-ENGINE-FAULT",
        "attempts_total": 0,
        "truncated": "none",
        "wall_s": 0.0,
        "recovered": [],
        "detail": None,
    }
    failed = {
        "verdict": "FAILED", "ecode": None, "artifacts": [], "kdf": None,
        "iocs": {}, "family": None, "diagnostics": diagnostics,
    }
    evidence = pathlib.Path(evidence_dir) if evidence_dir is not None else BREAKER_EVIDENCE_DIR
    try:
        result = _load_breaker()(
            apk_path, evidence, attempts_cap=attempts_cap, budget_s=BREAKER_BUDGET_S
        )
    except Exception as e:
        # A breaker fault is a diagnostic, never a pipeline failure (CLI parity).
        diagnostics["detail"] = f"{type(e).__name__}: {e}"[:200]
        logger.warning("MasterKey Step0: breaker second chance faulted: %s", diagnostics["detail"])
        return failed

    diagnostics.update(
        outcome=result.outcome,
        attempts_total=result.attempts_total,
        truncated=result.truncated,
        wall_s=round(result.wall_s, 3),
        recovered=[hit.member for hit in result.hits],
    )

    kit_dir = work_dir / result.sha256[:16]
    artifacts: list[Dict[str, Any]] = []
    kdf: Dict[str, Any] | None = None
    non_zip_written = False
    # Every hit is replayed once up front (analysis only). The write loop below stops
    # at kit.zip, but the evidence must still cover the hits that come after it.
    materialized = _materialize_hits(apk_path, result.hits)
    for hit, payload in materialized:
        name = _payload_name(payload)
        if name != "kit.zip" and non_zip_written:
            # One sample file per kind: a second non-ZIP payload would overwrite the
            # first, leaving two hashes describing one path. Kit still wins below.
            continue
        target = kit_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        artifacts.append({
            "file": str(target),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "validated": hit.validation,
        })
        kdf = {
            "cipher": hit.scheme["cipher"],
            "key_hash": hit.scheme["key_hash"],
            "key_len": hit.scheme["key_len"],
            "iv": hit.scheme["iv"],
            "seed": hit.seed,
            "provenance": hit.scheme["provenance"],
            "validation": hit.validation,
            "key_sha256": hit.key_sha256,
        }
        if name == "kit.zip":
            break  # a recovered kit is what the pipeline enriches from
        non_zip_written = True

    if not artifacts:
        return failed
    evidence = collect_payload_evidence([
        payload for hit, payload in materialized if hit.validation.startswith("zip")
    ])
    report: Dict[str, Any] = {
        "verdict": "RECOVERED", "ecode": None, "artifacts": artifacts, "kdf": kdf,
        "iocs": {}, "family": None, "diagnostics": diagnostics,
    }
    # Only ZIP-validated payloads are analysed, and only a recovery that analysed
    # something carries evidence.
    if _analysed_only(evidence):
        report["recovered_evidence"] = evidence
    return report


def _analysed_only(evidence: dict) -> Optional[dict]:
    """Evidence reaches the report only when it analysed at least one payload."""
    return evidence if evidence["payloads"] > 0 else None


def _evidence_from_artifacts(artifacts: list) -> Optional[dict]:
    """Dispatcher recoveries are not in memory: read the written artifacts back."""
    payloads = []
    for artifact in artifacts:
        path = artifact.get("file", "")
        try:
            payloads.append(pathlib.Path(path).read_bytes())
        except OSError as exc:
            logger.warning("payload evidence skipped %s: %s", path, exc)
    return _analysed_only(collect_payload_evidence(payloads))


def run_master_key_preprocess(
    apk_path: str, work_dir: str, breaker_attempts_cap: int = BREAKER_ATTEMPTS_CAP
) -> Dict[str, Any]:
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
        "breaker": {...}|None,  # second chance diagnostics: typed outcome, never key material
        "recovered_evidence": {...}|None,  # additive recovered-payload evidence from a breaker ZIP recovery; never key material
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
            "breaker": None,
            "triage_report": triage_report,
        }

    # Packed → attempt Master Key unpack (myg0N KDF brute + oracle)
    unpack_report = _attempt_unpack(apk, wd / "master_key", triage_report)
    # Second chance: the breaker owns at-rest asset blobs (a superset of the myg0N
    # brute the dispatcher runs). It runs only when the dispatcher failed, and a miss
    # leaves every field below exactly as unpack produced it - the breach, if any, is
    # reported in "breaker", never in "ecode".
    breaker_diagnostics = None
    effective = unpack_report
    if unpack_report.get("verdict") != "RECOVERED":
        breaker_report = _breaker_second_chance(
            apk, wd / "master_key", attempts_cap=breaker_attempts_cap
        )
        breaker_diagnostics = breaker_report["diagnostics"]
        if breaker_report["verdict"] == "RECOVERED" and breaker_report["artifacts"]:
            effective = breaker_report
    recovered_by_breaker = effective is not unpack_report
    ecode = effective.get("ecode")
    is_e_coded = bool(ecode and ecode.lower() in E_CODE_CATCH_ALLS)
    # Also handle E-codes with parentheses: E-NATIVE-NOENTRY(Ijiami) etc
    if ecode and not is_e_coded:
        base = ecode.split("(")[0].strip().lower()
        is_e_coded = base in E_CODE_CATCH_ALLS

    should_enrich = effective.get("verdict") == "RECOVERED" and bool(effective.get("artifacts"))

    # Map to KT taxonomy for reporting
    family = effective.get("family") or "Unknown"
    if recovered_by_breaker:
        recovered_kdf = effective.get("kdf") or {}
        taxonomy = (
            "at-rest asset blob recovered on second chance "
            f"({recovered_kdf.get('cipher')}/{recovered_kdf.get('provenance')}, "
            f"seed={recovered_kdf.get('seed')}) - master key breaker"
        )
    elif should_enrich:
        taxonomy = f"myg0N kit (custom, beaten) - {family} (MASTER_KEY §2-5, FULL_KT §4)"
    elif ecode == "E-NATIVE-NOENTRY":
        taxonomy = f"Commercial VMP {family} (Ijiami/Bangcle/360Jiagu - E-coded expected per MASTER_KEY §16, KT §4)"
    elif ecode == "E-JAVA-RUNTIME-DELIVERY":
        taxonomy = "Java injected repack (so_count:0) - runtime delivery, take Java path (MASTER_KEY §2.5, KT §4)"
    elif is_e_coded:
        taxonomy = f"E-coded {ecode} - documented limit, not model failure (PENDRIVE_MASTER_KEY_INTEL.md)"
    else:
        taxonomy = f"Unpacked attempt failed {ecode or 'no ecode'} - needs manual review"

    report: Dict[str, Any] = {
        "triage_verdict": verdict,
        "triage_confidence": confidence,
        "route": unpack_report.get("route", "NATIVE"),
        "verdict": effective.get("verdict", "FAILED"),
        "ecode": ecode,
        "is_e_coded": is_e_coded,
        "artifacts": effective.get("artifacts", []),
        "kdf": effective.get("kdf"),
        "iocs": effective.get("iocs", {}),
        "family_sniff": family,
        "kt_taxonomy": taxonomy,
        "should_enrich_strings": should_enrich,
        "breaker": breaker_diagnostics,
        "triage_report": triage_report,
        "unpack_report": unpack_report,
    }
    # Evidence is additive: a breaker recovery carries its own, a dispatcher recovery
    # is analysed from the artifacts it wrote.
    evidence = effective.get("recovered_evidence")
    if not recovered_by_breaker and effective.get("verdict") == "RECOVERED":
        evidence = _evidence_from_artifacts(effective.get("artifacts", []))
    if evidence:
        report["recovered_evidence"] = evidence
    return report


def _payload_blob(path: pathlib.Path) -> bytes:
    """Bytes whose strings are mined: a bare DEX as-is, a ZIP through its .dex/.apk members."""
    import io
    data = path.read_bytes()
    if data[:4] == b"dex\n":
        return data
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return b"".join(zf.read(n) for n in zf.namelist() if n.endswith(".dex") or n.endswith(".apk"))[:20_000_000]


def enrich_strings_with_recovered(strings_result: Dict[str, Any], master_key: Dict[str, Any]) -> Dict[str, Any]:
    """
    If Master Key recovered a kit.zip/installer.dex, extract its strings and
    merge into strings_result categories so downstream C2/family_id see
    decrypted strings (rescues Opfake/FakeInstaller opaque misses).

    Called from pipeline.py after Step2 if master_key["should_enrich_strings"].
    """
    if not master_key.get("should_enrich_strings"):
        return strings_result
    import re
    blobs = []
    for art in master_key.get("artifacts") or []:
        path = pathlib.Path(art.get("file", ""))
        try:
            blobs.append(_payload_blob(path))
        except Exception as e:  # one unreadable payload must not drop the others
            logger.warning("MasterKey enrich skipped %s: %s", path, e)
    if not blobs:
        return strings_result
    try:
        # Extract printable strings 4-120 chars, same TOKEN_RE as mine_family_knowledge.py:43
        raw_strings = [s for blob in blobs for s in re.findall(rb"[A-Za-z0-9_./: @\[\]\(\)\-#&%]{4,120}", blob)]
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
        logger.info("MasterKey enrich: +%d strings from %d payload(s) (now %d)", len(decoded), len(blobs), strings_result["total_strings"])
    except Exception as e:
        logger.warning("MasterKey enrich failed: %s", e)
    return strings_result
