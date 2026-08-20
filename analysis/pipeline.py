"""
DroidForensix Analysis Pipeline Orchestrator

Coordinates the 9-step analysis pipeline:
1. APK Extraction
2. String Enumeration
3. Encoding Detection
4. Payload Decoding
5. C2 Extraction
6. Threat Chain Correlation
7. Obfuscation Analysis
8. LLM Assessment
9. Family Identification

Emits unified progress events for real-time frontend updates.
"""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from backend.config import settings
from analysis.step1_apk_extraction import extract_apk
from analysis.step2_string_enumeration import enumerate_strings
from analysis.step3_encoding_detection import detect_encoding
from analysis.step4_decoding import decode_payloads
from analysis.step5_c2_extraction import extract_c2_infrastructure
from analysis.step6_correlation import build_threat_chains
from analysis.step7_llm_assessment import assess_with_llm
from analysis.step8_obfuscation_analysis import analyze_obfuscation
from analysis.step9_post_process import post_process_result
from analysis.hardcoded_secrets import analyze_hardcoded_secrets
from analysis.step10_binary_packing import detect_binary_packing
from analysis.step11_string_clustering import cluster_high_entropy_strings
from analysis.step12_reflective_tracing import find_reflective_calls
from analysis.step13_native_elf_analysis import analyze_native_libraries_from_apk
from analysis.step14_network_protocol_analysis import analyze_network_protocols
from analysis.step15_reflective_permission_correlation import correlate_reflective_permission_usage
from analysis.step16_certificate_analysis import analyze_certificate
from analysis.step17_family_clustering import cluster_family
from analysis.step18_threat_synthesis import synthesize_threat_profile
from backend.family_id import identify_family
from backend.dissection import APKDissector


class PipelineError(Exception):
    """Raised when pipeline execution fails."""
    pass


# Event emitter callback type: function(event_type, data) -> None
EventEmitter = Optional[Callable[[str, dict], None]]

logger = logging.getLogger(__name__)

TOTAL_STEPS = 18

STEP_NAMES = {
    1: "APK Extraction",
    2: "String Enumeration",
    3: "Encoding Detection",
    4: "Payload Decoding",
    5: "C2 Extraction",
    6: "Threat Chain Correlation",
    7: "Obfuscation Analysis",
    8: "LLM Assessment",
    9: "Family Identification",
    10: "Binary Packing Detection",
    11: "String Entropy & Clustering",
    12: "Reflective Method Tracing",
    13: "Native ELF Analysis",
    14: "Network Protocol Analysis",
    15: "Reflective Permission Correlation",
    16: "Certificate Analysis",
    17: "Family Clustering",
    18: "Threat Synthesis",
}

STEP_TIMEOUTS = {
    1: 180, 2: 180, 3: 180, 4: 90, 5: 450,
    6: 90, 7: 270, 8: 900, 9: 450,
    10: 90, 11: 90, 12: 90, 13: 90, 14: 90,
    15: 45, 16: 45, 17: 45, 18: 45,
}


class TimeoutError(Exception):
    pass


class InterruptableThread(threading.Thread):
    def __init__(self, target, args=(), kwargs=None):
        super().__init__()
        self.target = target
        self.args = args
        self.kwargs = kwargs or {}
        self.result = None
        self.exception = None

    def run(self):
        try:
            self.result = self.target(*self.args, **self.kwargs)
        except Exception as e:
            self.exception = e


def run_with_timeout(fn, args, timeout, step_name):
    thread = InterruptableThread(target=fn, args=args)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError(f"{step_name} timed out after {timeout}s")
    if thread.exception:
        raise thread.exception
    return thread.result


def _validate_step_input(step_name, data, required_keys):
    missing = [k for k in required_keys if k not in data]
    if missing:
        raise PipelineError(f"{step_name}: missing required keys: {missing}")


def _emit(emitter: EventEmitter, event_type: str, data: dict):
    """Emit an event if emitter is provided."""
    if emitter:
        try:
            emitter(event_type, data)
        except Exception:
            logger.debug("Event emitter failed for %s", event_type)


def _estimate_remaining_eta(apk_size: int, remaining_steps: int) -> float:
    """
    Estimate remaining analysis time based on APK size.
    Buckets:
    - < 1MB: ~2.0s per step
    - 1-10MB: ~3.5s per step
    - > 10MB: ~5.0s per step
    """
    if apk_size < 1_000_000:      # < 1MB
        avg_per_step = 2.0
    elif apk_size < 10_000_000:   # 1-10MB
        avg_per_step = 3.5
    else:                          # > 10MB
        avg_per_step = 5.0
    return remaining_steps * avg_per_step


def _run_step(step_num: int, sample_id: str, apk_size: int,
              global_start: float, emitter: EventEmitter,
              work_dir: str, func, *args, **kwargs):
    """
    Run a pipeline step, emit step_started/step_completed, and return result.
    """
    step_name = STEP_NAMES[step_num]
    elapsed_before = time.time() - global_start

    _emit(emitter, "step_started", {
        "sample_id": sample_id,
        "step_number": step_num,
        "step_name": step_name,
        "elapsed_seconds": round(elapsed_before, 3),
    })

    step_start = time.time()
    timeout = STEP_TIMEOUTS.get(step_num, 120)
    try:
        result = run_with_timeout(func, args, timeout, step_name)
    except TimeoutError:
        _emit(emitter, "error", {
            "sample_id": sample_id,
            "step_number": step_num,
            "step_name": step_name,
            "error_message": f"Step {step_num} ({step_name}) timed out after {timeout}s",
            "severity": "high",
        })
        raise PipelineError(
            f"Step {step_num} ({step_name}) timed out after {timeout}s.\n\n"
            f"Options:\n"
            f"  1. Increase timeout for this step in STEP_TIMEOUTS (analysis/pipeline.py)\n"
            f"  2. If step {step_num} repeatedly times out, the APK may be too large or obfuscated\n"
            f"  3. Re-run with --skip-step={step_num} if this step is optional"
        )
    except Exception as e:
        _emit(emitter, "error", {
            "sample_id": sample_id,
            "step_number": step_num,
            "step_name": step_name,
            "error_message": f"Step {step_num} ({step_name}): {e}",
            "severity": "high",
        })
        raise PipelineError(
            f"Step {step_num} ({step_name}) failed: {type(e).__name__}: {e}\n\n"
            f"Check:\n"
            f"  1. Is the APK valid? Try: python -m analysis.pipeline <apk> --skip-step={step_num}\n"
            f"  2. Is there enough disk space? Pipeline requires ~500MB temporary space\n"
            f"  3. For configuration issues, check backend/config.py"
        )

    step_duration = time.time() - step_start
    elapsed = time.time() - global_start
    remaining_steps = TOTAL_STEPS - step_num
    remaining_eta = _estimate_remaining_eta(apk_size, remaining_steps)
    progress_pct = int((step_num / TOTAL_STEPS) * 100)

    _emit(emitter, "step_completed", {
        "sample_id": sample_id,
        "step_number": step_num,
        "step_name": step_name,
        "duration_seconds": round(step_duration, 3),
        "elapsed_seconds": round(elapsed, 3),
        "remaining_steps": remaining_steps,
        "remaining_eta_seconds": round(remaining_eta, 3),
        "step_status": "success",
        "progress_percent": progress_pct,
    })

    return result, round(step_duration, 3)


def run_pipeline(apk_path: str, work_dir: Optional[str] = None,
                 event_emitter: EventEmitter = None,
                 pipeline_timeout: int = 600) -> dict:
    """
    Run the full analysis pipeline on an APK.

    Args:
        apk_path: Path to APK file.
        work_dir: Working directory for intermediate outputs. Defaults to
            settings.WORK_DIR.
        event_emitter: Optional callback for emitting events.
        pipeline_timeout: Maximum total pipeline runtime in seconds.

    Returns:
        dict with full analysis results.
    """
    work_dir = str(work_dir) if work_dir else str(settings.WORK_DIR)
    global_start = time.time()
    timeline = {}
    apk_size = Path(apk_path).stat().st_size

    # Step 1: APK Extraction (special: sample_id unknown until finished)
    step_num = 1
    step_name = STEP_NAMES[step_num]
    _emit(event_emitter, "step_started", {
        "sample_id": None,
        "step_number": step_num,
        "step_name": step_name,
        "elapsed_seconds": 0.0,
    })

    step_start = time.time()
    try:
        extraction = extract_apk(apk_path, work_dir)
    except Exception as e:
        _emit(event_emitter, "error", {
            "sample_id": None,
            "step_number": step_num,
            "step_name": step_name,
            "error_message": f"Step 1 (APK Extraction): {e}",
            "severity": "high",
        })
        raise PipelineError(
            f"Step 1 (APK Extraction) failed: {type(e).__name__}: {e}\n\n"
            f"Common fixes:\n"
            f"  1. Verify the file exists and is a valid APK: ls -la {apk_path}\n"
            f"  2. Check required tools: apktool, androguard\n"
            f"  3. Ensure WORK_DIR in backend/config.py is writable\n"
            f"  4. Try with --use-androguard-only to skip external tools"
        )

    step_duration = time.time() - step_start
    timeline["step1"] = round(step_duration, 3)
    sample_id = extraction["sample_id"]
    elapsed = time.time() - global_start
    remaining_steps = TOTAL_STEPS - step_num
    remaining_eta = _estimate_remaining_eta(apk_size, remaining_steps)
    progress_pct = int((step_num / TOTAL_STEPS) * 100)

    _emit(event_emitter, "analysis_started", {
        "sample_id": sample_id,
        "sample_name": extraction["sample_name"],
        "file_size_bytes": apk_size,
        "total_steps": TOTAL_STEPS,
        "predicted_eta_seconds": round(remaining_eta, 3),
    })

    _emit(event_emitter, "step_completed", {
        "sample_id": sample_id,
        "step_number": step_num,
        "step_name": step_name,
        "duration_seconds": round(step_duration, 3),
        "elapsed_seconds": round(elapsed, 3),
        "remaining_steps": remaining_steps,
        "remaining_eta_seconds": round(remaining_eta, 3),
        "step_status": "success",
        "progress_percent": progress_pct,
    })

    _emit(event_emitter, "metric_updated", {
        "sample_id": sample_id,
        "metric_name": "apktool_success",
        "metric_value": 1 if extraction["apktool_success"] else 0,
        "step_context": step_num,
    })

    elapsed = time.time() - global_start
    if elapsed > pipeline_timeout:
        raise PipelineError(
            f"Pipeline timed out after {elapsed:.0f}s (limit: {pipeline_timeout}s).\n\n"
            f"Options:\n"
            f"  1. Increase pipeline_timeout (default 600s) in run_pipeline() call\n"
            f"  2. APK is very large — consider running individual steps manually\n"
            f"  3. APK is very large — consider running individual steps manually"
        )

    _validate_step_input("Step 2 input", extraction, ["sample_id", "package_name", "apktool_output_dir"])

    # Step 2: String Enumeration
    strings_result, timeline["step2"] = _run_step(
        2, sample_id, apk_size, global_start, event_emitter, work_dir,
        enumerate_strings, extraction
    )
    _emit(event_emitter, "metric_updated", {
        "sample_id": sample_id,
        "metric_name": "string_count",
        "metric_value": strings_result.get("total_strings", 0),
        "step_context": 2,
    })

    if time.time() - global_start > pipeline_timeout:
        raise PipelineError(
            f"Pipeline timed out after {time.time() - global_start:.0f}s (limit: {pipeline_timeout}s).\n\n"
            f"Options:\n"
            f"  1. Increase pipeline_timeout (default 600s) in run_pipeline() call\n"
            f"  2. APK is very large — run individual steps instead\n"
            f"  3. APK is very large — run individual steps instead"
        )

    _validate_step_input("Step 3 input", strings_result, ["total_strings", "categories"])

    # Hardcoded Secrets Scan (inline after string enumeration)
    secrets_result = analyze_hardcoded_secrets(strings_result)
    _emit(event_emitter, "metric_updated", {
        "sample_id": sample_id,
        "metric_name": "hardcoded_secrets_count",
        "metric_value": secrets_result.get("secret_risk", {}).get("total_secrets", 0),
        "step_context": 2,
    })
    logger.info("Hardcoded secrets: %d", secrets_result.get("secret_risk", {}).get("total_secrets", 0))

    # Step 3: Encoding Detection
    encodings_result, timeline["step3"] = _run_step(
        3, sample_id, apk_size, global_start, event_emitter, work_dir,
        detect_encoding, strings_result
    )
    _emit(event_emitter, "metric_updated", {
        "sample_id": sample_id,
        "metric_name": "encoding_count",
        "metric_value": len(encodings_result.get("encodings", [])),
        "step_context": 3,
    })

    if time.time() - global_start > pipeline_timeout:
        raise PipelineError(
            f"Pipeline timed out after {time.time() - global_start:.0f}s (limit: {pipeline_timeout}s).\n\n"
            f"Options:\n"
            f"  1. Increase pipeline_timeout (default 600s) in run_pipeline() call\n"
            f"  2. APK is very large — run individual steps instead\n"
            f"  3. APK is very large — run individual steps instead"
        )

    _validate_step_input("Step 4 input", encodings_result, ["encodings"])

    # Step 4: Payload Decoding
    payloads_result, timeline["step4"] = _run_step(
        4, sample_id, apk_size, global_start, event_emitter, work_dir,
        decode_payloads, encodings_result
    )
    _emit(event_emitter, "metric_updated", {
        "sample_id": sample_id,
        "metric_name": "payload_count",
        "metric_value": len(payloads_result.get("payloads", [])),
        "step_context": 4,
    })

    if time.time() - global_start > pipeline_timeout:
        raise PipelineError(
            f"Pipeline timed out after {time.time() - global_start:.0f}s (limit: {pipeline_timeout}s).\n\n"
            f"Options:\n"
            f"  1. Increase pipeline_timeout (default 600s) in run_pipeline() call\n"
            f"  2. APK is very large — run individual steps instead\n"
            f"  3. APK is very large — run individual steps instead"
        )

    _validate_step_input("Step 5 input", payloads_result, ["payloads"])

    # Step 5: C2 Extraction
    c2_result, timeline["step5"] = _run_step(
        5, sample_id, apk_size, global_start, event_emitter, work_dir,
        extract_c2_infrastructure, payloads_result, strings_result
    )
    _emit(event_emitter, "metric_updated", {
        "sample_id": sample_id,
        "metric_name": "c2_count",
        "metric_value": len(c2_result.get("c2_infrastructure", [])),
        "step_context": 5,
    })

    if time.time() - global_start > pipeline_timeout:
        raise PipelineError(
            f"Pipeline timed out after {time.time() - global_start:.0f}s (limit: {pipeline_timeout}s).\n\n"
            f"Options:\n"
            f"  1. Increase pipeline_timeout (default 600s) in run_pipeline() call\n"
            f"  2. APK is very large — run individual steps instead\n"
            f"  3. APK is very large — run individual steps instead"
        )

    _validate_step_input("Step 6 input", c2_result, ["c2_infrastructure"])

    # Step 6: Threat Chain Correlation
    chains_result, timeline["step6"] = _run_step(
        6, sample_id, apk_size, global_start, event_emitter, work_dir,
        build_threat_chains, encodings_result, payloads_result, c2_result
    )
    _emit(event_emitter, "metric_updated", {
        "sample_id": sample_id,
        "metric_name": "threat_chain_count",
        "metric_value": len(chains_result.get("threat_chains", [])),
        "step_context": 6,
    })

    if time.time() - global_start > pipeline_timeout:
        raise PipelineError(
            f"Pipeline timed out after {time.time() - global_start:.0f}s (limit: {pipeline_timeout}s).\n\n"
            f"Options:\n"
            f"  1. Increase pipeline_timeout (default 600s) in run_pipeline() call\n"
            f"  2. APK is very large — run individual steps instead\n"
            f"  3. APK is very large — run individual steps instead"
        )

    _validate_step_input("Step 7 input", chains_result, ["threat_chains"])

    # Step 7: Obfuscation Analysis
    def obfuscation_with_fallback():
        try:
            return analyze_obfuscation(apk_path, work_dir, sample_id=sample_id)
        except FileNotFoundError as e:
            return {
                "sample_id": sample_id,
                "obfuscation_score": 0.0,
                "obfuscation_level": "low",
                "indicators": {},
                "dex_entropy": [],
                "native_library_artifacts": [],
                "notes": [f"Obfuscation analysis skipped: {e} (file not found)"],
            }
        except ImportError as e:
            return {
                "sample_id": sample_id,
                "obfuscation_score": 0.0,
                "obfuscation_level": "low",
                "indicators": {},
                "dex_entropy": [],
                "native_library_artifacts": [],
                "notes": [f"Obfuscation analysis skipped: missing dependency ({e.name}). Install: pip install {e.name}"],
            }
        except Exception as e:
            return {
                "sample_id": sample_id,
                "obfuscation_score": 0.0,
                "obfuscation_level": "low",
                "indicators": {},
                "dex_entropy": [],
                "native_library_artifacts": [],
                "notes": [f"Obfuscation analysis failed: {type(e).__name__}: {e}"],
            }

    obfuscation_result, timeline["step7"] = _run_step(
        7, sample_id, apk_size, global_start, event_emitter, work_dir,
        obfuscation_with_fallback
    )
    _emit(event_emitter, "metric_updated", {
        "sample_id": sample_id,
        "metric_name": "obfuscation_score",
        "metric_value": obfuscation_result.get("obfuscation_score", 0),
        "step_context": 7,
    })

    # Step 8: LLM Assessment
    def llm_with_fallback():
        try:
            return assess_with_llm(chains_result, c2_result, obfuscation_result, secrets_result)
        except (ConnectionError, TimeoutError) as e:
            llm_error = (
                f"LLM connection failed: {e}\n\n"
                f"Options:\n"
                f"  1. Check Ollama is running: ollama list\n"
                f"  2. Start Ollama: ollama serve\n"
                f"  3. Set OLLAMA_HOST if running remotely\n"
                f"  4. Re-run with --heuristic-only to skip LLM"
            )
            return {
                "severity": "low",
                "risk_score": 0,
                "narrative": llm_error,
                "primary_threat": "other",
                "recommended_actions": ["Start Ollama and retry", "Or re-run with --heuristic-only"],
                "confidence": 0.0,
            }
        except Exception as e:
            return {
                "severity": "low",
                "risk_score": 0,
                "narrative": f"LLM assessment failed: {type(e).__name__}: {e}",
                "primary_threat": "other",
                "recommended_actions": ["Check Ollama connection", "Re-run with --heuristic-only"],
                "confidence": 0.0,
            }

    llm_assessment, timeline["step8"] = _run_step(
        8, sample_id, apk_size, global_start, event_emitter, work_dir,
        llm_with_fallback
    )

    # Build result dict
    manifest = extraction.get("manifest_info", {}) or {}
    result = {
        "sample_id": sample_id,
        "metadata": {
            "sample_name": extraction["sample_name"],
            "file_size_bytes": extraction["file_size_bytes"],
            "sha256": extraction["sha256"],
            "md5": extraction["md5"],
            "package_name": extraction["package_name"],
            "package": extraction["package_name"],
            "apk_path": str(apk_path),
        },
        "extraction": {
            "apktool_success": extraction["apktool_success"],
            "errors": extraction.get("errors", []),
            "native_libs_found": extraction["native_libs_found"],
            "decompiled_classes": extraction["decompiled_classes"],
            "crypter_stub": extraction.get("crypter_stub", False),
            "extraction_status": extraction.get("extraction_status", "ok"),
            "total_strings_extracted": strings_result["total_strings"],
        },
        "manifest": {
            "version_name": manifest.get("version_name"),
            "version_code": manifest.get("version_code"),
            "target_sdk_version": manifest.get("target_sdk_version"),
            "min_sdk_version": manifest.get("min_sdk_version"),
            "uses_permissions": manifest.get("uses_permissions", []),
        },
        "strings": strings_result["categories"],
        "hardcoded_secrets": secrets_result["hardcoded_secrets"],
        "secret_risk": secrets_result["secret_risk"],
        "encodings": encodings_result["encodings"],
        "payloads": payloads_result["payloads"],
        "c2_infrastructure": c2_result["c2_infrastructure"],
        "threat_chains": chains_result["threat_chains"],
        "llm_assessment": llm_assessment,
        "obfuscation_analysis": obfuscation_result,
        "timeline": timeline,
    }

    # Step 9a: Post-processing sanity corrections
    try:
        result = post_process_result(result)
    except Exception as e:
        _emit(event_emitter, "error", {
            "sample_id": sample_id,
            "step_number": 9,
            "step_name": "Post-processing",
            "error_message": f"Post-processing failed: {e}",
            "severity": "medium",
        })

    # Step 9b: Family identification (deterministic + optional LLM)
    def family_with_fallback():
        try:
            return identify_family(sample_id, result, use_llm=True, use_cache=True)
        except Exception as e:
            return {
                "family": "unknown",
                "confidence": 0.0,
                "method": "error",
                "reasoning": str(e),
                "candidates": [],
            }

    family_result, timeline["step9"] = _run_step(
        9, sample_id, apk_size, global_start, event_emitter, work_dir,
        family_with_fallback
    )
    result["family_identification"] = family_result

    # Step 10: Binary Packing Detection
    packing_result, timeline["step10"] = _run_step(
        10, sample_id, apk_size, global_start, event_emitter, work_dir,
        detect_binary_packing, {"apk_path": apk_path}
    )

    # Step 11: String Entropy & Clustering
    all_strings = []
    for cat in strings_result.get("categories", {}).values():
        if isinstance(cat, list):
            all_strings.extend(cat)
        elif isinstance(cat, dict):
            all_strings.extend(cat.get("values", cat.get("strings", [])))
    string_cluster_result, timeline["step11"] = _run_step(
        11, sample_id, apk_size, global_start, event_emitter, work_dir,
        cluster_high_entropy_strings, all_strings
    )

    # Step 12: Reflective Method Tracing
    reflective_result, timeline["step12"] = _run_step(
        12, sample_id, apk_size, global_start, event_emitter, work_dir,
        find_reflective_calls, extraction
    )

    # Step 13: Native ELF Analysis
    native_elf_result, timeline["step13"] = _run_step(
        13, sample_id, apk_size, global_start, event_emitter, work_dir,
        analyze_native_libraries_from_apk, apk_path, extraction.get("apktool_output_dir")
    )

    # Step 14: Network Protocol Analysis
    network_result, timeline["step14"] = _run_step(
        14, sample_id, apk_size, global_start, event_emitter, work_dir,
        analyze_network_protocols, all_strings
    )

    # Step 15: Reflective Permission Correlation
    manifest_perms = manifest.get("uses_permissions", [])
    reflective_calls_list = reflective_result.get("reflective_calls", [])
    permission_result, timeline["step15"] = _run_step(
        15, sample_id, apk_size, global_start, event_emitter, work_dir,
        correlate_reflective_permission_usage, manifest_perms, reflective_calls_list
    )

    # Step 16: Certificate Analysis
    cert_result, timeline["step16"] = _run_step(
        16, sample_id, apk_size, global_start, event_emitter, work_dir,
        analyze_certificate, apk_path
    )

    # Step 17: Family Clustering (cross-sample)
    family_cluster_result, timeline["step17"] = _run_step(
        17, sample_id, apk_size, global_start, event_emitter, work_dir,
        cluster_family, sample_id, extraction, result
    )

    # Step 18: Threat Synthesis
    synthesis_context = {
        "packing": packing_result,
        "reflective_tracing": reflective_result,
        "permissions": permission_result,
        "network": network_result,
        "strings": string_cluster_result,
        "native_elf": native_elf_result,
        "certificate": cert_result,
        "family_clustering": family_cluster_result,
    }
    synthesis_result, timeline["step18"] = _run_step(
        18, sample_id, apk_size, global_start, event_emitter, work_dir,
        synthesize_threat_profile, synthesis_context
    )

    # Save structural APK dissection (fast, cached for dashboard)
    try:
        dissector = APKDissector(apk_path, work_dir=work_dir)
        dissection_data = dissector.dissect()
        dissection_path = Path(work_dir) / sample_id / "dissection.json"
        with open(dissection_path, "w", encoding="utf-8") as f:
            json.dump(dissection_data, f, indent=2, default=str)
    except Exception as e:
        _emit(event_emitter, "error", {
            "sample_id": sample_id,
            "step_number": 9,
            "step_name": "Dissection",
            "error_message": f"Dissection save failed: {e}",
            "severity": "low",
        })

    duration = round(time.time() - global_start, 3)
    timeline["total"] = duration

    # Merge step 10-18 results
    result.update({
        "binary_packing": packing_result,
        "string_clustering": string_cluster_result,
        "reflective_tracing": reflective_result,
        "native_elf_analysis": native_elf_result,
        "network_protocols": network_result,
        "permission_correlation": permission_result,
        "certificate_analysis": cert_result,
        "family_clustering": family_cluster_result,
        "threat_synthesis": synthesis_result,
    })

    # Flag for manual review: family matched but LLM risk is low
    family_name = (result.get("family_identification") or {}).get("family", "unknown")
    risk_score = (result.get("llm_assessment") or {}).get("risk_score", 0)
    llm_method = (result.get("llm_assessment") or {}).get("method", "")
    if family_name != "unknown" and risk_score < 50 and llm_method == "heuristic_benign_skip":
        result["needs_manual_review"] = True
        result["manual_review_reason"] = f"Family={family_name} but risk_score={risk_score} (benign verdict skipped LLM)"
    else:
        result["needs_manual_review"] = result.get("llm_assessment", {}).get("needs_manual_review", False)
        if result["needs_manual_review"]:
            result["manual_review_reason"] = "Suspicious static features (reflection + dynamic loading / packing / low-conf C2)"

    # Save full result (strip lone surrogates so Pydantic serialization never fails)
    from backend.transformers import _strip_surrogates
    result = _strip_surrogates(result)

    result_path = Path(work_dir) / sample_id / "pipeline_result.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    _emit(event_emitter, "analysis_complete", {
        "sample_id": sample_id,
        "total_duration_seconds": duration,
        "step_timings": {
            "step1_extraction": timeline.get("step1", 0),
            "step2_strings": timeline.get("step2", 0),
            "step3_encoding": timeline.get("step3", 0),
            "step4_decode": timeline.get("step4", 0),
            "step5_c2": timeline.get("step5", 0),
            "step6_chains": timeline.get("step6", 0),
            "step7_obfuscation": timeline.get("step7", 0),
            "step8_llm": timeline.get("step8", 0),
            "step9_family": timeline.get("step9", 0),
            "step10_packing": timeline.get("step10", 0),
            "step11_strings": timeline.get("step11", 0),
            "step12_reflective": timeline.get("step12", 0),
            "step13_elf": timeline.get("step13", 0),
            "step14_network": timeline.get("step14", 0),
            "step15_permissions": timeline.get("step15", 0),
            "step16_certificate": timeline.get("step16", 0),
            "step17_clustering": timeline.get("step17", 0),
            "step18_synthesis": timeline.get("step18", 0),
        },
        "final_verdict": result.get("llm_assessment", {}).get("severity", "unknown"),
        "risk_score": result.get("llm_assessment", {}).get("risk_score", 0),
    })

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python pipeline.py <apk_path> [work_dir]")
        sys.exit(1)
    apk = sys.argv[1]
    work = sys.argv[2] if len(sys.argv) > 2 else str(settings.WORK_DIR)

    def print_event(event_type, data):
        print(f"[EVENT] {event_type}: {json.dumps(data, default=str)[:150]}")

    result = run_pipeline(apk, work, event_emitter=print_event)
    print(json.dumps(result, indent=2, default=str))
