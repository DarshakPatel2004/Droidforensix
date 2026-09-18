"""
Step 7: LLM-Powered Assessment

Sends threat chains to an LLM (NVIDIA NIM by default) for severity assessment.
Validates JSON output, retries on failure, and provides rule-based fallback.

Environment variables:
    NVIDIA_NIM_API_KEY  - NVIDIA NIM API key (required unless Ollama is used)
    NVIDIA_NIM_MODEL    - Model ID on NVIDIA NIM (default: deepseek-ai/deepseek-v4-pro)
    NVIDIA_NIM_BASE_URL - Endpoint base URL (default: https://integrate.api.nvidia.com/v1)

Fallback to local Ollama is still supported:
    OLLAMA_HOST         - Ollama host (default: http://localhost:11434)
    OLLAMA_MODEL        - Ollama model (default: mistral:7b-instruct-q4_K_M)
"""

import json
import os
import re
import time
import urllib.parse
import socket
from pathlib import Path
from typing import Dict, Any, Optional
from collections import Counter

import requests

from backend.config import settings


class LLMAssessmentError(Exception):
    """Raised when LLM assessment fails."""
    pass


DEFAULT_FALLBACK = {
    "severity": "low",
    "risk_score": 25,
    "narrative": "LLM assessment unavailable. Fallback assessment based on indicator count.",
    "primary_threat": "other",
    "recommended_actions": ["Review extracted indicators manually", "Re-run analysis when LLM is available"],
    "confidence": 0.5,
}


SYSTEM_PROMPT = """/no_think

You are an expert Android security analyst writing a forensic investigation report. Your task is to assess a mobile application sample based on the provided threat chains, C2 extraction results, and static analysis indicators.

CRITICAL — You are NOT required to find malware. If the evidence does not support a malware classification, say so. False positives are harmful.

Output valid JSON only, no markdown, no explanation, no code blocks:

{"severity": "critical|high|medium|low", "risk_score": 0-100, "narrative": "3-5 sentence forensic narrative", "primary_threat": "c2_exfiltration|ransomware|spyware|banking_trojan|adware|dropper|other", "threat_indicators": ["indicator1", "indicator2"], "recommended_actions": ["action1", "action2"], "confidence": 0.0-1.0}

SEVERITY SCALE
- critical (80-100): Active public C2 with confirmed exfiltration, ransomware, or banking trojan behavior
- high (60-79): Confirmed C2 with data exfiltration capability — NOT justified by permissions or crypto API usage alone
- medium (30-59): Suspicious indicators present but NO confirmed C2. Default for apps with encodings/permissions/obfuscation but no C2
- low (0-29): Few or no malicious indicators. Default for apps with standard library usage

CRITICAL — FALSE POSITIVE PREVENTION
- No C2 indicators extracted → severity MUST be medium or low, risk_score MUST be ≤ 50
- Dangerous permissions (CAMERA, LOCATION, PHONE_STATE, etc.) alone do NOT make malware — most legitimate apps declare them
- Crypto/SSL/hashing APIs alone do NOT make malware — standard Android libraries use these
- If the narrative mentions C2 but no C2 was extracted, you are hallucinating. STOP. Only describe what was actually observed.
- A high obfuscation score with zero C2 and zero threat chains does NOT justify high severity. It means the app uses obfuscation.

HARDCODED SECRETS
- If hardcoded secrets findings are provided in the analysis context, include them in your assessment.
- High-criticality secrets (private keys, cloud credentials, auth tokens) increase the app's risk profile even without active C2 — they indicate credential theft capability or insecure data storage.
- A private key embedded in the APK is CRITICAL severity regardless of other findings — it means signing credentials or encryption keys are exposed.
- Hardcoded API keys for cloud services (AWS, Google, Firebase) indicate potential data exfiltration or unauthorized service access.
- Do NOT flag developer debug keys or well-known test credentials as malicious — use judgment based on context.

CONCRETE EVIDENCE REQUIREMENTS
- threat_indicators: List specific technical artifacts actually found (e.g. "XOR-encoded strings in resources", "Reflection API usage", "Hardcoded AWS credentials"), NOT generic labels
- recommended_actions: Specific to findings, not generic advice like "update antivirus"
- narrative: Name specific encoding types, permission categories, secret types, and techniques observed. Do NOT write generic malware descriptions
- Do NOT include actual malicious URLs or payloads in the narrative — describe indirectly

{antml:thinking_mode}auto{/antml:thinking_mode}"""


def format_threat_context(chains_result: dict, c2_result: dict, obfuscation_result: Optional[dict] = None, secrets_result: Optional[dict] = None) -> str:
    """Format threat chains, C2 summary, obfuscation indicators, and hardcoded secrets for LLM consumption."""
    lines = []
    lines.append(f"Total threat chains: {chains_result.get('total_chains', 0)}")
    lines.append(f"Total C2 indicators: {c2_result.get('total_c2s', 0)}")
    lines.append("")

    for chain in chains_result.get("threat_chains", [])[:10]:  # Limit to 10 chains
        heur = chain.get("heuristic_score")
        dec_chain = chain.get("decoding_chain")
        c2_inds = chain.get("c2_indicators")
        extras = []
        if heur is not None:
            extras.append(f"heuristic_score={heur}")
        if dec_chain:
            extras.append(f"decoding_chain={' -> '.join(dec_chain)}")
        if c2_inds:
            extras.append(f"c2_count={len(c2_inds)}")
        extra_str = f" [{', '.join(extras)}]" if extras else ""
        lines.append(f"Chain {chain.get('chain_id')}: severity={chain.get('severity')}, confidence={chain.get('confidence')}{extra_str}")
        for step in chain.get("steps", []):
            artifact = str(step.get("artifact", ""))[:80]
            step_heur = step.get("heuristic_score")
            step_chain = step.get("decoding_chain")
            meta = ""
            if step_heur is not None:
                meta = f" (hs={step_heur}"
                if step_chain:
                    meta += f", dc={'->'.join(step_chain)}"
                meta += ")"
            lines.append(f"  Step {step.get('step')}: {step.get('type')} -> {artifact}{meta}")
        lines.append("")

    lines.append("C2 Infrastructure Summary:")
    for c2 in c2_result.get("c2_infrastructure", [])[:10]:
        domain = c2.get("domain") or c2.get("ip") or "unknown"
        lines.append(f"  - {c2.get('protocol', 'unknown')}://{domain}:{c2.get('port', 'unknown')}{c2.get('path', '/')} "
                     f"(classification={c2.get('ip_classification', 'n/a')}, type={c2.get('communication_type', 'other')})")

    if obfuscation_result:
        lines.append("")
        lines.append("Static Obfuscation & Permission Analysis:")
        lines.append(f"  Obfuscation score: {obfuscation_result.get('obfuscation_score', 0)} ({obfuscation_result.get('obfuscation_level', 'unknown')})")
        indicators = obfuscation_result.get("indicators", {})
        lines.append(f"  Classes: {indicators.get('total_classes', 0)}, Methods: {indicators.get('total_methods', 0)}")
        lines.append(f"  Reflection usages: {len(indicators.get('reflection', []))}")
        lines.append(f"  Dynamic loading usages: {len(indicators.get('dynamic_loading', []))}")
        lines.append(f"  Crypto API usages: {len(indicators.get('crypto_apis', []))}")
        lines.append(f"  Suspicious API usages: {len(indicators.get('suspicious_apis', []))}")
        lines.append(f"  Dangerous permissions: {len(indicators.get('dangerous_permissions', []))}")
        for perm in indicators.get("dangerous_permissions", [])[:10]:
            lines.append(f"    - {perm}")
        dex_entropy = obfuscation_result.get("dex_entropy", [])
        if any(d.get("likely_packed") for d in dex_entropy):
            lines.append("  DEX packing detected: likely_packed=True")

    if secrets_result:
        secrets_findings = secrets_result.get("hardcoded_secrets", [])
        secret_risk = secrets_result.get("secret_risk", {})
        if secret_risk.get("total_secrets", 0):
            lines.append("")
            lines.append("Hardcoded Secrets Analysis:")
            lines.append(f"  Total secrets: {secret_risk['total_secrets']} (severity: {secret_risk['severity']})")
            by_sev = secret_risk.get("by_severity", {})
            if by_sev.get("critical"):
                lines.append(f"  Critical: {by_sev['critical']}")
            if by_sev.get("high"):
                lines.append(f"  High: {by_sev['high']}")
            if by_sev.get("medium"):
                lines.append(f"  Medium: {by_sev['medium']}")
            lines.append(f"  Unique types: {secret_risk.get('unique_types', 0)}")
            top_critical = [s for s in secrets_findings if s.get("severity") == "critical"][:3]
            for s in top_critical:
                lines.append(f"    - [{s.get('secret_type')}] {s.get('value', '')[:60]}")
            top_high = [s for s in secrets_findings if s.get("severity") == "high"][:5]
            for s in top_high:
                lines.append(f"    - [{s.get('secret_type')}] {s.get('value', '')[:60]}")

    return "\n".join(lines)


def parse_llm_json(raw_output: str) -> Optional[Dict[str, Any]]:
    """Extract and parse JSON from LLM output."""
    raw_output = raw_output.strip()

    # Remove markdown code blocks if present
    if raw_output.startswith("```"):
        lines = raw_output.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        raw_output = "\n".join(lines).strip()

    # Try parsing the whole thing
    try:
        return json.loads(raw_output)
    except json.JSONDecodeError:
        pass

    # Try to extract JSON object with regex
    match = re.search(r'\{.*\}', raw_output, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return None


def validate_assessment(assessment: dict) -> bool:
    """Validate LLM assessment schema."""
    required = ["severity", "risk_score", "narrative", "recommended_actions"]
    if not all(k in assessment for k in required):
        return False
    if assessment.get("severity") not in ("critical", "high", "medium", "low"):
        return False
    risk_score = assessment.get("risk_score")
    if not isinstance(risk_score, int) or not (0 <= risk_score <= 100):
        return False
    if not isinstance(assessment.get("recommended_actions"), list):
        return False
    return True


def sanity_check(assessment: dict, chains_result: dict, c2_result: dict, obfuscation_result: Optional[dict] = None, secrets_result: Optional[dict] = None) -> dict:
    """Cross-reference LLM severity against detected indicators, including obfuscation/permissions/secrets."""
    c2_count = c2_result.get("total_c2s", 0)
    chain_count = chains_result.get("total_chains", 0)
    severity = assessment.get("severity", "low")
    risk_score = assessment.get("risk_score", 0)
    obf_score = (obfuscation_result or {}).get("obfuscation_score", 0)
    indicators = (obfuscation_result or {}).get("indicators", {})
    dangerous_perms = indicators.get("dangerous_permissions", [])

    # If critical/high secrets found but severity is low, raise it
    if secrets_result:
        secrets_findings = secrets_result.get("hardcoded_secrets", [])
        critical_count = sum(1 for s in secrets_findings if s.get("severity") == "critical")
        high_count = sum(1 for s in secrets_findings if s.get("severity") == "high")
        if critical_count > 0 and severity == "low":
            assessment["severity"] = "high"
            assessment["risk_score"] = max(risk_score, 70)
            assessment["narrative"] += " [SANITY CHECK: elevated due to critical hardcoded secrets (private keys/credentials).]"
        elif (critical_count > 0 or high_count >= 3) and severity == "medium":
            assessment["severity"] = "high"
            assessment["risk_score"] = max(risk_score, 65)
            assessment["narrative"] += " [SANITY CHECK: elevated due to multiple high-severity hardcoded secrets.]"

    # If significant obfuscation exists but severity is low, raise it
    if severity == "low" and obf_score > 50:
        if len(dangerous_perms) > 0 or obf_score > 70:
            assessment["severity"] = "medium"
            assessment["risk_score"] = max(risk_score, 30)
            assessment["narrative"] += " [SANITY CHECK: elevated due to obfuscation indicators (score {:.0f}).]".format(obf_score)
            severity = "medium"
            risk_score = assessment["risk_score"]

    # If active C2 exists but severity is low, raise it
    if c2_count > 0 and severity == "low":
        assessment["severity"] = "medium"
        assessment["risk_score"] = max(risk_score, 35)
        assessment["narrative"] += " [SANITY CHECK: elevated due to detected C2 infrastructure.]"

    # If no C2 was extracted, cap severity and risk_score
    if c2_count == 0:
        sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        rev_sev = {4: "critical", 3: "high", 2: "medium", 1: "low"}
        current = sev_map.get(assessment.get("severity", "low"), 1)
        max_sev = sev_map.get("medium", 2)
        if current > max_sev or assessment.get("risk_score", 0) > 50:
            assessment["severity"] = rev_sev[max_sev]
            assessment["risk_score"] = min(assessment.get("risk_score", 0), 50)
            assessment["narrative"] += " [SANITY CHECK: score capped — no C2 indicators extracted.]"
        narrative_lower = assessment.get("narrative", "").lower()
        c2_claim_keywords = ["c2", "command and control", "command & control", "c&c", "c2 server", "c2 infrastructure", "c2 communication"]
        if any(kw in narrative_lower for kw in c2_claim_keywords):
            assessment["severity"] = "low"
            assessment["risk_score"] = min(assessment.get("risk_score", 0), 25)
            assessment["narrative"] += " [SANITY CHECK: narrative references C2 infrastructure, but no C2 indicators were extracted. Score reduced — C2 claims appear speculative.]"

    return assessment


# ============================================================================
# Option 2: Conditional LLM Skip for Benign Apps
# ============================================================================

def _extract_high_confidence_c2(c2_result: dict, min_confidence: float = 0.8) -> list:
    """Extract C2 infrastructure entries with confidence >= min_confidence."""
    c2_infrastructure = c2_result.get("c2_infrastructure", [])
    high_conf = [
        c for c in c2_infrastructure
        if c.get("confidence", 0) >= min_confidence
    ]
    return high_conf


def _count_significant_chains(chains_result: dict) -> tuple[int, int]:
    """
    Count threat chains, separating "known" (decoded) vs "unknown" (all unknowns).
    
    Returns: (known_decoded_count, all_unknown_count)
    
    Rationale: A chain with no decoding (pure unknown encoding) is less
    actionable than one with known decoding steps. We use this to filter
    noise — many benign apps have hundreds of "unknown" encodings in their
    strings (standard Android library compression, ProGuard output, etc.).
    """
    chains = chains_result.get("threat_chains", [])
    known_decoded = 0
    all_unknown = 0
    
    for chain in chains:
        dc = chain.get("decoding_chain", [])
        # If all steps are "unknown" or dc is empty, count as all_unknown
        if not dc or all(t == "unknown" for t in dc):
            all_unknown += 1
        else:
            # At least one known decoding step -> significant chain
            known_decoded += 1
    
    return known_decoded, all_unknown


def should_skip_llm(
    chains_result: dict,
    c2_result: dict,
    obfuscation_result: Optional[dict] = None,
    secrets_result: Optional[dict] = None,
    high_conf_threshold: float = 0.6,
) -> bool:
    """
    Decide whether to skip LLM assessment and use rule-based fallback.
    
    Returns True (skip LLM) if NO high-confidence C2 infrastructure exists
    AND no critical/high-severity hardcoded secrets were found.
    
    The key insight: C2 infrastructure is the strongest single indicator of
    malicious intent. If no C2 indicator reaches high confidence (> 0.8),
    the app is unlikely to gain value from an LLM call — Mistral 7B will
    either hallucinate C2 claims or produce a generic benign narrative.
    
    The rule-based fallback (heuristic_fallback) already handles attribution
    based on obfuscation, chain volume, and permissions — so LLM is only
    needed when there's actual C2 signal worth reasoning about.
    
    Args:
        chains_result: Threat chain results from step 6
        c2_result: C2 extraction results from step 5
        obfuscation_result: Optional obfuscation analysis from step 8
        high_conf_threshold: Minimum C2 confidence to consider "high-confidence"
    
    Returns:
        True if should skip LLM (use heuristic fallback)
        False if should call LLM
    """
    high_conf_c2 = _extract_high_confidence_c2(c2_result, min_confidence=high_conf_threshold)
    
    # If ANY high-confidence C2 exists, call LLM — there's real signal to reason about
    if len(high_conf_c2) > 0:
        return False
    
    # Check for critical/high-severity hardcoded secrets — these warrant LLM assessment
    if secrets_result:
        secret_risk = secrets_result.get("secret_risk", {})
        if secret_risk.get("severity") in ("critical", "high"):
            return False
        # Also check individual findings directly
        secrets_findings = secrets_result.get("hardcoded_secrets", [])
        for s in secrets_findings:
            if s.get("severity") in ("critical", "high"):
                return False
    
    # No high-confidence C2 → skip LLM. Benign signal, no hallucination risk.
    return True


def _cap_risk_on_junk_c2(assessment: dict, c2_result: dict) -> dict:
    """
    Final safety net: if LLM was called but no C2 reaches high confidence,
    cap risk at 30. Prevents LLM hallucination on low-confidence C2 noise.
    """
    c2_infrastructure = c2_result.get("c2_infrastructure", [])
    high_conf = [c for c in c2_infrastructure if c.get("confidence", 0) >= 0.85]
    if len(high_conf) == 0 and len(c2_infrastructure) > 0:
        if assessment.get("risk_score", 0) > 30:
            assessment["risk_score"] = 30
            assessment["severity"] = "low"
            assessment["narrative"] += " [SAFETY CAP: risk capped due to low-confidence C2 indicators.]"
    return assessment


def benign_verdict_heuristic(
    chains_result: dict,
    c2_result: dict,
    obfuscation_result: Optional[dict] = None,
) -> dict:
    """
    Rule-based verdict for apps with benign signal (no high-conf C2, low decoded chains).
    
    Returns a low/medium severity assessment with clean, deterministic narrative.
    No LLM hallucination, no false C2 claims.
    """
    known_chains, unknown_chains = _count_significant_chains(chains_result)
    obf_score = (obfuscation_result or {}).get("obfuscation_score", 0)
    indicators = (obfuscation_result or {}).get("indicators", {})
    dangerous_perms = indicators.get("dangerous_permissions", [])
    suspicious_apis = indicators.get("suspicious_apis", [])
    crypto_apis = indicators.get("crypto_apis", [])
    reflection = indicators.get("reflection", [])
    dynamic_loading = indicators.get("dynamic_loading", [])
    
    # Build a concise narrative
    narrative_parts = []
    
    if unknown_chains > 0:
        narrative_parts.append(
            f"No high-confidence C2 or confirmed malicious behavior detected. "
            f"App contains {unknown_chains} undecodable string artifacts (likely benign library compression or ProGuard obfuscation)."
        )
    else:
        narrative_parts.append(
            "No high-confidence C2 infrastructure or decoded threat chains detected."
        )
    
    if dangerous_perms or crypto_apis or reflection:
        features = []
        if dangerous_perms:
            features.append(f"{len(dangerous_perms)} dangerous permissions")
        if crypto_apis:
            features.append(f"{len(crypto_apis)} crypto API usages")
        if reflection:
            features.append(f"{len(reflection)} reflection patterns")
        narrative_parts.append(
            f"Static indicators ({', '.join(features)}) fall within benign app norms "
            f"and do not establish malicious intent without actionable C2 or exfiltration evidence."
        )
    
    # Determine risk based on obfuscation + feature count
    risk_score = 45  # Base: benign (no C2 signal). Under threshold 50, but conservative
    if obf_score >= 50:
        risk_score = 45
        narrative_parts.append(
            f"Obfuscation score ({obf_score}) is moderate; recommend manual code review if context warrants."
        )
    # Escalate if multiple signals present simultaneously
    if dangerous_perms or suspicious_apis:
        signal_count = len(dangerous_perms) + len(suspicious_apis)
        if signal_count >= 3:
            risk_score = min(55, risk_score + 10)
        elif signal_count >= 1:
            risk_score = min(50, risk_score + 5)
    if reflection:
        risk_score = min(55, risk_score + 5)
    if dynamic_loading:
        risk_score = min(55, risk_score + 5)
    
    return {
        "severity": "low",
        "risk_score": risk_score,
        "narrative": " ".join(narrative_parts),
        "primary_threat": "other",
        "threat_indicators": [],
        "recommended_actions": ["No action required. App shows no signs of malicious control-flow or exfiltration."],
        "confidence": 0.9,
        "method": "heuristic_benign_skip",
    }


def _quick_family_check(chains_result: dict, c2_result: dict, obfuscation_result: Optional[dict] = None) -> Optional[str]:
    """Fast deterministic family pre-check using C2 domains and string patterns.
    Returns family name if matched, None otherwise. No LLM, no ground-truth lookup."""
    from backend.family_id import FAMILY_SIGNATURES
    c2_infra = (c2_result or {}).get("c2_infrastructure", [])
    for entry in c2_infra:
        domain = entry.get("value", "")
        for sig in FAMILY_SIGNATURES:
            for pat in sig.c2_patterns:
                if pat.mode == "EXACT" and domain == pat.pattern:
                    return sig.family_name
                elif pat.mode == "SUFFIX" and domain.endswith(pat.pattern):
                    return sig.family_name
                elif pat.mode == "SUBSTRING" and pat.pattern in domain:
                    return sig.family_name
    indicators = (obfuscation_result or {}).get("indicators", {})
    susp_apis = " ".join(indicators.get("suspicious_apis", [])).lower()
    for sig in FAMILY_SIGNATURES:
        for sp in sig.string_patterns:
            if sp.lower() in susp_apis:
                return sig.family_name
    return None


def _needs_manual_review(chains_result: dict, c2_result: dict, obfuscation_result: Optional[dict], assessment: dict) -> bool:
    """Flag sample for manual review: low risk but suspicious static features present."""
    indicators = (obfuscation_result or {}).get("indicators", {})
    reflection = indicators.get("reflection", [])
    dynamic_loading = indicators.get("dynamic_loading", [])
    packing = indicators.get("packing", [])
    if reflection and dynamic_loading:
        return True
    if packing:
        return True
    c2_infra = (c2_result or {}).get("c2_infrastructure", [])
    low_conf_c2 = [c for c in c2_infra if c.get("confidence", 0) >= 0.4]
    if low_conf_c2:
        return True
    return False


PERMISSION_BEHAVIOR_GROUPS = {
    "sms_fraud": {
        "permissions": {"SEND_SMS", "READ_SMS", "RECEIVE_SMS"},
        "boost": 35,
        "description": "SMS hijacking/fraud (send + intercept)",
    },
    "phone_identity": {
        "permissions": {"READ_PHONE_STATE"},
        "boost": 15,
        "description": "Phone identity theft / device fingerprinting",
    },
    "location_surveillance": {
        "permissions": {"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "RECORD_AUDIO"},
        "boost": 25,
        "description": "Coordinated location + audio surveillance",
    },
    "device_admin_abuse": {
        "permissions": {"BIND_DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW"},
        "boost": 20,
        "description": "Device admin abuse (persistence/control)",
    },
}


def _perm_short_name(perm: str) -> str:
    return perm.split(".")[-1] if "." in perm else perm


def _match_behavior_groups(app_permissions: list) -> list:
    """Return list of matched behavior groups for the app's dangerous permissions."""
    short_names = {_perm_short_name(p) for p in app_permissions}
    matches = []
    for group_name, group_config in PERMISSION_BEHAVIOR_GROUPS.items():
        required = group_config["permissions"]
        if required.issubset(short_names):
            matches.append({
                "group": group_name,
                "description": group_config["description"],
                "boost": group_config["boost"],
                "matched_permissions": list(required),
            })
    return matches


def heuristic_fallback(chains_result: dict, c2_result: dict, obfuscation_result: Optional[dict] = None) -> dict:
    """Rule-based fallback when LLM is unavailable. Considers chain volume, C2, obfuscation."""
    c2_count = c2_result.get("total_c2s", 0)
    chain_count = chains_result.get("total_chains", 0)
    obf_score = (obfuscation_result or {}).get("obfuscation_score", 0)
    obf_level = (obfuscation_result or {}).get("obfuscation_level", "low")
    indicators = (obfuscation_result or {}).get("indicators", {})
    dangerous_perms = indicators.get("dangerous_permissions", [])
    suspicious_apis = indicators.get("suspicious_apis", [])
    reflection = indicators.get("reflection", [])
    dynamic_loading = indicators.get("dynamic_loading", [])
    permission_behaviors = indicators.get("permission_behaviors", []) or _match_behavior_groups(dangerous_perms)
    crypto_apis = indicators.get("crypto_apis", [])

    unknown_enc_count = 0
    known_enc_count = 0
    for chain in chains_result.get("threat_chains", []):
        dc = chain.get("decoding_chain", [])
        if not dc or all(t == "unknown" for t in dc):
            unknown_enc_count += 1
        else:
            known_enc_count += 1

    if c2_count > 0:
        c2_infra = c2_result.get("c2_infrastructure", [])
        max_conf = max((c.get("confidence", 0) for c in c2_infra), default=0.0)
        ad_networks = sum(1 for c in c2_infra if c.get("threat_category") == "adware")
        all_ad = ad_networks == len(c2_infra)

        # Check whether ANY non-ad C2 looks like a real endpoint
        # (valid domain structure, not a garbage fragment).
        has_real_c2 = False
        for c in c2_infra:
            if c.get("threat_category") == "adware":
                continue
            domain = c.get("domain", "") or ""
            if not domain:
                continue
            # Reject obviously malformed domains
            if domain.endswith(".") or "." not in domain:
                continue
            tld = domain.split(".")[-1]
            if len(tld) <= 1:
                continue
            has_real_c2 = True
            break

        if max_conf >= 0.7:
            return {
                "severity": "high",
                "risk_score": 80,
                "narrative": f"Detected {c2_count} C2 indicator(s) across {chain_count} threat chain(s). High-confidence infrastructure present.",
                "primary_threat": "c2_exfiltration",
                "recommended_actions": ["Block identified C2 domains/IPs", "Analyze network traffic for exfiltration"],
                "confidence": 0.7,
                "method": "heuristic_c2",
            }

        if has_real_c2:
            # Non-ad, structurally valid C2 at moderate confidence — keep elevated
            return {
                "severity": "high",
                "risk_score": 75,
                "narrative": f"Detected {c2_count} C2 indicator(s) ({ad_networks} ad/analytics). Moderate-confidence non-ad infrastructure present.",
                "primary_threat": "c2_exfiltration",
                "recommended_actions": ["Verify C2 domains against known threat intel", "Review network traffic patterns"],
                "confidence": 0.6,
                "method": "heuristic_c2_candidate",
            }

        if max_conf >= 0.5:
            # All C2s are ad-network or malformed — likely false positive
            risk = min(65, 55 + ad_networks * 3)
            return {
                "severity": "medium",
                "risk_score": risk,
                "narrative": f"Detected {c2_count} possible C2 indicator(s) with moderate confidence. {'All flagged as ad/analytics SDK traffic' if all_ad else 'Indicators appear malformed or low-signal'} — likely benign.",
                "primary_threat": "adware" if all_ad else "other",
                "recommended_actions": ["Verify C2 domains against known ad/analytics SDKs", "Review network permissions in context"],
                "confidence": 0.55,
                "method": "heuristic_c2_moderate",
            }

        return {
            "severity": "medium",
            "risk_score": 45,
            "narrative": f"Detected {c2_count} low-confidence network indicator(s). Likely benign SDK or analytics endpoints with no malicious pattern.",
            "primary_threat": "other",
            "recommended_actions": ["Review network indicators manually if context warrants", "No immediate action required"],
            "confidence": 0.5,
            "method": "heuristic_c2_low",
        }

    if chain_count >= 1000 or (unknown_enc_count >= 500 and known_enc_count == 0):
        return {
            "severity": "high",
            "risk_score": 75,
            "narrative": f"Extreme obfuscation detected: {chain_count} threat chains ({unknown_enc_count} with unknown encoding). Massively encoded payloads with no identifiable C2 — strong evasion signal.",
            "primary_threat": "dropper",
            "recommended_actions": [
                "Heavy obfuscation detected — likely packed/encrypted payload",
                "Use dynamic analysis (Frida) to capture runtime decryption",
                "Check for ZIP-password-protected DEX in APK",
            ],
            "confidence": 0.65,
            "method": "heuristic_extreme_payload",
        }

    if chain_count >= 300 and obf_score >= 15:
        return {
            "severity": "high",
            "risk_score": 68,
            "narrative": f"Large-scale obfuscation: {chain_count} threat chains with obfuscation score {obf_score}. Heavy encoding without clear C2 suggests evasion-focused malware.",
            "primary_threat": "dropper",
            "recommended_actions": [
                "Review decoded payloads for embedded URLs",
                "Analyze native libraries for additional C2",
                "Run APK in sandbox for behavioral analysis",
            ],
            "confidence": 0.6,
            "method": "heuristic_complex",
        }

    if chain_count > 0:
        base_risk = 45
        if permission_behaviors:
            code_signals = len(reflection) + len(dynamic_loading) + len(suspicious_apis)
            if code_signals == 0:
                base_risk = 55
        return {
            "severity": "medium",
            "risk_score": base_risk,
            "narrative": f"Detected {chain_count} threat chain(s) but no confirmed active C2. Obfuscation/encoding present.",
            "primary_threat": "other",
            "recommended_actions": ["Review decoded artifacts", "Investigate encoding functions"],
            "confidence": 0.6,
            "method": "heuristic_moderate",
        }

    if obf_score >= 70:
        return {
            "severity": "high",
            "risk_score": 70,
            "narrative": f"No decoded threat chains, but obfuscation score {obf_score} ({obf_level}) with {len(dangerous_perms)} dangerous permissions.",
            "primary_threat": "other",
            "recommended_actions": ["Analyze native libraries for hidden payloads", "Check for ZIP entry password protection"],
            "confidence": 0.55,
            "method": "heuristic_obfuscated",
        }

    if obf_score >= 50 or len(dangerous_perms) >= 3 or permission_behaviors:
        floor = 50
        if permission_behaviors:
            code_signals = len(reflection) + len(dynamic_loading) + len(suspicious_apis)
            if code_signals == 0:
                floor = 55
        risk_score = min(100, max(floor, int(obf_score)))
        return {
            "severity": "medium",
            "risk_score": risk_score,
            "narrative": f"No decoded threat chains, but static analysis shows {obf_level} obfuscation (score {obf_score}) with {len(dangerous_perms)} dangerous permissions, {len(suspicious_apis)} suspicious APIs, {len(reflection)} reflection usages, {len(dynamic_loading)} dynamic loading instances, and {len(crypto_apis)} crypto API usages.",
            "primary_threat": "other",
            "recommended_actions": ["Analyze native libraries for hidden payloads", "Check for ZIP entry password protection"],
            "confidence": 0.5,
            "method": "heuristic_permissions",
        }

    return {
        "severity": "low",
        "risk_score": 25,
        "narrative": "No significant threat chains, obfuscation, or permission abuse detected.",
        "primary_threat": "other",
        "recommended_actions": ["No action required"],
        "confidence": 0.5,
        "method": "heuristic_benign",
    }


fallback_assessment = heuristic_fallback


def _call_nvidia_nim(context: str, model: str, base_url: str, api_key: str, max_retries: int = 2) -> Optional[str]:
    """Call NVIDIA NIM chat completions endpoint and return raw response text."""
    try:
        from openai import OpenAI, APITimeoutError
    except ImportError as e:
        raise LLMAssessmentError(f"openai package not installed: {e}")

    # OpenRouter requires HTTP-Referer and X-Title headers
    default_headers = {
        "HTTP-Referer": "https://github.com/anomalyco/DroidForensix",
        "X-Title": "DroidForensix",
    }
    # max_retries=0: the SDK's default 2 silent auto-retries (3 x 60s + backoff)
    # per request can exceed the step timeout before our own loop gets to retry.
    client = OpenAI(base_url=base_url, api_key=api_key, timeout=60, max_retries=0, default_headers=default_headers)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"THREAT CHAINS:\n{context}\n\nASSESSMENT:"},
    ]

    last_error = ""
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.1,
                max_tokens=512,
            )
            return response.choices[0].message.content
        except (requests.exceptions.Timeout, APITimeoutError):
            # openai SDK (httpx) raises APITimeoutError, not requests.exceptions.Timeout
            last_error = "NVIDIA NIM request timed out. Check network connectivity and NIM endpoint."
            sleep_time = 5 + attempt * 3
            print(f"  [!] NIM timeout, retrying in {sleep_time}s...")
            time.sleep(sleep_time)
        except requests.exceptions.ConnectionError as e:
            last_error = f"NVIDIA NIM unreachable: {e}"
            print(f"  [!] NIM connection error (check NVIDIA_NIM_BASE_URL and API key)")
            time.sleep(2)
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else 0
            last_error = f"NVIDIA NIM HTTP {status}"
            if status == 401:
                print(f"  [!] NIM auth failed — check NVIDIA_NIM_API_KEY")
            elif status == 429:
                sleep_time = 15 + attempt * 5
                print(f"  [!] NIM rate limited (429). Sleeping {sleep_time}s...")
                time.sleep(sleep_time)
            elif status >= 500:
                sleep_time = 10 + attempt * 5
                print(f"  [!] NIM server error {status}, retrying in {sleep_time}s...")
                time.sleep(sleep_time)
            else:
                print(f"  [!] Provider returned HTTP {status} (not retryable)")
                return None
        except Exception as e:
            # Catch OpenAI API errors (NotFoundError, RateLimitError, etc.)
            err_name = type(e).__name__
            status = getattr(e, 'status_code', 0) or (e.response.status_code if hasattr(e, 'response') and e.response else 0)
            if status == 404:
                print(f"  [!] Model not found (404) — check model name or provider endpoint")
                return None
            elif status == 429:
                print(f"  [!] Rate limited (429). Sleeping 15s...")
                time.sleep(15)
            else:
                last_error = str(e)
                print(f"  [!] LLM API error: {err_name}")
                time.sleep(2)

    return None


def _normalize_ollama_host(host: str) -> str:
    """Normalize Ollama host so it is reachable on Windows.

    On Windows, connecting to 0.0.0.0 raises [Errno 22] Invalid argument.
    Rewrite 0.0.0.0 to 127.0.0.1 while preserving scheme and port.
    """
    if not host:
        return "http://127.0.0.1:11434"
    parsed = urllib.parse.urlparse(host)
    hostname = parsed.hostname or "127.0.0.1"
    if hostname in ("0.0.0.0", "::"):
        hostname = "127.0.0.1"
    port = parsed.port or 11434
    scheme = parsed.scheme or "http"
    return f"{scheme}://{hostname}:{port}"


def _ollama_available(host: str, timeout: float = 2.0) -> bool:
    """Fast TCP probe to determine if Ollama is reachable; fail-fast before
    spending minutes on the first request. Mirrors droidforensix_llm._ollama_available."""
    host = _normalize_ollama_host(host)
    parsed = urllib.parse.urlparse(host)
    netloc = parsed.hostname or "127.0.0.1"
    port = parsed.port or 11434
    try:
        s = socket.create_connection((netloc, port), timeout=timeout)
        s.close()
        return True
    except (OSError, socket.error):
        return False


class OllamaClient:
    """Reusable Ollama client with connection pooling and exponential backoff."""

    def __init__(self, base_url: str = "http://127.0.0.1:11434",
                 model: str = "mistral:7b-instruct-q4_K_M",
                 max_retries: int = 3, timeout: int = 300):
        self.base_url = _normalize_ollama_host(base_url)
        self.model = model
        self.max_retries = max_retries
        self.timeout = timeout
        self.session = self._create_session()

    def _create_session(self):
        from requests.adapters import HTTPAdapter
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=5, pool_maxsize=5)
        session.mount("http://", adapter)
        return session

    def generate(self, context: str) -> Optional[str]:
        prompt = f"{SYSTEM_PROMPT}\n\nTHREAT CHAINS:\n{context}\n\nASSESSMENT:"
        url = f"{self.base_url.rstrip('/')}/api/generate"
        last_error = ""

        for attempt in range(self.max_retries):
            try:
                resp = self.session.post(
                    url,
                    json={
                        "model": self.model, "prompt": prompt,
                        "stream": False, "format": "json",
                        "options": {"num_ctx": 4096, "temperature": 0.1},
                    },
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("response", "")
            except requests.exceptions.Timeout:
                last_error = "timeout"
                if attempt < self.max_retries - 1:
                    wait = 2 ** attempt
                    print(f"  [Ollama] Timeout, retrying in {wait}s (attempt {attempt + 2}/{self.max_retries})...")
                    time.sleep(wait)
            except requests.exceptions.ConnectionError as e:
                last_error = f"connection_error: {e}"
                if attempt < self.max_retries - 1:
                    wait = 2 ** attempt
                    print(f"  [Ollama] Connection error, retrying in {wait}s (attempt {attempt + 2}/{self.max_retries})...")
                    time.sleep(wait)
            except requests.exceptions.HTTPError as e:
                status = e.response.status_code if e.response is not None else 0
                if attempt < self.max_retries - 1 and status in (429, 500, 502, 503, 504):
                    wait = (2 ** attempt) * 2
                    print(f"  [Ollama] HTTP {status}, retrying in {wait}s...")
                    time.sleep(wait)
                else:
                    print(f"  [Ollama] HTTP {status} — not retryable")
                    return None
            except Exception as e:
                last_error = str(e)
                print(f"  [Ollama] Unexpected error: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)

        guidance = (
            f"  [Ollama] All {self.max_retries} retries exhausted ({last_error}).\n"
            f"  Fix:\n"
            f"    1. Verify Ollama is running: ollama list\n"
            f"    2. Start Ollama: ollama serve\n"
            f"    3. Check model: ollama pull {self.model}\n"
            f"    4. Test connection: curl {self.base_url}/api/tags\n"
            f"    5. Re-run with --heuristic-only to skip LLM"
        )
        print(guidance)
        return None


def _call_ollama(context: str, host: str, model: str, max_retries: int = 3) -> Optional[str]:
    """Legacy wrapper — delegates to OllamaClient."""
    client = OllamaClient(base_url=host, model=model, max_retries=max_retries)
    return client.generate(context)


def assess_with_llm(chains_result: dict, c2_result: dict, obfuscation_result: Optional[dict] = None, secrets_result: Optional[dict] = None) -> dict:
    """
    Full Step 7: Get LLM assessment of threat chains, obfuscation indicators, and hardcoded secrets.

    Prefers NVIDIA NIM if NVIDIA_NIM_API_KEY is set, otherwise falls back to Ollama.
    Any unexpected error returns the rule-based fallback assessment so the pipeline
    keeps running.
    """
    sample_id = chains_result.get("sample_id") or c2_result.get("sample_id") or "unknown"
    work_dir = settings.WORK_DIR / sample_id
    try:
        work_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        # If the work directory cannot be created, still return a fallback.
        import logging
        logging.getLogger(__name__).debug("Could not create work dir %s", work_dir)

    # ========== OPTION 2: Pre-flight benign check ==========
    if should_skip_llm(chains_result, c2_result, obfuscation_result, secrets_result):
        family_match = _quick_family_check(chains_result, c2_result, obfuscation_result)
        if family_match:
            print(f"  [Option 2] Benign signal BUT family match ({family_match}) -> forcing LLM")
        else:
            print(f"  [Option 2] Benign signal detected -> skipping LLM, using heuristic verdict")
            assessment = benign_verdict_heuristic(chains_result, c2_result, obfuscation_result)
            assessment["raw_llm_output"] = "(skipped: heuristic benign verdict)"
            assessment["needs_manual_review"] = _needs_manual_review(chains_result, c2_result, obfuscation_result, assessment)
            try:
                result_path = work_dir / "step7_assessment.json"
                with open(result_path, "w", encoding="utf-8") as f:
                    json.dump(assessment, f, indent=2)
            except OSError as e:
                assessment["raw_llm_output"] += f" [save warning: {e}]"
            time.sleep(0.5)
            return assessment

    try:
        context = format_threat_context(chains_result, c2_result, obfuscation_result, secrets_result)
        assessment = None
        raw_output = ""
        max_retries = 2

        # Determine provider: explicit setting overrides auto-detection.
        provider = (os.environ.get("LLM_PROVIDER") or settings.LLM_PROVIDER or "auto").lower()
        nim_api_key = os.environ.get("NVIDIA_NIM_API_KEY")
        or_api_key = os.environ.get("OPENROUTER_API_KEY")
        use_nvidia = provider == "nvidia" or (provider == "auto" and nim_api_key)
        use_openrouter = provider == "openrouter" or (provider == "auto" and or_api_key and not nim_api_key)

        if use_nvidia:
            # NVIDIA NIM path
            nim_model = os.environ.get("NVIDIA_NIM_MODEL", settings.NIM_MODEL or "deepseek-ai/deepseek-v4-pro")
            nim_base_url = os.environ.get("NVIDIA_NIM_BASE_URL", settings.NIM_HOST or "https://integrate.api.nvidia.com/v1")
            print(f"  [*] Using NVIDIA NIM model: {nim_model}")

            for attempt in range(max_retries):
                raw_output = _call_nvidia_nim(context, nim_model, nim_base_url, nim_api_key, max_retries=2)
                parsed = parse_llm_json(raw_output) if raw_output else None
                if parsed and validate_assessment(parsed):
                    assessment = sanity_check(parsed, chains_result, c2_result, obfuscation_result, secrets_result)
                    assessment["method"] = "llm"
                    break
                else:
                    wait = (attempt + 1) * 2
                    print(f"  [!] Invalid LLM response, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...")
                    messages_note = "Your previous response was invalid. Output ONLY valid JSON.\n\n"
                    context = messages_note + format_threat_context(chains_result, c2_result, obfuscation_result, secrets_result)
                    time.sleep(wait)
        elif use_openrouter:
            # OpenRouter path (OpenAI-compatible API)
            or_model = os.environ.get("OPENROUTER_MODEL", settings.OPENROUTER_MODEL or "google/gemma-4-31b-it:free")
            or_base_url = os.environ.get("OPENROUTER_BASE_URL", settings.OPENROUTER_HOST or "https://openrouter.ai/api/v1")
            print(f"  [*] Using OpenRouter model: {or_model}")

            for attempt in range(max_retries):
                raw_output = _call_nvidia_nim(context, or_model, or_base_url, or_api_key, max_retries=2)
                parsed = parse_llm_json(raw_output) if raw_output else None
                if parsed and validate_assessment(parsed):
                    assessment = sanity_check(parsed, chains_result, c2_result, obfuscation_result, secrets_result)
                    assessment["method"] = "llm"
                    break
                else:
                    wait = (attempt + 1) * 2
                    print(f"  [!] Invalid LLM response, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...")
                    messages_note = "Your previous response was invalid. Output ONLY valid JSON.\n\n"
                    context = messages_note + format_threat_context(chains_result, c2_result, obfuscation_result, secrets_result)
                    time.sleep(wait)
        else:
            # Local Ollama path
            ollama_host = _normalize_ollama_host(os.environ.get("OLLAMA_HOST", settings.OLLAMA_HOST))
            ollama_model = os.environ.get("OLLAMA_MODEL", settings.OLLAMA_MODEL)
            print(f"  [*] Using Ollama model: {ollama_model} at {ollama_host}")

            for attempt in range(max_retries):
                raw_output = _call_ollama(context, ollama_host, ollama_model, max_retries=2)
                parsed = parse_llm_json(raw_output) if raw_output else None
                if parsed and validate_assessment(parsed):
                    assessment = sanity_check(parsed, chains_result, c2_result, obfuscation_result, secrets_result)
                    assessment["method"] = "llm"
                    break
                else:
                    wait = (attempt + 1) * 2
                    print(f"  [!] Invalid LLM response, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...")
                    messages_note = "Your previous response was invalid. Output ONLY valid JSON.\n\n"
                    context = messages_note + format_threat_context(chains_result, c2_result, obfuscation_result, secrets_result)
                    time.sleep(wait)

        if assessment is None:
            assessment = fallback_assessment(chains_result, c2_result, obfuscation_result)

        assessment["raw_llm_output"] = (raw_output or "")[:2000]

        # Safety net: cap risk if no high-confidence C2 present
        assessment = _cap_risk_on_junk_c2(assessment, c2_result)

        # Cooldown: prevent hammering Ollama during batch runs
        time.sleep(2.0)

        # Save intermediate result
        try:
            result_path = work_dir / "step7_assessment.json"
            with open(result_path, "w", encoding="utf-8") as f:
                json.dump(assessment, f, indent=2)
        except OSError as e:
            assessment["raw_llm_output"] += f" [save warning: {e}]"

        return assessment
    except Exception as e:
        # Last-resort fallback: never let LLM assessment crash the pipeline.
        assessment = fallback_assessment(chains_result, c2_result, obfuscation_result)
        assessment["raw_llm_output"] = (
            f"LLM assessment error: {type(e).__name__}: {e}\n\n"
            f"Options:\n"
            f"  1. Check LLM_PROVIDER env var (nvidia, openrouter, or auto)\n"
            f"  2. For Ollama: verify 'ollama serve' is running\n"
            f"  3. For NVIDIA NIM: verify NVIDIA_NIM_API_KEY is set\n"
            f"  4. Re-run with --heuristic-only to skip LLM"
        )[:2000]
        return assessment


METHOD_EXPLAIN_SYSTEM_PROMPT = """/no_think

You are an Android malware analyst reviewing decompiled Java bytecode for a forensic report.
Given a method's name, its class context, any suspicious flags already detected, and its full body,
write a detailed analyst note covering:
- What the method does technically (specific API calls, data flows, control logic)
- Why it is suspicious IN THIS CONTEXT (not just what the method does objectively, but why its presence here is concerning)
- What combination with other methods or patterns elevates the risk
- A benign alternative explanation: what would legitimate use of this method look like?
- Any Android-specific security implications (permission abuse, dynamic code loading, data exfiltration paths)

Be specific. Reference actual method names, class names, or variable patterns you observe in the code.
Do not write generic descriptions — ground every claim in the actual code provided.
Do not simply describe what the method does (e.g., "startActivityForResult starts an activity"). Instead, explain WHY this call is suspicious in this specific context.

Output must be valid JSON only. No markdown, no preamble, no code blocks. Schema:
{
  "summary": "3-5 sentence detailed analyst note grounded in the actual code, explaining why suspicious in context",
  "threat_type": "reflection|dynamic_loading|crypto|network|command_exec|persistence|permissions|benign|unknown",
  "confidence": 0.0-1.0
}
"""

CHAIN_EXPLAIN_SYSTEM_PROMPT = """/no_think

You are an Android malware analyst reviewing a threat chain extracted from an Android APK.
A threat chain is a sequence of steps linking an encoded string through decoding to a final C2 endpoint.
Given the chain steps and metadata, write an analyst note covering:
- What the chain does from start to end (the full data flow)
- Whether this represents a real threat (C2 communication, data exfiltration, etc.)
- What an attacker could achieve with this chain
- How the decoding works (what encoding, what decodes it, what the decoded content is)
- Whether the C2 endpoint is likely active or a false positive

Be specific. Reference actual artifacts, source locations, and decoding methods from the chain.
Do not write generic descriptions.

Output must be valid JSON only. No markdown, no preamble, no code blocks. Schema:
{
  "summary": "3-5 sentence analyst note grounded in the actual chain data",
  "threat_type": "c2_communication|data_exfiltration|payload_delivery|command_execution|benign|unknown",
  "confidence": 0.0-1.0
}
"""


DISSECTION_SUMMARY_SYSTEM_PROMPT = """/no_think

You are an Android malware threat analyst performing a forensic assessment of an APK.
You will receive a condensed dissection of the APK's structure: metadata, permissions,
components, DEX statistics, and the top suspicious classes (by network calls and
permission usage).

Produce a structured threat assessment. Be specific — reference actual permission names,
class names, component names, and DEX statistics. Do not write generic descriptions.
Ground every claim in the data provided.

Output must be valid JSON only. No markdown, no preamble, no code blocks. Schema:
{
  "threat_level": "critical|high|medium|low",
  "risk_score": 0-100,
  "summary": "2-3 sentence forensic narrative summarizing the APK's threat posture",
  "key_behaviors": ["behavior 1 (with specific class/permission reference)", ...],
  "suspicious_methods": [{"class": "com.example.Foo", "method": "bar", "reason": "why suspicious"}, ...],
  "c2_indicators": ["IP/domain/URL pattern observed", ...],
  "recommended_focus": ["area 1 the analyst should investigate further", ...]
}

Severity mapping:
- critical (80-100): Confirmed C2 exfiltration, ransomware behavior, rootkit, or banking trojan with active C2
- high (60-79): Suspicious network callbacks + dangerous permissions + obfuscation or dynamic loading
- medium (40-59): Some suspicious patterns but no confirmed malicious behavior (e.g., adware, excessive permissions)
- low (0-39): Benign or minimal risk — standard app with normal permissions and no suspicious patterns
"""


def explain_threat_chain(chain: dict) -> dict:
    """Call LLM to produce a plain-English explanation of a threat chain."""
    steps = chain.get("steps", [])
    step_lines = []
    for s in steps:
        step_lines.append(
            f"  Step {s.get('step')} ({s.get('type')}): "
            f"artifact={s.get('artifact', '')} | "
            f"source={s.get('source_location', '')} | "
            f"confidence={s.get('confidence', 0)}"
        )

    context = (
        f"Chain ID: {chain.get('chain_id', 'unknown')}\n"
        f"Severity: {chain.get('severity', 'unknown')}\n"
        f"Confidence: {chain.get('confidence', 0)}\n"
        f"Steps ({len(step_lines)}):\n"
        + "\n".join(step_lines)
    )

    fallback = {
        "summary": "Chain explanation unavailable.",
        "threat_type": "unknown",
        "confidence": 0.0,
    }

    try:
        provider = (os.environ.get("LLM_PROVIDER") or settings.LLM_PROVIDER or "auto").lower()
        nim_api_key = os.environ.get("NVIDIA_NIM_API_KEY")
        use_nvidia = provider == "nvidia" or (provider == "auto" and nim_api_key)

        raw_output = ""
        if use_nvidia:
            combined = f"{CHAIN_EXPLAIN_SYSTEM_PROMPT}\n\nTHREAT CHAIN:\n{context}\n\nEXPLANATION:"
            raw_output = _call_nvidia_nim(combined, os.environ.get("NVIDIA_NIM_MODEL", settings.NIM_MODEL or "deepseek-ai/deepseek-v4-pro"), os.environ.get("NVIDIA_NIM_BASE_URL", settings.NIM_HOST or "https://integrate.api.nvidia.com/v1"), nim_api_key, max_retries=2) or ""
        else:
            ollama_host = _normalize_ollama_host(os.environ.get("OLLAMA_HOST", settings.OLLAMA_HOST))
            ollama_model = os.environ.get("OLLAMA_MODEL", settings.OLLAMA_MODEL)
            combined = f"{CHAIN_EXPLAIN_SYSTEM_PROMPT}\n\nTHREAT CHAIN:\n{context}\n\nEXPLANATION:"
            import ollama as _ollama
            client = _ollama.Client(host=_normalize_ollama_host(ollama_host), timeout=300)
            resp = client.generate(
                model=ollama_model,
                prompt=combined,
                format="json",
                options={"num_ctx": 4096, "temperature": 0.1},
            )
            raw_output = resp.get("response", "")

        parsed = parse_llm_json(raw_output)
        if parsed and "summary" in parsed:
            return {
                "summary": str(parsed.get("summary", ""))[:500],
                "threat_type": str(parsed.get("threat_type", "unknown")),
                "confidence": float(parsed.get("confidence", 0.5)),
            }
        return fallback
    except Exception as e:
        fallback["summary"] = f"Chain explanation error: {e}"[:300]
        return fallback


def explain_method(
    class_name: str,
    method_name: str,
    method_code: str,
    flags: list[str] | None = None,
) -> dict:
    """
    Call the configured LLM (NIM or Ollama) to produce a plain-English
    explanation of a single decompiled method.

    Returns a dict with keys: summary, threat_type, confidence.
    Never raises — returns a fallback dict on any error.
    """
    flags = flags or []
    # Truncate code to keep prompt lean — shorter = faster inference on limited VRAM
    code_snippet = method_code[:1500] if method_code else "(no body)"

    context = (
        f"Class: {class_name}\n"
        f"Method: {method_name}\n"
        f"Detected flags: {', '.join(flags) if flags else 'none'}\n\n"
        f"Method body:\n{code_snippet}"
    )

    fallback = {
        "summary": "LLM explanation unavailable. Review the method body manually.",
        "threat_type": "unknown",
        "confidence": 0.0,
    }

    try:
        provider = (os.environ.get("LLM_PROVIDER") or settings.LLM_PROVIDER or "auto").lower()
        nim_api_key = os.environ.get("NVIDIA_NIM_API_KEY")
        use_nvidia = provider == "nvidia" or (provider == "auto" and nim_api_key)

        raw_output = ""
        if use_nvidia:
            nim_model = os.environ.get("NVIDIA_NIM_MODEL", settings.NIM_MODEL or "deepseek-ai/deepseek-v4-pro")
            nim_base_url = os.environ.get("NVIDIA_NIM_BASE_URL", settings.NIM_HOST or "https://integrate.api.nvidia.com/v1")
            # Temporarily swap system prompt via a wrapper prompt
            combined = f"{METHOD_EXPLAIN_SYSTEM_PROMPT}\n\nMETHOD TO ANALYSE:\n{context}\n\nEXPLANATION:"
            raw_output = _call_nvidia_nim(combined, nim_model, nim_base_url, nim_api_key, max_retries=2) or ""
        else:
            ollama_host = _normalize_ollama_host(os.environ.get("OLLAMA_HOST", settings.OLLAMA_HOST))
            ollama_model = os.environ.get("OLLAMA_MODEL", settings.OLLAMA_MODEL)
            # Build a self-contained prompt since _call_ollama embeds SYSTEM_PROMPT;
            # override by passing everything as the context string with inline instructions.
            combined = f"{METHOD_EXPLAIN_SYSTEM_PROMPT}\n\nMETHOD TO ANALYSE:\n{context}\n\nEXPLANATION:"

            import ollama as _ollama
            client = _ollama.Client(
                host=_normalize_ollama_host(ollama_host),
                timeout=120,
            )
            resp = client.generate(
                model=ollama_model,
                prompt=combined,
                format="json",
                options={"num_ctx": 4096, "temperature": 0.1},
            )
            raw_output = resp.get("response", "")

        parsed = parse_llm_json(raw_output)
        if parsed and "summary" in parsed:
            return {
                "summary": str(parsed.get("summary", ""))[:500],
                "threat_type": str(parsed.get("threat_type", "unknown")),
                "confidence": float(parsed.get("confidence", 0.5)),
            }
        return fallback

    except Exception as e:
        fallback["summary"] = f"Explanation error: {e}"[:300]
        return fallback


def _condense_dissection(dissection: dict, class_objects: list | None = None) -> str:
    """Build a condensed text representation of the dissection for LLM input.
    Focuses on the sections most relevant for threat assessment.
    Truncates to fit within ~3500 tokens (leaving room for system prompt + response).
    """
    parts = []

    # Metadata
    meta = dissection.get("metadata", {})
    parts.append("=== METADATA ===")
    parts.append(f"Package: {meta.get('package_name', 'unknown')}")
    parts.append(f"Version: {meta.get('version_name', '?')} (code {meta.get('version_code', '?')})")
    parts.append(f"Min SDK: {meta.get('min_sdk_version', '?')}, Target SDK: {meta.get('target_sdk_version', '?')}")
    parts.append(f"File size: {meta.get('file_size_bytes', 0) / 1024 / 1024:.1f} MB")
    parts.append(f"Multidex: {meta.get('is_multidex', False)}")

    # Permissions
    perms = dissection.get("permissions", [])
    parts.append(f"\n=== PERMISSIONS ({len(perms)}) ===")
    dangerous = [p for p in perms if p.get("protection_level") == "dangerous"]
    normal = [p for p in perms if p.get("protection_level") == "normal"]
    sig = [p for p in perms if p.get("protection_level") == "signature"]
    parts.append(f"Dangerous ({len(dangerous)}): {', '.join(p['name'] for p in dangerous[:15])}")
    if len(dangerous) > 15:
        parts.append(f"  ... and {len(dangerous) - 15} more dangerous permissions")
    parts.append(f"Normal ({len(normal)}): {', '.join(p['name'] for p in normal[:10])}")
    if sig:
        parts.append(f"Signature ({len(sig)}): {', '.join(p['name'] for p in sig[:5])}")

    # Components
    comps = dissection.get("components", {})
    parts.append(f"\n=== COMPONENTS ===")
    for ctype in ["activities", "services", "receivers", "providers"]:
        items = comps.get(ctype, [])
        exported = [i for i in items if i.get("exported")]
        parts.append(f"{ctype}: {len(items)} total, {len(exported)} exported")
        if exported:
            for e in exported[:5]:
                parts.append(f"  [exported] {e.get('name', '?')}")
            if len(exported) > 5:
                parts.append(f"  ... and {len(exported) - 5} more exported {ctype}")

    # DEX stats
    dex = dissection.get("dex_stats", {})
    parts.append(f"\n=== DEX STATISTICS ===")
    parts.append(f"DEX files: {dex.get('dex_count', '?')}")
    parts.append(f"Total classes: {dex.get('total_classes', '?')}")
    parts.append(f"Total methods: {dex.get('total_methods', '?')}")
    parts.append(f"Total strings: {dex.get('total_strings', '?')}")

    # Native libs
    native = dissection.get("native_libs", [])
    if native:
        parts.append(f"\n=== NATIVE LIBRARIES ({len(native)}) ===")
        for lib in native[:10]:
            if isinstance(lib, dict):
                parts.append(f"  {lib.get('name', '?')} ({lib.get('size', '?')} bytes)")
            else:
                parts.append(f"  {lib}")

    # File structure overview
    fs = dissection.get("file_structure", {})
    top_dirs = fs.get("top_level_directories", [])
    if top_dirs:
        parts.append(f"\n=== FILE STRUCTURE ===")
        parts.append(f"Top-level directories: {', '.join(top_dirs[:15])}")
        parts.append(f"Total files: {fs.get('total_files', '?')}")

    # Top suspicious classes (from class objects)
    if class_objects:
        by_net = sorted(
            [c for c in class_objects if c.get("network_calls")],
            key=lambda c: len(c.get("network_calls", [])),
            reverse=True,
        )
        by_perm = sorted(
            [c for c in class_objects if c.get("permissions_used")],
            key=lambda c: len(c.get("permissions_used", [])),
            reverse=True,
        )
        parts.append(f"\n=== TOP SUSPICIOUS CLASSES (by network calls) ===")
        for c in by_net[:10]:
            nc = len(c.get("network_calls", []))
            mc = len(c.get("methods", []))
            methods_preview = ", ".join(m["name"] for m in c.get("methods", [])[:3])
            parts.append(f"  {c['name']}: {nc} network calls, {mc} methods [{methods_preview}]")

        if by_perm:
            parts.append(f"\n=== TOP SUSPICIOUS CLASSES (by permission usage) ===")
            for c in by_perm[:5]:
                used = c.get("permissions_used", [])
                parts.append(f"  {c['name']}: {len(used)} permission refs")

    result = "\n".join(parts)
    # Hard truncate if still too long (rough estimate: 4 chars per token)
    if len(result) > 14000:
        result = result[:14000] + "\n... [truncated]"
    return result


def _format_behavior_item(b) -> str:
    """Normalize a key_behaviors item to a display string."""
    if isinstance(b, str):
        return b
    if isinstance(b, dict):
        for key in ("value", "text", "behavior"):
            v = b.get(key)
            if v is not None and str(v).strip():
                return str(v).strip()
        parts = []
        if b.get("class"):
            parts.append(b["class"])
        if b.get("method"):
            parts.append(f".{b['method']}")
        if b.get("permission"):
            if parts:
                parts.append(f" — {b['permission']}")
            else:
                parts.append(b["permission"])
        if b.get("reason"):
            if parts:
                parts.append(f": {b['reason']}")
            else:
                parts.append(b["reason"])
        if parts:
            return "".join(parts)
        return json.dumps(b, ensure_ascii=False)
    return str(b)


def _format_c2_item(c) -> str:
    """Normalize a c2_indicators item to a display string.

    When the LLM emits a dict, prefer named indicator keys first so the
    actual indicator is shown instead of a label like "domain".
    """
    if isinstance(c, str):
        return c
    if isinstance(c, dict):
        preferred_keys = ("value", "indicator", "ip", "domain", "url", "raw", "text")
        for key in preferred_keys:
            v = c.get(key)
            if v is not None and str(v).strip():
                return str(v).strip()
        for v in c.values():
            if v and str(v).strip().lower() != "not applicable":
                return str(v).strip()
        return next((str(v).strip() for v in c.values() if str(v).strip()), json.dumps(c, ensure_ascii=False))
    return str(c)


def summarize_dissection(dissection: dict, class_objects: list | None = None) -> dict:
    """Call LLM to produce a structured threat assessment from dissection data.
    
    Returns a dict with: threat_level, risk_score, summary, key_behaviors,
    suspicious_methods, c2_indicators, recommended_focus.
    Never raises — returns a fallback dict on any error.
    """
    fallback = {
        "threat_level": "unknown",
        "risk_score": 0,
        "summary": "LLM summary unavailable.",
        "key_behaviors": [],
        "suspicious_methods": [],
        "c2_indicators": [],
        "recommended_focus": [],
        "status": "fallback",
    }

    provider = (os.environ.get("LLM_PROVIDER") or settings.LLM_PROVIDER or "auto").lower()
    nim_api_key = os.environ.get("NVIDIA_NIM_API_KEY")
    use_nvidia = provider == "nvidia" or (provider == "auto" and nim_api_key)

    condensed = _condense_dissection(dissection, class_objects)
    combined = f"{DISSECTION_SUMMARY_SYSTEM_PROMPT}\n\nAPK DISSECTION DATA:\n{condensed}\n\nTHREAT ASSESSMENT:"

    try:
        if use_nvidia:
            raw_output = _call_nvidia_nim(
                combined,
                settings.NIM_MODEL or os.environ.get("NIM_MODEL", "deepseek-ai/deepseek-v4-pro"),
                settings.NIM_HOST or os.environ.get("NVIDIA_NIM_BASE_URL", ""),
                nim_api_key,
                max_retries=2,
            )
        else:
            ollama_host = os.environ.get("OLLAMA_HOST") or settings.OLLAMA_HOST
            ollama_model = os.environ.get("OLLAMA_MODEL") or settings.OLLAMA_MODEL
            import ollama as _ollama
            client = _ollama.Client(
                host=_normalize_ollama_host(ollama_host),
                timeout=120,
            )
            resp = client.generate(
                model=ollama_model,
                prompt=combined,
                format="json",
                options={"num_ctx": 4096, "temperature": 0.1},
            )
            raw_output = resp.get("response", "")

        parsed = parse_llm_json(raw_output)
        if not parsed:
            fallback["raw_output"] = raw_output[:500]
            return fallback

        # Validate and normalize
        threat_level = str(parsed.get("threat_level", "unknown")).lower()
        if threat_level not in ("critical", "high", "medium", "low"):
            threat_level = "unknown"

        risk_score = parsed.get("risk_score", 0)
        try:
            risk_score = max(0, min(100, int(risk_score)))
        except (TypeError, ValueError):
            risk_score = 0

        key_behaviors = parsed.get("key_behaviors", [])
        if not isinstance(key_behaviors, list):
            key_behaviors = [str(key_behaviors)]
        key_behaviors = [_format_behavior_item(b) for b in key_behaviors if b is not None]

        suspicious_methods = parsed.get("suspicious_methods", [])
        if not isinstance(suspicious_methods, list):
            suspicious_methods = []

        c2_indicators = parsed.get("c2_indicators", [])
        if not isinstance(c2_indicators, list):
            c2_indicators = [str(c2_indicators)]
        c2_indicators = [_format_c2_item(c) for c in c2_indicators if c is not None]

        recommended_focus = parsed.get("recommended_focus", [])
        if not isinstance(recommended_focus, list):
            recommended_focus = [str(recommended_focus)]

        return {
            "threat_level": threat_level,
            "risk_score": risk_score,
            "summary": str(parsed.get("summary", ""))[:500],
            "key_behaviors": key_behaviors,
            "suspicious_methods": suspicious_methods,
            "c2_indicators": c2_indicators,
            "recommended_focus": recommended_focus,
            "status": "ok",
        }

    except Exception as e:
        fallback["summary"] = f"LLM summary error: {e}"[:300]
        return fallback


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python step7_llm_assessment.py <step6_chains.json> <step5_c2s.json>")
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        chains = json.load(f)
    with open(sys.argv[2], "r", encoding="utf-8") as f:
        c2s = json.load(f)
    print(json.dumps(assess_with_llm(chains, c2s), indent=2))