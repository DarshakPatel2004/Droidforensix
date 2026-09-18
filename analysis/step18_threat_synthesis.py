"""
Step 18: Threat Synthesis & Zero-Day Payload Scoring.

Aggregates outputs from steps 10-17 into a unified threat profile.
Produces a single zero-day risk score based on weighted indicators
from binary packing, reflective tracing, permissions, network,
strings, ELF, certificate, and family clustering.
"""

import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

THREAT_WEIGHTS = [
    {"signal": "binary_packing", "weight": 20, "description": "Packed/obfuscated binary"},
    {"signal": "reflective_calls", "weight": 20, "description": "Reflective method invocation to sensitive APIs"},
    {"signal": "reflective_permission_mismatch", "weight": 15, "description": "High permission usage with low declared-usage ratio"},
    {"signal": "c2_endpoints", "weight": 20, "description": "Suspicious/C2 network endpoints found"},
    {"signal": "high_entropy_strings", "weight": 10, "description": "Obfuscated or encrypted string payloads"},
    {"signal": "native_obfuscation", "weight": 10, "description": "Obfuscated or suspicious native libraries"},
    {"signal": "certificate_anomaly", "weight": 5, "description": "Suspicious or self-signed certificate"},
]


def score_zero_day_risk(context: Dict[str, Any]) -> float:
    if not context:
        return 0.0

    score = 0.0

    packing = context.get("packing", {})
    if packing.get("packing_detected"):
        packing_score = packing.get("obfuscation_score", 0) / 100
        score += 20 * packing_score

    reflective = context.get("reflective_tracing", {})
    sensitive_count = reflective.get("total_sensitive", 0)
    score += min(20, sensitive_count * 4)

    perms = context.get("permissions", {})
    usage_ratio = perms.get("usage_ratio", 1.0)
    total_used = perms.get("total_used", 0)
    if usage_ratio < 0.5 and total_used > 3:
        score += 15 * (1 - usage_ratio)

    network = context.get("network", {})
    c2_count = network.get("total_c2", 0)
    score += min(20, c2_count * 5)

    strings = context.get("strings", {})
    high_entropy = strings.get("total_high_entropy", 0)
    score += min(10, high_entropy * 1)

    native = context.get("native_elf", {})
    libs = native.get("native_libraries", [])
    obfuscated_libs = sum(
        1 for lib in libs if lib.get("obfuscation", {}).get("obfuscation_detected", False)
    )
    score += min(10, obfuscated_libs * 5)

    cert = context.get("certificate", {})
    if cert.get("known_bad"):
        score += 5
    elif cert.get("certificate_found") and cert.get("suspicious_issuer"):
        score += 3

    return round(score, 1)


def synthesize_threat_profile(pipeline_context: Dict[str, Any]) -> Dict[str, Any]:
    if not pipeline_context or all(
        not v for v in pipeline_context.values()
    ):
        return {
            "zero_day_risk_score": 0.0,
            "risk_level": "unknown",
            "contributing_signals": [],
            "signal_count": 0,
        }

    score = score_zero_day_risk(pipeline_context)

    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 35:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "none"

    contributing_signals = []
    for signal_def in THREAT_WEIGHTS:
        signal_key = signal_def["signal"]
        weight = signal_def["weight"]

        if signal_key == "binary_packing":
            packing = pipeline_context.get("packing", {})
            if packing.get("packing_detected"):
                val = packing.get("obfuscation_score", 0) / 100
                contributing_signals.append({
                    "signal": signal_key,
                    "contribution": round(weight * val, 1),
                    "detail": packing.get("indicators", []),
                })

        elif signal_key == "reflective_calls":
            reflective = pipeline_context.get("reflective_tracing", {})
            if reflective.get("total_sensitive", 0):
                contributing_signals.append({
                    "signal": signal_key,
                    "contribution": min(weight, reflective.get("total_sensitive", 0) * 4),
                    "detail": f"{reflective.get('total_sensitive', 0)} sensitive APIs targeted",
                })

        elif signal_key == "reflective_permission_mismatch":
            perms = pipeline_context.get("permissions", {})
            if perms.get("usage_ratio", 1.0) < 0.5 and perms.get("total_used", 0) > 3:
                contributing_signals.append({
                    "signal": signal_key,
                    "contribution": round(weight * (1 - perms.get("usage_ratio", 0)), 1),
                    "detail": f"{perms.get('total_unused', 0)} unused of {perms.get('total_permissions', 0)}",
                })

        elif signal_key == "c2_endpoints":
            network = pipeline_context.get("network", {})
            if network.get("total_c2", 0):
                contributing_signals.append({
                    "signal": signal_key,
                    "contribution": min(weight, network.get("total_c2", 0) * 5),
                    "detail": f"{network.get('total_c2', 0)} C2 endpoints",
                })

        elif signal_key == "high_entropy_strings":
            strings = pipeline_context.get("strings", {})
            if strings.get("total_high_entropy", 0):
                contributing_signals.append({
                    "signal": signal_key,
                    "contribution": min(weight, strings.get("total_high_entropy", 0)),
                    "detail": f"{strings.get('total_high_entropy', 0)} high-entropy strings",
                })

        elif signal_key == "native_obfuscation":
            native = pipeline_context.get("native_elf", {})
            libs = native.get("native_libraries", [])
            obfuscated_libs = [
                lib for lib in libs
                if lib.get("obfuscation", {}).get("obfuscation_detected", False)
            ]
            if obfuscated_libs:
                contributing_signals.append({
                    "signal": signal_key,
                    "contribution": min(weight, len(obfuscated_libs) * 5),
                    "detail": f"{len(obfuscated_libs)} obfuscated native libraries",
                })

        elif signal_key == "certificate_anomaly":
            cert = pipeline_context.get("certificate", {})
            if cert.get("known_bad") or cert.get("suspicious_issuer"):
                contrib = 5 if cert.get("known_bad") else 3
                contributing_signals.append({
                    "signal": signal_key,
                    "contribution": min(weight, contrib),
                    "detail": "Known-bad certificate" if cert.get("known_bad") else "Suspicious issuer",
                })

    contributing_signals.sort(key=lambda s: -s["contribution"])

    return {
        "zero_day_risk_score": score,
        "risk_level": level,
        "contributing_signals": contributing_signals,
        "signal_count": len(contributing_signals),
    }
