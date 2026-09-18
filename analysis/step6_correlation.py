"""
Step 6: Threat Chain Correlation

Builds directed threat chains linking encoded strings → decoded payloads →
C2 infrastructure. Calculates composite confidence scores and severity indicators.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional

from backend.config import settings


class CorrelationError(Exception):
    """Raised when correlation fails."""
    pass


# Weights for composite confidence calculation
STEP_WEIGHTS = [0.15, 0.20, 0.25, 0.20, 0.20]

# Minimum confidence threshold for C2 records to be included in threat chains.
# Low-confidence C2s (e.g. leftover SDK references) generate false-positive chains.
C2_CONFIDENCE_THRESHOLD = 0.6


def extract_function_name(source_location: str) -> str:
    """Extract a function-like name from source location for chain steps."""
    if ":" in source_location:
        file_part = source_location.split(":")[0]
    else:
        file_part = source_location
    # Remove .java extension
    if file_part.endswith(".java"):
        file_part = file_part[:-5]
    # Return last path component
    return file_part.split("/")[-1]


def build_threat_chains(encodings_result: dict, payloads_result: dict,
                        c2_result: dict) -> dict:
    """
    Full Step 6: Build threat chains from encodings, payloads, and C2s.

    Args:
        encodings_result: Output dict from Step 3.
        payloads_result: Output dict from Step 4.
        c2_result: Output dict from Step 5.

    Returns:
        dict with threat chains.
    """
    sample_id = encodings_result["sample_id"]
    work_dir = settings.WORK_DIR / sample_id
    work_dir.mkdir(parents=True, exist_ok=True)

    chains = []
    chain_id = 0

    # Index payloads by encoding_id
    payloads_by_encoding = {}
    for payload in payloads_result.get("payloads", []):
        enc_id = payload.get("encoding_id")
        if enc_id:
            payloads_by_encoding.setdefault(enc_id, []).append(payload)

    # Filter C2s by confidence threshold BEFORE building chains.
    high_confidence_c2s = [
        c2 for c2 in c2_result.get("c2_infrastructure", [])
        if c2.get("confidence", 0) >= C2_CONFIDENCE_THRESHOLD
    ]

    # Index filtered C2s by payload_id
    c2s_by_payload = {}
    for c2 in high_confidence_c2s:
        pld_id = c2.get("payload_id")
        if pld_id:
            c2s_by_payload.setdefault(pld_id, []).append(c2)

    for encoding in encodings_result.get("encodings", []):
        enc_id = encoding.get("encoding_id")
        enc_type = encoding.get("type", "unknown")
        enc_source = encoding.get("source_location", "unknown")
        enc_confidence = encoding.get("confidence", 0.5)

        payloads = payloads_by_encoding.get(enc_id, [])
        if not payloads:
            # Encoding without successful decode — create a partial chain
            severity = "low"
            if enc_type == "custom":
                severity = "medium"
            chain_confidence = round(enc_confidence * STEP_WEIGHTS[0] / sum(STEP_WEIGHTS[:1]), 4)
            chains.append({
                "chain_id": f"chain_{chain_id:03d}",
                "severity": severity,
                "confidence": chain_confidence,
                "steps": [
                    {
                        "step": 1,
                        "type": "encoded_string",
                        "artifact": encoding.get("original_string", "")[:100],
                        "source_location": enc_source,
                        "confidence": enc_confidence,
                    }
                ],
            })
            chain_id += 1
            continue

        for payload in payloads:
            pld_id = payload.get("payload_id", "")
            pld_source = payload.get("source_location", enc_source)
            pld_confidence = payload.get("confidence", 0.5)
            decoded_preview = payload.get("decoded_content", "")[:200]
            dec_engine = payload.get("decoding_engine")
            heur_score = dec_engine.get("heuristic_score") if dec_engine else None
            chain_path = dec_engine.get("chain_path") if dec_engine else None
            c2_inds = dec_engine.get("c2_indicators") if dec_engine else None

            c2s = c2s_by_payload.get(pld_id, [])
            if not c2s:
                # Payload without C2 — still a chain but lower severity
                steps = [
                    {
                        "step": 1,
                        "type": "encoded_string",
                        "artifact": encoding.get("original_string", "")[:100],
                        "source_location": enc_source,
                        "confidence": enc_confidence,
                    },
                    {
                        "step": 2,
                        "type": "decoding_function",
                        "artifact": f"decode_{enc_type}()",
                        "source_location": pld_source,
                        "confidence": pld_confidence,
                    },
                    {
                        "step": 3,
                        "type": "decoded_artifact",
                        "artifact": decoded_preview,
                        "original_string": encoding.get("original_string", "")[:200],
                        "source_location": pld_source,
                        "confidence": pld_confidence,
                        "heuristic_score": heur_score,
                        "decoding_chain": chain_path,
                    },
                ]
                chain_confidence = round(
                    (enc_confidence * STEP_WEIGHTS[0] +
                     pld_confidence * STEP_WEIGHTS[1] +
                     pld_confidence * STEP_WEIGHTS[2]) /
                    sum(STEP_WEIGHTS[:3]), 4)
                chains.append({
                    "chain_id": f"chain_{chain_id:03d}",
                    "severity": "medium",
                    "confidence": chain_confidence,
                    "heuristic_score": heur_score,
                    "decoding_chain": chain_path,
                    "c2_indicators": c2_inds,
                    "steps": steps,
                })
                chain_id += 1
                continue

            for c2 in c2s:
                c2_confidence = c2.get("confidence", 0.5)
                c2_source = c2.get("source_location", pld_source)
                raw_url = c2.get("raw_url", "")

                steps = [
                    {
                        "step": 1,
                        "type": "encoded_string",
                        "artifact": encoding.get("original_string", "")[:100],
                        "source_location": enc_source,
                        "confidence": enc_confidence,
                    },
                    {
                        "step": 2,
                        "type": "decoding_function",
                        "artifact": f"decode_{enc_type}()",
                        "source_location": pld_source,
                        "confidence": pld_confidence,
                    },
                    {
                        "step": 3,
                        "type": "decoded_artifact",
                        "artifact": decoded_preview,
                        "original_string": encoding.get("original_string", "")[:200],
                        "source_location": pld_source,
                        "confidence": pld_confidence,
                    },
                    {
                        "step": 4,
                        "type": "usage",
                        "artifact": extract_function_name(c2_source),
                        "source_location": c2_source,
                        "confidence": c2_confidence,
                    },
                    {
                        "step": 5,
                        "type": "c2_infrastructure",
                        "artifact": raw_url,
                        "source_location": c2_source,
                        "confidence": c2_confidence,
                    },
                ]

                chain_confidence = round(
                    (enc_confidence * STEP_WEIGHTS[0] +
                     pld_confidence * STEP_WEIGHTS[1] +
                     pld_confidence * STEP_WEIGHTS[2] +
                     c2_confidence * STEP_WEIGHTS[3] +
                     c2_confidence * STEP_WEIGHTS[4]) /
                    sum(STEP_WEIGHTS), 4)

                # Severity based on confidence and indicators
                severity = "medium"
                if chain_confidence >= 0.8 and c2.get("ip_classification") == "public":
                    severity = "critical"
                elif chain_confidence >= 0.7:
                    severity = "high"
                elif chain_confidence < 0.5:
                    severity = "low"

                chains.append({
                    "chain_id": f"chain_{chain_id:03d}",
                    "severity": severity,
                    "confidence": chain_confidence,
                    "steps": steps,
                })
                chain_id += 1

    result = {
        "sample_id": sample_id,
        "total_chains": len(chains),
        "threat_chains": chains,
    }

    # Save intermediate result
    result_path = work_dir / "step6_chains.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("Usage: python step6_correlation.py <step3_encodings.json> <step4_payloads.json> <step5_c2s.json>")
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        encodings = json.load(f)
    with open(sys.argv[2], "r", encoding="utf-8") as f:
        payloads = json.load(f)
    with open(sys.argv[3], "r", encoding="utf-8") as f:
        c2s = json.load(f)
    print(json.dumps(build_threat_chains(encodings, payloads, c2s), indent=2))
