"""Measure Cipher.doFinal new-C2 yield: baseline (steps 1-5) vs +cipher.

For each APK: run extraction + strings + encodings once, then decode/C2
twice (without and with cipher encodings appended). Strictly-new C2s are
cipher-payload-linked records whose raw_url never appears in baseline.

Resumable: skips samples already present in the output JSON.
Usage: python scripts/measure_cipher_yield.py <apks.txt> <out.json>
"""

import json
import logging
import sys
import time
import traceback
from pathlib import Path

logging.disable(logging.CRITICAL)
try:
    from loguru import logger as _loguru

    _loguru.remove()
except Exception:
    pass

from analysis.step1_apk_extraction import extract_apk
from analysis.step2_string_enumeration import enumerate_strings
from analysis.step3_encoding_detection import detect_encoding
from analysis.step4_decoding import decode_payloads
from analysis.step5_c2_extraction import extract_c2_infrastructure
from analysis.cipher_tracing import trace_cipher_in_apk
from backend.config import settings


def measure_one(apk_path: str, work_dir: str) -> dict:
    """Baseline vs cipher C2 sets for a single APK."""
    started = time.time()
    extraction = extract_apk(apk_path, work_dir)
    strings_result = enumerate_strings(extraction)
    encodings_result = detect_encoding(strings_result)
    base_ids = {e["encoding_id"] for e in encodings_result.get("encodings", [])}

    # Baseline: steps 4-5 without cipher encodings.
    base_payloads = decode_payloads(encodings_result)
    base_c2 = extract_c2_infrastructure(base_payloads, strings_result)
    base_urls = {c["raw_url"] for c in base_c2.get("c2_infrastructure", [])}

    # Cipher run: append cipher encodings, redo steps 4-5.
    cipher_result = trace_cipher_in_apk(extraction)
    cipher_ids = set()
    if cipher_result["encodings"]:
        next_id = len(encodings_result["encodings"])
        for offset, enc in enumerate(cipher_result["encodings"]):
            enc["encoding_id"] = f"enc_{next_id + offset:03d}"
            cipher_ids.add(enc["encoding_id"])
        encodings_result["encodings"].extend(cipher_result["encodings"])
        encodings_result["total_encodings"] = len(encodings_result["encodings"])

    cipher_payloads = decode_payloads(encodings_result)
    cipher_c2 = extract_c2_infrastructure(cipher_payloads, strings_result)

    cipher_pids = {
        p["payload_id"]
        for p in cipher_payloads.get("payloads", [])
        if p.get("encoding_id") in cipher_ids
    }
    cipher_linked = [
        c["raw_url"]
        for c in cipher_c2.get("c2_infrastructure", [])
        if c.get("payload_id") in cipher_pids
    ]
    strictly_new = sorted(set(cipher_linked) - base_urls)

    return {
        "sample": Path(apk_path).name,
        "sample_id": extraction["sample_id"],
        "apktool_success": extraction["apktool_success"],
        "baseline_c2s": len(base_urls),
        "cipher_sites": cipher_result["total_sites"],
        "cipher_solved": cipher_result["solved"],
        "cipher_unsolved": cipher_result["traced_unsolved"],
        "cipher_linked_c2s": len(cipher_linked),
        "new_c2_urls": strictly_new,
        "new_c2_count": len(strictly_new),
        "elapsed_s": round(time.time() - started, 1),
    }


def main() -> None:
    apks_path, out_path = sys.argv[1], sys.argv[2]
    apks = [line.strip() for line in open(apks_path) if line.strip()]
    out_file = Path(out_path)
    results = []
    if out_file.exists():
        results = json.loads(out_file.read_text(encoding="utf-8"))
    done = {r["sample"] for r in results}

    for apk in apks:
        name = Path(apk).name
        if name in done:
            print(f"SKIP {name}", flush=True)
            continue
        try:
            record = measure_one(apk, str(settings.WORK_DIR))
        except Exception as exc:
            record = {
                "sample": name,
                "error": f"{type(exc).__name__}: {exc}",
                "trace": traceback.format_exc()[-500:],
            }
        results.append(record)
        out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(
            "DONE {} base={} solved={} unsolved={} new={} ({:.0f}s)".format(
                name,
                record.get("baseline_c2s"),
                record.get("cipher_solved"),
                record.get("cipher_unsolved"),
                record.get("new_c2_count"),
                record.get("elapsed_s", 0),
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
