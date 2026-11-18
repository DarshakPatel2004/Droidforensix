"""Render the full PDF report for one analysed sample.

Usage: python docs/report-rework/render_sample.py <sha256> <out.pdf>
Reads analysis/work/<sha256>/pipeline_result.json. Family attribution is read
from the cache when present; no LLM call is made for it (use_llm=False).
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend import threat_intel as ti  # noqa: E402
from backend.family_id import identify_family  # noqa: E402
from backend.obfuscation_view import build_obfuscation_view  # noqa: E402
from backend.pdf_report import generate_report  # noqa: E402


def main(sample_id: str, out_path: str) -> None:
    result = json.loads((ROOT / "analysis" / "work" / sample_id / "pipeline_result.json").read_text(encoding="utf-8"))
    threat = ti.build_threat_intel(result, sample_id)
    obf = build_obfuscation_view(sample_id, result.get("obfuscation_analysis"))
    family = identify_family(sample_id, result, use_llm=False)
    pdf = generate_report(sample_id=sample_id, sample_result=result, threat_data=threat,
                          obfuscation=obf, annotated_methods=[], mode="full", family=family)
    Path(out_path).write_bytes(pdf)
    print("ok", len(pdf))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
