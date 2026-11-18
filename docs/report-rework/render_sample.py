"""Render one sample's report: writes <out>.json (the report model) and <out>.pdf.

Usage: python docs/report-rework/render_sample.py <sha256> <out_base>
The model in backend/report_model.py is the source of truth. The PDF is still
rendered from the same pipeline outputs; moving it to read the model is the next step.
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
from backend.report_model import build_report_model  # noqa: E402


def main(sample_id: str, out_base: str) -> None:
    base = Path(out_base)
    model = build_report_model(sample_id)
    base.with_suffix(".json").write_text(json.dumps(model, indent=2, default=str), encoding="utf-8")
    result = json.loads((ROOT / "analysis" / "work" / sample_id / "pipeline_result.json").read_text(encoding="utf-8"))
    threat = ti.build_threat_intel(result, sample_id)
    obf = build_obfuscation_view(sample_id, result.get("obfuscation_analysis"))
    family = identify_family(sample_id, result, use_llm=False)
    pdf = generate_report(sample_id=sample_id, sample_result=result, threat_data=threat,
                          obfuscation=obf, annotated_methods=[], mode="full", family=family)
    base.with_suffix(".pdf").write_bytes(pdf)
    print("ok", base.with_suffix(".json").name, base.with_suffix(".pdf").name)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
