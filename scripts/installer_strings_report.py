#!/usr/bin/env python3
"""Stage-3 corpus tooling for the RTO.apk unpacking case study.

Reads the committed decoder output (`rto_analysis/phase2/installer_deobfuscated_strings.json`)
and writes a sorted, human/machine-usable TSV corpus plus a coverage summary.

The re-derivation of these strings from the raw payload (bytecode replay of the
stub's smali/alvik IR feeding the NkWaRdJEKEf58YYznc(long) hash-chain against the
CJK pool) is the OPEN reproducibility step documented in rto_analysis/stage3.md;
this tool works with what is committed as evidence.

Usage:
    python scripts/installer_strings_report.py [--json <path>]

Outputs next to the JSON:
    installer_deobfuscated_strings.tsv   -- seed<TAB>string, only decoded entries
    installer_deobfuscated_strings.summary.json -- coverage stats
"""

import argparse
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_JSON = PROJECT_ROOT / "rto_analysis" / "phase2" / "installer_deobfuscated_strings.json"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, default=DEFAULT_JSON)
    args = parser.parse_args()

    src: Path = args.json
    data = json.loads(src.read_text(encoding="utf-8"))

    pairs = [(seed, text) for seed, text in data.items() if isinstance(text, str) and text]
    unique_strings = sorted({text for _, text in pairs})

    tsv_path = src.with_name("installer_deobfuscated_strings.tsv")
    with tsv_path.open("w", encoding="utf-8", newline="") as fh:
        fh.write("seed\tstring\n")
        for seed, text in sorted(pairs, key=lambda p: p[1]):
            fh.write(f"{seed}\t{text}\n")

    summary = {
        "source": str(src),
        "total_entries": len(data),
        "decoded_entries": len(pairs),
        "null_entries": len(data) - len(pairs),
        "unique_strings": len(unique_strings),
        "decoded_rate": round(len(pairs) / len(data), 4) if data else 0.0,
    }
    summary_path = src.with_name("installer_deobfuscated_strings.summary.json")
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"Wrote {tsv_path.name} and {summary_path.name}")


if __name__ == "__main__":
    main()