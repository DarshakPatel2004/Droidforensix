"""Guard against retired thesis numbers reappearing in project docs.

The c2_alignment sign-off (4217835, 80f9e5a) retired a set of stale
numbers; manual greps caught them three times across sessions. The
2026-09-24 summary reconciliation retired the old 97%/72% thesis headlines.
This test makes both checks automatic for tracked evaluation/docs files and
the root THESIS_SUMMARY.md.

If a banned pattern legitimately returns (e.g. a future metric coincides
with an old one), update BANNED deliberately in the same commit that
introduces the new number, and say why in the commit message.
"""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCAN_DIRS = ("evaluation", "docs")
SCAN_FILES = (ROOT / "THESIS_SUMMARY.md",)
SUFFIXES = (".py", ".md", ".txt")

BANNED = [
    r"\b0\.892\b",          # retired CV string (source_aware_eval, fixed 4217835)
    r"\b89\.20\b",          # retired CV percent form
    r"\b95\.68\b",          # retired in-sample percent (old bundle)
    r"\b0\.9568\b",          # retired in-sample raw (old bundle)
    r"verified 19-Sep-2026",  # superseded by 19-22 Sep 2026 header (80f9e5a)
    r"[−-]6\.48",           # retired gap-to-in-sample claim
    r"\+0\.40\s*pts",      # retired gain claim (scoped to "pts" so the live
                           # signature-scoring constant +0.40 in
                           # docs/codebase-reference.md doesn't false-match)
    # Retired THESIS_SUMMARY headlines (2026-09-24).
    r"Claim 1: Binary Malware Detection\s+[—-]\s+97% Real-World Accuracy",
    r"Claim 2: Family Identification\s+[—-]\s+72% on Specific-Labeled Samples",
    r"\|\s*5\s*\|\s*Binary Malware Detection\s*\|\s*✅ Done\s*\|\s*97% real-world",
    r"real_world_accuracy_report\.json\s+# 97% binary detector",
    r"Binary detector \(97%, 0% FN\)",
    r'"Why 44% family\?"',
    r'"Why not 97% family\?"',
    # Retired current-model count; historical 20-feature analyses stay allowed.
    r"malben_rf\.pkl`? \(20 features",
    r"RandomForest,\s*\n20 features",
    r"cached 20-feature rows",
]


def _iter_doc_files():
    """Tracked files only: the gitignored scratch under evaluation/ must not be scanned."""
    yield from SCAN_FILES
    listed = subprocess.run(
        ["git", "ls-files", "--", *SCAN_DIRS],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    for rel in listed.splitlines():
        path = ROOT / rel
        if path.suffix in SUFFIXES and path.is_file():
            yield path


def test_no_stale_thesis_numbers():
    offenders = []
    for path in _iter_doc_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in BANNED:
            if re.search(pattern, text):
                offenders.append(f"{path.relative_to(ROOT)}: {pattern}")
    assert not offenders, (
        "Retired thesis numbers found (see tests/evaluation/"
        "test_no_stale_numbers.py docstring for provenance):\n  "
        + "\n  ".join(offenders)
    )
