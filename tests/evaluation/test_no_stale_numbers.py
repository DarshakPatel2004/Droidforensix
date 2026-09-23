"""Guard against retired thesis numbers reappearing in project docs.

The c2_alignment sign-off (4217835, 80f9e5a) retired a set of stale
numbers; manual greps caught them three times across sessions. This test
makes that check automatic for tracked docs (evaluation/, docs/ — py/md/txt).

If a banned pattern legitimately returns (e.g. a future metric coincides
with an old one), update BANNED deliberately in the same commit that
introduces the new number, and say why in the commit message.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCAN_DIRS = ("evaluation", "docs")
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
]


def _iter_doc_files():
    for dirname in SCAN_DIRS:
        base = ROOT / dirname
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
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
        f"test_no_stale_numbers.py docstring for provenance):\n  "
        + "\n  ".join(offenders)
    )
