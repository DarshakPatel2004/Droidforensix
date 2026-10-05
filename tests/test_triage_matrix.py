"""Unit tests for scripts/triage_matrix.py helpers (no corpus needed).

classify() drives the section-15 delta accounting; resolve_path() is the
Kali->repo path remap the sample set depends on.
"""

import pytest

from scripts.triage_matrix import REPO, classify, resolve_path


@pytest.mark.parametrize("verdict,expected", [
    ("indeterminate(suspect:dropper-shape)", "suspect"),
    ("packed_known(Bangcle/SecNeo)", "brand_matched"),
    ("packed_custom", "flagged"),
    ("obfuscated_native", "flagged"),
    ("packed_custom(allowlisted-benign)", "allowlisted"),
    ("indeterminate", "indeterminate"),
    ("indeterminate(allowlisted-benign)", "allowlisted"),
    ("clean_static", "clean"),
    ("clean_static(allowlisted-benign)", "allowlisted"),
    ("something_new", "unexpected"),
])
def test_classify_maps_verdict_to_matrix_column(verdict, expected):
    assert classify(verdict) == expected


def test_classify_suspect_wins_over_allowlist_suffix():
    """A suspect verdict stays suspect even with the allowlist suffix
    appended later in triage_apk (suffix order is verdict-unchanging)."""
    assert classify(
        "indeterminate(suspect:dropper-shape)(allowlisted-benign)"
    ) == "suspect"


def test_resolve_path_remaps_kali_to_repo():
    resolved = resolve_path("/home/kali/DroidForensix/RTO.apk")
    assert resolved == REPO / "RTO.apk"


def test_resolve_path_keeps_windows_absolute(tmp_path):
    assert resolve_path(str(tmp_path / "x.apk")) == tmp_path / "x.apk"


def test_resolve_path_joins_relative_to_repo():
    assert resolve_path("PENDRIVE DATA/a.apk") == REPO / "PENDRIVE DATA" / "a.apk"
