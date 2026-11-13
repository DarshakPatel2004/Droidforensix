"""Regression checks for the scripts/ audit findings (R-series) that are pure logic."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from compare_aggregators import _is_definitive  # noqa: E402
from download_common import safe_error, sanitize_filename  # noqa: E402


# R4: the AndroZoo key must never reach the console through a request error.
def test_safe_error_redacts_secret():
    secret = "SECRETKEY123"
    exc = RuntimeError(f"404 Client Error for url: /api/download?apikey={secret}&sha256=x")
    assert secret not in safe_error(exc, secret)


# R2: submitter-chosen names are reduced to safe characters.
def test_sanitize_filename_strips_path_separators():
    assert "/" not in sanitize_filename("..\\..\\evil")
    assert sanitize_filename("...") == "unknown"


# R6: transient errors are not cached; definitive answers are.
def test_only_definitive_lookups_are_cached():
    assert _is_definitive({"detected": False})
    assert _is_definitive({"found": False, "error": "not_found"})
    assert not _is_definitive({"detected": False, "error": "rate_limited"})
    assert not _is_definitive({"found": False, "error": "unauthorized"})
