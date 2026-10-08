"""Unit tests for the known-bad-cert branch in identify_family (offline)."""

import pytest

from backend import family_id
from backend.family_id import identify_family


@pytest.fixture(autouse=True)
def _restore_ground_truth_files():
    """Restore module state after each test.

    These tests disable the ground-truth override so the cert branch is the
    only thing under test. Without restoring it, the override stayed disabled
    for every later test in the session.
    """
    original = family_id.GROUND_TRUTH_FILES
    yield
    family_id.GROUND_TRUTH_FILES = original
    family_id._ground_truth_map.cache_clear()


def _result(cert_block):
    return {
        "metadata": {"sha256": "00" * 32, "package_name": "com.test.app"},
        "certificate_analysis": cert_block,
        "strings": {"string_literals": []},
        "c2_infrastructure": [],
    }


class TestKnownBadCertBranch:
    def test_known_bad_names_family(self):
        family_id.GROUND_TRUTH_FILES = []
        family_id._ground_truth_map.cache_clear()
        out = identify_family(
            "00" * 32,
            _result({"known_bad": True, "known_bad_family": "SmsSend"}),
            use_llm=False,
            use_cache=False,
        )
        assert out["family"] == "SmsSend"
        assert out["method"] == "known_bad_cert"
        assert out["confidence"] == 0.85

    def test_catchall_db_family_abstains(self):
        family_id.GROUND_TRUTH_FILES = []
        family_id._ground_truth_map.cache_clear()
        out = identify_family(
            "00" * 32,
            _result({"known_bad": True, "known_bad_family": "AndroidOS"}),
            use_llm=False,
            use_cache=False,
        )
        assert out["family"] != "AndroidOS"

    def test_no_cert_falls_through(self):
        family_id.GROUND_TRUTH_FILES = []
        family_id._ground_truth_map.cache_clear()
        out = identify_family(
            "00" * 32,
            _result({"known_bad": False}),
            use_llm=False,
            use_cache=False,
        )
        assert out["family"] == "unknown"

    def test_ground_truth_files_are_restored(self):
        """Guards against the suite-wide leak this module used to cause."""
        assert family_id.GROUND_TRUTH_FILES == ["ground_truth_test_set.json",
                                                "ground_truth_drebin.json",
                                                "ground_truth_fdroid.json"]
