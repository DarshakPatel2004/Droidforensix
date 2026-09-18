"""Unit tests for the known-bad-cert branch in identify_family (offline)."""

from backend import family_id
from backend.family_id import identify_family


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
        try:
            out = identify_family(
                "00" * 32,
                _result({"known_bad": True, "known_bad_family": "SmsSend"}),
                use_llm=False,
                use_cache=False,
            )
        finally:
            family_id._ground_truth_map.cache_clear()
        assert out["family"] == "SmsSend"
        assert out["method"] == "known_bad_cert"
        assert out["confidence"] == 0.85

    def test_catchall_db_family_abstains(self):
        family_id.GROUND_TRUTH_FILES = []
        family_id._ground_truth_map.cache_clear()
        try:
            out = identify_family(
                "00" * 32,
                _result({"known_bad": True, "known_bad_family": "AndroidOS"}),
                use_llm=False,
                use_cache=False,
            )
        finally:
            family_id._ground_truth_map.cache_clear()
        assert out["family"] != "AndroidOS"

    def test_no_cert_falls_through(self):
        family_id.GROUND_TRUTH_FILES = []
        family_id._ground_truth_map.cache_clear()
        try:
            out = identify_family(
                "00" * 32,
                _result({"known_bad": False}),
                use_llm=False,
                use_cache=False,
            )
        finally:
            family_id._ground_truth_map.cache_clear()
        assert out["family"] == "unknown"
