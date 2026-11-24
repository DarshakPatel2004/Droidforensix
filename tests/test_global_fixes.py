"""Regression tests for the global inconsistency fixes (C2 classification, sanity notes)."""

from analysis.step7_llm_assessment import sanity_check
from backend.threat_intel import classify_c2


def test_unenriched_c2_is_unknown_not_benign():
    # No live_dns and no circl: absence of evidence must not read as benign.
    label, reason = classify_c2({"domain": "unverified-host.example", "live_dns": {}, "circl": {}})
    assert label == "unknown"
    assert "no positive benign evidence" in reason


def test_ip_only_c2_is_not_called_junk_benign():
    # An IP-only indicator has no domain; it must not be marked benign as a "junk domain".
    label, reason = classify_c2({"ip": "61.164.109.77", "live_dns": {}, "circl": {}})
    assert label != "benign"
    assert "junk" not in reason
    assert "IP-direct" in reason


def test_enriched_clean_c2_is_still_benign():
    # Enrichment ran and found an established domain, so benign stays benign.
    c2 = {
        "domain": "established-host.example",
        "live_dns": {"resolves": True},
        "circl": {"pdns_domain": {"count": 12}},
    }
    label, _ = classify_c2(c2)
    assert label == "benign"


def test_sanity_notes_stay_out_of_narrative():
    assessment = {"severity": "low", "risk_score": 10, "narrative": "Model narrative."}
    # Only a corroborated endpoint (full URL from code, real path) raises LOW to MEDIUM and adds a note.
    corroborated = {"confidence": 0.9, "path": "/gate/data.php", "is_fallback": False}
    c2_result = {"total_c2s": 2, "c2_infrastructure": [corroborated]}
    out = sanity_check(assessment, {}, c2_result)
    assert out["narrative"] == "Model narrative."
    assert any("SANITY CHECK" in note for note in out.get("sanity_notes", []))
