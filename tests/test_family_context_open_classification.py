"""Unit tests for the LLM-fallback context branch (offline, no LLM call).

Verifies the zero-candidate path in _family_context releases the forced
abstention: when no KB family matches, the context must instruct the model
to classify from evidence (open classification) instead of telling it
"Unknown is ONLY correct if no candidate matches".
"""

from backend import family_id


def _result():
    return {
        "metadata": {"sha256": "11" * 32, "package_name": "com.evil.alpha"},
        "certificate_analysis": {},
        "strings": {"string_literals": ["alpha.sendsms", "alpha.install", "hello"], "byte_arrays": []},
        "c2_infrastructure": [],
        "obfuscation_analysis": {},
        "threat_chains": [],
        "encodings": [],
        "payloads": [],
        "extraction": {},
        "llm_assessment": {},
    }


class TestOpenClassificationBranch:
    def test_no_candidate_emits_open_classification_instruction(self):
        ctx = family_id._family_context(_result(), sample_id="11" * 32)
        assert "no candidate family has any matched signal" in ctx
        assert "OPEN CLASSIFICATION" in ctx
        assert "Unknown is ONLY correct if no candidate matches" not in ctx

    def test_candidate_present_keeps_multiple_choice(self):
        # 50 shared bytes of a real family's discriminator -> candidate appears.
        kb = family_id._kb_load()
        target = None
        for name, fp in kb.items():
            if fp.get("strings"):
                target = fp["strings"][0]["token"]
                break
        assert target is not None, "KB has no string discriminators to test with"
        ctx = family_id._family_context(
            {
                **_result(),
                "strings": {
                    "string_literals": [target] * 60,
                    "byte_arrays": [],
                },
            },
            sample_id="22" * 32,
        )
        assert target in ctx
        assert "CANDIDATES" in ctx


class TestNudgedOpenClassification:
    """The open branch must push for a best-effort family call (probe-verified:
    lane 11/84 -> 23/84 official is_correct, 0 regressions on GT-unknown)."""

    def test_context_tail_demands_best_effort_call(self):
        ctx = family_id._family_context(_result(), sample_id="11" * 32)
        assert "best-effort family call at moderate confidence" in ctx
        assert "reserve 'unknown' for samples with no malicious behavior" in ctx

    def test_evidence_label_points_at_profiles_not_dismissal(self):
        ctx = family_id._family_context(_result(), sample_id="11" * 32)
        assert "judge them against candidate signals or family profiles" in ctx
        assert "not matched to any candidate" not in ctx

    def test_system_prompt_has_profiles_and_bans_category_output(self):
        prompt = family_id._FAMILY_SYSTEM_PROMPT
        assert "best-effort call whenever the APK" in prompt
        assert "never a behavior-category phrase" in prompt
        assert "FakeInstaller / FakeInst" in prompt
        assert "not the behavior class" in prompt