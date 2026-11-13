"""Canned-response tests for the LLM output parsers (T-10).

Covers step7's JSON extraction and assessment validation, the step7 retry and
fallback loop, and the family-ID verdict parser in backend/family_id.py. No
network: the OpenAI client is replaced at the openai.OpenAI boundary.
"""

import hashlib
import json
from types import SimpleNamespace

import openai
import pytest

import analysis.step7_llm_assessment as step7
from backend import family_id

SAMPLE_ID = hashlib.sha256(b"closure-llm-parser").hexdigest()


# ---------------------------------------------------------------------------
# step7: parse_llm_json
# ---------------------------------------------------------------------------


class TestParseLlmJson:
    def test_plain_object(self):
        assert step7.parse_llm_json('{"severity": "low", "risk_score": 3}') == {"severity": "low", "risk_score": 3}

    def test_fenced_json_block_is_unwrapped(self):
        raw = '```json\n{"severity": "high"}\n```'
        assert step7.parse_llm_json(raw) == {"severity": "high"}

    def test_object_wrapped_in_prose_is_extracted(self):
        raw = 'Sure, here is the verdict: {"severity": "medium", "risk_score": 40} Hope it helps.'
        assert step7.parse_llm_json(raw) == {"severity": "medium", "risk_score": 40}

    @pytest.mark.parametrize("raw", [
        '{"severity": "low", "risk_score": ',   # truncated mid-object
        "I cannot comply with that request.",   # no JSON at all
        "",                                     # empty completion
    ])
    def test_unparseable_output_returns_none(self, raw):
        assert step7.parse_llm_json(raw) is None

    def test_bare_array_is_returned_as_is(self):
        # Valid JSON is returned without an object check; callers must type-check it.
        assert step7.parse_llm_json("[1, 2, 3]") == [1, 2, 3]


# ---------------------------------------------------------------------------
# step7: validate_assessment
# ---------------------------------------------------------------------------


def _valid_assessment(**overrides):
    base = {"severity": "high", "risk_score": 75, "narrative": "n", "recommended_actions": ["isolate"]}
    base.update(overrides)
    return base


class TestValidateAssessment:
    def test_accepts_well_formed_assessment(self):
        assert step7.validate_assessment(_valid_assessment()) is True

    @pytest.mark.parametrize("missing", ["severity", "risk_score", "narrative", "recommended_actions"])
    def test_rejects_missing_required_key(self, missing):
        data = _valid_assessment()
        del data[missing]
        assert step7.validate_assessment(data) is False

    @pytest.mark.parametrize("severity", ["severe", "HIGH", "", None])
    def test_rejects_unknown_severity(self, severity):
        assert step7.validate_assessment(_valid_assessment(severity=severity)) is False

    @pytest.mark.parametrize("score", [-1, 101, 50.0, "50", None])
    def test_rejects_out_of_range_or_wrong_type_score(self, score):
        assert step7.validate_assessment(_valid_assessment(risk_score=score)) is False

    def test_rejects_boolean_risk_score(self):
        # bool is a subclass of int, so the guard must reject it explicitly.
        assert step7.validate_assessment(_valid_assessment(risk_score=True)) is False

    def test_rejects_non_list_actions(self):
        assert step7.validate_assessment(_valid_assessment(recommended_actions="isolate")) is False


# ---------------------------------------------------------------------------
# step7: assess_with_llm retry and fallback loop
# ---------------------------------------------------------------------------


@pytest.fixture
def nim_provider(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_PROVIDER", "nvidia")
    monkeypatch.setattr(step7, "_api_key", lambda name: "closure-test-key")
    monkeypatch.setattr(step7, "should_skip_llm", lambda *a, **k: False)
    monkeypatch.setattr(step7.time, "sleep", lambda s: None)
    chains = {"sample_id": SAMPLE_ID, "work_dir": str(tmp_path), "chains": []}
    c2 = {"sample_id": SAMPLE_ID, "work_dir": str(tmp_path), "total_c2s": 0, "c2_infrastructure": []}
    return chains, c2


class TestAssessWithLlmLoop:
    def test_malformed_then_valid_response_is_accepted_on_retry(self, monkeypatch, nim_provider):
        chains, c2 = nim_provider
        replies = iter([
            "Sorry, I cannot help.",
            json.dumps(_valid_assessment(severity="high", risk_score=70)),
        ])
        calls = []

        def fake_nim(context, model, base_url, api_key, max_retries=2):
            calls.append(context)
            return next(replies)

        monkeypatch.setattr(step7, "_call_nvidia_nim", fake_nim)
        out = step7.assess_with_llm(chains, c2)
        assert out["method"] == "llm"
        # The fixture extracts no C2, so sanity_check caps the LLM's 70 at 50.
        assert out["risk_score"] == 50
        assert len(calls) == 2
        # The retry prompt tells the model its previous answer was invalid.
        assert calls[1].startswith("Your previous response was invalid.")

    def test_two_invalid_responses_fall_back_to_heuristics(self, monkeypatch, nim_provider):
        chains, c2 = nim_provider
        monkeypatch.setattr(step7, "_call_nvidia_nim", lambda *a, **k: '{"severity": "bogus"}')
        out = step7.assess_with_llm(chains, c2)
        assert out.get("method") != "llm"
        assert out["raw_llm_output"] == '{"severity": "bogus"}'

    def test_provider_exception_falls_back_and_reports_error(self, monkeypatch, nim_provider):
        chains, c2 = nim_provider

        def exploding(*a, **k):
            raise ConnectionError("nim unreachable")

        monkeypatch.setattr(step7, "_call_nvidia_nim", exploding)
        out = step7.assess_with_llm(chains, c2)
        assert out.get("method") != "llm"
        assert out["raw_llm_output"].startswith("LLM assessment error: ")


# ---------------------------------------------------------------------------
# backend/family_id.py: LLM family verdict parser
# ---------------------------------------------------------------------------


KNOWN_FAMILY = family_id.FAMILY_SIGNATURES[0].family_name


class _FakeClient:
    """Replaces openai.OpenAI; every chat completion returns the given text."""

    def __init__(self, content=None, error=None):
        self._content = content
        self._error = error
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        if self._error is not None:
            raise self._error
        message = SimpleNamespace(content=self._content)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


@pytest.fixture
def family_llm(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "closure-test-key")
    monkeypatch.delenv("NVIDIA_NIM_API_KEY", raising=False)

    def use(content=None, error=None):
        monkeypatch.setattr(openai, "OpenAI", lambda **kwargs: _FakeClient(content=content, error=error))

    return use


RESULT = {"sample_id": SAMPLE_ID, "metadata": {"package_name": "com.example.closure"}}


def _verdict(**fields):
    return json.dumps(fields)


class TestFamilyLlmVerdict:
    def test_known_family_is_returned_with_canonical_spelling(self, family_llm):
        family_llm(_verdict(family=KNOWN_FAMILY.lower(), confidence=0.7, reasoning="string match"))
        verdict = family_id._llm_family(RESULT)
        assert verdict == {
            "family": KNOWN_FAMILY,
            "source": "llm",
            "confidence": 0.7,
            "reasoning": "string match",
        }

    def test_unknown_label_is_accepted_as_unknown(self, family_llm):
        family_llm(_verdict(family="unknown", confidence=0.2))
        assert family_id._llm_family(RESULT)["family"] == "unknown"

    def test_invented_family_name_is_discarded(self, family_llm):
        # A free-generated name is not a justified attribution and must not become one.
        family_llm(_verdict(family="NotARealFamily9000", confidence=0.99))
        assert family_id._llm_family(RESULT) is None

    @pytest.mark.parametrize("family", ["none", "N/A", "  "])
    def test_empty_style_labels_are_no_verdict(self, family_llm, family):
        family_llm(_verdict(family=family, confidence=0.9))
        assert family_id._llm_family(RESULT) is None

    @pytest.mark.parametrize("content", ["not json at all", '{"confidence": 0.9}', "[]"])
    def test_malformed_or_familyless_output_is_no_verdict(self, family_llm, content):
        family_llm(content)
        assert family_id._llm_family(RESULT) is None

    def test_prose_wrapped_verdict_is_still_parsed(self, family_llm):
        family_llm("Verdict: " + _verdict(family=KNOWN_FAMILY, confidence=0.5) + " end")
        assert family_id._llm_family(RESULT)["family"] == KNOWN_FAMILY

    @pytest.mark.parametrize("raw, expected", [("5", 1.0), ("-3", 0.0), ('"high"', 0.5)])
    def test_confidence_is_clamped_or_defaulted(self, family_llm, raw, expected):
        family_llm('{"family": "%s", "confidence": %s}' % (KNOWN_FAMILY, raw))
        assert family_id._llm_family(RESULT)["confidence"] == expected

    def test_reasoning_is_truncated_to_300_chars(self, family_llm):
        family_llm(_verdict(family=KNOWN_FAMILY, confidence=0.5, reasoning="x" * 500))
        assert len(family_id._llm_family(RESULT)["reasoning"]) == 300

    def test_provider_error_is_no_verdict(self, family_llm):
        family_llm(error=RuntimeError("upstream 500"))
        assert family_id._llm_family(RESULT) is None
