from analysis.step7_llm_assessment import SYSTEM_PROMPT


def test_encodings_alone_do_not_default_to_medium():
    # Regression: the rubric once said medium is the default for encodings alone,
    # which put benign libraries with XOR helpers at medium (9 of 15 benign on the subset).
    assert "Default for apps with encodings/permissions/obfuscation" not in SYSTEM_PROMPT
    assert "encoded strings or XOR helpers alone" in SYSTEM_PROMPT


def _capture_create_kwargs(base_url):
    from unittest import mock

    from analysis.step7_llm_assessment import _call_nvidia_nim

    with mock.patch("openai.OpenAI") as client_cls:
        client = client_cls.return_value
        client.chat.completions.create.return_value.choices = [mock.Mock(message=mock.Mock(content="{}"))]
        _call_nvidia_nim("ctx", "some/model", base_url, "key", max_retries=1)
        return client.chat.completions.create.call_args.kwargs


def test_openrouter_calls_turn_reasoning_off():
    kwargs = _capture_create_kwargs("https://openrouter.ai/api/v1")
    assert kwargs["extra_body"] == {"reasoning": {"enabled": False}}


def test_nvidia_calls_are_unchanged():
    kwargs = _capture_create_kwargs("https://integrate.api.nvidia.com/v1")
    assert kwargs["extra_body"] is None
