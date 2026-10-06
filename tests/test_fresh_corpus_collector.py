"""Tests for fresh-corpus collection safeguards."""

from scripts.collect_fresh_corpus import safe_error


def test_safe_error_redacts_api_key():
    secret = "secret-api-key"
    error = RuntimeError("request failed: https://example.invalid/?apikey=secret-api-key")

    assert safe_error(error, secret) == (
        "request failed: https://example.invalid/?apikey=<redacted>"
    )
