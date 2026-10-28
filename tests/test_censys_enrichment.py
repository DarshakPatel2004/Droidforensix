"""Censys async enrichment on httpx: status handling, retries and result shape."""

import asyncio

import httpx
import pytest

from backend import censys_enrichment

IP = "8.8.8.8"


def _run_query(handler, monkeypatch):
    """Run one _query_one against a mock transport; returns (result, number of requests)."""
    calls = []

    async def no_sleep(_seconds):
        return None

    def counting_handler(request):
        calls.append(request)
        return handler(request)

    async def main():
        async with httpx.AsyncClient(transport=httpx.MockTransport(counting_handler)) as client:
            return await censys_enrichment._query_one(client, asyncio.Semaphore(1), IP, {})

    monkeypatch.setattr(censys_enrichment.asyncio, "sleep", no_sleep)
    return asyncio.run(main()), len(calls)


def test_not_found_is_reported_without_retry(monkeypatch):
    result, calls = _run_query(lambda request: httpx.Response(404), monkeypatch)
    assert result["_error"] == "not_found"
    assert calls == 1


def test_success_is_extracted(monkeypatch):
    body = {"result": {"resource": {"autonomous_system": {"asn": 15169, "name": "GOOGLE"}}}}
    result, calls = _run_query(lambda request: httpx.Response(200, json=body), monkeypatch)
    assert "_error" not in result
    assert result["ip"] == IP
    assert calls == 1


def test_client_error_is_not_retried(monkeypatch):
    result, calls = _run_query(lambda request: httpx.Response(403), monkeypatch)
    assert "_error" in result
    assert calls == 1


@pytest.mark.parametrize("status", [500, 503])
def test_server_error_is_retried(monkeypatch, status):
    result, calls = _run_query(lambda request: httpx.Response(status), monkeypatch)
    assert "_error" in result
    assert calls == 4
