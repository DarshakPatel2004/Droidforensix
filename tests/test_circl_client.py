"""
Tests for the CIRCL enrichment client.
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
import requests

from backend.circl_client import (
    CIRCLAuthError,
    CIRCLClient,
    CIRCLClientError,
    CIRCLTimeoutError,
    enrich_c2s,
)


@pytest.fixture
def client():
    return CIRCLClient(username="test_user", password="test_pass")


class TestCIRCLClientInit:
    def test_missing_username(self, monkeypatch):
        monkeypatch.delenv("CIRCL_USERNAME", raising=False)
        monkeypatch.delenv("CIRCL_PASSWORD", raising=False)
        with pytest.raises(CIRCLAuthError):
            CIRCLClient(username=None, password="pass")

    def test_missing_password(self, monkeypatch):
        monkeypatch.delenv("CIRCL_USERNAME", raising=False)
        monkeypatch.delenv("CIRCL_PASSWORD", raising=False)
        with pytest.raises(CIRCLAuthError):
            CIRCLClient(username="user", password=None)

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("CIRCL_USERNAME", "env_user")
        monkeypatch.setenv("CIRCL_PASSWORD", "env_pass")
        c = CIRCLClient()
        assert c.username == "env_user"
        assert c.password == "env_pass"


class TestPSSLMethods:
    def test_pssl_query_ip_success(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "8.8.8.8": {"certificates": ["abc123"], "subjects": {}}
        }

        with patch.object(client._session, "request", return_value=mock_response):
            result = client.pssl_query_ip("8.8.8.8")

        assert "8.8.8.8" in result
        assert result["8.8.8.8"]["certificates"] == ["abc123"]

    def test_pssl_query_certificate_success(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"seen": ["1.2.3.4"], "hits": 1}

        with patch.object(client._session, "request", return_value=mock_response):
            result = client.pssl_query_certificate("abc123")

        assert result["seen"] == ["1.2.3.4"]

    def test_pssl_non_200_returns_error(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad request"

        with patch.object(client._session, "request", return_value=mock_response):
            result = client.pssl_query_ip("8.8.8.8")

        assert result["status_code"] == 400
        assert result["error"] == "Bad request"


class TestPDNSMethods:
    def test_pdns_success(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.iter_lines.return_value = iter(
            [json.dumps({"rrtype": "A", "rrname": "example.com"}).encode()]
        )

        with patch.object(client._session, "request", return_value=mock_response):
            result = client.pdns_query("example.com")

        assert result["query"] == "example.com"
        assert result["count"] == 1
        assert result["timed_out"] is False
        assert result["records"][0]["rrtype"] == "A"

    def test_pdns_timeout_graceful(self, client):
        with patch.object(
            client._session,
            "request",
            side_effect=requests.exceptions.Timeout,
        ):
            result = client.pdns_query("example.com")

        assert result["query"] == "example.com"
        assert result["timed_out"] is True
        assert result["count"] == 0

    def test_pdns_non_200_returns_error(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Not found"
        mock_response.headers = {}

        with patch.object(client._session, "request", return_value=mock_response):
            result = client.pdns_query("example.com")

        assert result["status_code"] == 404
        assert result["error"] == "Not found"


class TestEnrichment:
    def test_enrich_c2_with_ip_and_domain(self, client):
        c2s = [{"ip": "8.8.8.8", "domain": "example.com"}]

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            if "/v2pssl/query/" in url:
                response.status_code = 200
                response.json.return_value = {"8.8.8.8": {"certificates": ["abc"]}}
            elif "/pdns/query/" in url:
                response.status_code = 200
                response.headers = {}
                response.iter_lines.return_value = iter([b'{"rrtype":"A"}'])
            else:
                response.status_code = 404
                response.text = "Not found"
                response.headers = {}
            return response

        with patch.object(client._session, "request", side_effect=mock_request):
            result = client.enrich_c2_infrastructure(c2s)

        assert len(result) == 1
        assert "circl" in result[0]
        assert "pssl_ip" in result[0]["circl"]
        assert "pdns_domain" in result[0]["circl"]

    def test_enrich_c2_url_extracts_domain(self, client):
        c2s = [{"url": "http://evil.com/path"}]

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.status_code = 200
            response.headers = {}
            response.iter_lines.return_value = iter([b'{"rrtype":"A"}'])
            return response

        with patch.object(client._session, "request", side_effect=mock_request):
            result = client.enrich_c2_infrastructure(c2s, include_pssl=False)

        assert result[0]["circl"]["pdns_domain"]["query"] == "evil.com"


class TestErrors:
    def test_auth_error_401(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with patch.object(client._session, "request", return_value=mock_response):
            with pytest.raises(CIRCLAuthError):
                client.pssl_query_ip("8.8.8.8")

    def test_request_exception(self, client):
        with patch.object(
            client._session,
            "request",
            side_effect=requests.exceptions.ConnectionError("boom"),
        ):
            with pytest.raises(CIRCLClientError):
                client.pssl_query_ip("8.8.8.8")


class TestModuleFunctions:
    def test_enrich_c2s_without_env_vars(self, monkeypatch):
        monkeypatch.delenv("CIRCL_USERNAME", raising=False)
        monkeypatch.delenv("CIRCL_PASSWORD", raising=False)
        # Should raise because no credentials in environment
        with pytest.raises(CIRCLAuthError):
            enrich_c2s([{"ip": "8.8.8.8"}])

    def test_enrich_c2s_with_env_vars(self, monkeypatch):
        monkeypatch.setenv("CIRCL_USERNAME", "u")
        monkeypatch.setenv("CIRCL_PASSWORD", "p")

        with patch("backend.circl_client.CIRCLClient.enrich_c2_infrastructure") as mock:
            mock.return_value = [{"ip": "8.8.8.8", "circl": {}}]
            result = enrich_c2s([{"ip": "8.8.8.8"}])
            assert result[0]["ip"] == "8.8.8.8"


class TestPDNSPaginationAndFiltering:
    def test_pdns_rrtype_filter_header(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.iter_lines.return_value = iter([])

        with patch.object(client._session, "request", return_value=mock_response) as mock:
            client.pdns_query("example.com", rrtype="A")

        call_kwargs = mock.call_args.kwargs
        assert call_kwargs["headers"]["dribble-filter-rrtype"] == "A"

    def test_pdns_streaming_parse(self, client):
        lines = [
            b'{"rrtype":"A","rrname":"example.com"}',
            b"",
            b"not-json",
            b'{"rrtype":"AAAA","rrname":"example.com"}',
        ]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.iter_lines.return_value = iter(lines)

        with patch.object(client._session, "request", return_value=mock_response):
            result = client.pdns_query("example.com")

        assert result["count"] == 2
        assert result["records"][0]["rrtype"] == "A"
        assert result["records"][1]["rrtype"] == "AAAA"

    def test_pdns_auto_paginate_follows_cursor(self, client):
        responses = []
        for i in range(3):
            response = MagicMock()
            response.status_code = 200
            response.headers = {"x-dribble-paginate": str(i + 1) if i < 2 else ""}
            response.iter_lines.return_value = iter(
                [json.dumps({"rrtype": "A", "page": i}).encode()]
            )
            responses.append(response)

        with patch.object(client._session, "request", side_effect=responses) as mock:
            result = client.pdns_query(
                "example.com", paginate_count=10, auto_paginate=True
            )

        assert result["count"] == 3
        assert result["pages_fetched"] == 3
        assert mock.call_count == 3
        # Cursor should be passed on second and third requests.
        second_call_headers = mock.call_args_list[1].kwargs["headers"]
        third_call_headers = mock.call_args_list[2].kwargs["headers"]
        assert second_call_headers["dribble-paginate-cursor"] == "1"
        assert third_call_headers["dribble-paginate-cursor"] == "2"

    def test_pdns_auto_paginate_respects_max_pages(self, client):
        responses = []
        for i in range(5):
            response = MagicMock()
            response.status_code = 200
            response.headers = {"x-dribble-paginate": str(i + 1)}
            response.iter_lines.return_value = iter(
                [json.dumps({"rrtype": "A", "page": i}).encode()]
            )
            responses.append(response)

        with patch.object(client._session, "request", side_effect=responses) as mock:
            result = client.pdns_query(
                "example.com",
                paginate_count=10,
                auto_paginate=True,
                max_pages=2,
            )

        assert result["pages_fetched"] == 2
        assert mock.call_count == 2

    def test_pdns_dribble_errors_parsed(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "x-dribble-errors": json.dumps(
                [{"error": "maxset", "record": "example.com", "value": 1000}]
            )
        }
        mock_response.iter_lines.return_value = iter([])

        with patch.object(client._session, "request", return_value=mock_response):
            result = client.pdns_query("example.com")

        assert len(result["dribble_errors"]) == 1
        assert result["dribble_errors"][0]["error"] == "maxset"

    def test_pdns_timeout_mid_pagination(self, client):
        first_response = MagicMock()
        first_response.status_code = 200
        first_response.headers = {"x-dribble-paginate": "abc"}
        first_response.iter_lines.return_value = iter([b'{"rrtype":"A"}'])

        with patch.object(
            client._session,
            "request",
            side_effect=[first_response, requests.exceptions.Timeout],
        ):
            result = client.pdns_query(
                "example.com", paginate_count=10, auto_paginate=True
            )

        assert result["timed_out"] is True
        assert result["count"] == 1
        assert result["pages_fetched"] == 1
