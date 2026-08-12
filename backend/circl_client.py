"""
CIRCL enrichment client for C2 infrastructure analysis.

Supports:
- pSSL v2: IP -> certificate history, certificate -> IP history
- pDNS: domain/IP -> passive DNS records (best-effort; CIRCL pDNS is
  currently timing out for some accounts, so calls gracefully degrade)

Credentials are read from environment variables:
    CIRCL_USERNAME
    CIRCL_PASSWORD
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import requests
from requests.auth import HTTPBasicAuth


CIRCL_BASE_URL = "https://www.circl.lu"
DEFAULT_TIMEOUT = 15  # seconds; pDNS is flaky so keep it short
DEFAULT_PDNS_TIMEOUT = 8  # even shorter for pDNS since it often hangs
RATE_LIMIT_DELAY = 2.0  # CIRCL asks for ~1 request every 2 seconds


class CIRCLClientError(Exception):
    """Base exception for CIRCL client errors."""


class CIRCLAuthError(CIRCLClientError):
    """Raised when credentials are invalid or missing."""


class CIRCLTimeoutError(CIRCLClientError):
    """Raised when CIRCL service times out (common for pDNS currently)."""


class CIRCLClient:
    """Thin client for CIRCL pDNS and pSSL APIs."""

    def __init__(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        base_url: str = CIRCL_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
        pdns_timeout: int = DEFAULT_PDNS_TIMEOUT,
        rate_limit_delay: float = RATE_LIMIT_DELAY,
    ):
        self.username = username or os.getenv("CIRCL_USERNAME")
        self.password = password or os.getenv("CIRCL_PASSWORD")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.pdns_timeout = pdns_timeout
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time: Optional[float] = None
        self._session = requests.Session()

        if not self.username or not self.password:
            raise CIRCLAuthError(
                "CIRCL credentials not configured. Set CIRCL_USERNAME and "
                "CIRCL_PASSWORD environment variables."
            )

        self._auth = HTTPBasicAuth(self.username, self.password)

    def _request(
        self,
        method: str,
        path: str,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        stream: bool = False,
    ) -> requests.Response:
        """Make a rate-limited request to CIRCL."""
        self._rate_limit()
        url = f"{self.base_url}{path}"
        try:
            response = self._session.request(
                method,
                url,
                auth=self._auth,
                headers=headers,
                json=json_data,
                timeout=timeout if timeout is not None else self.timeout,
                stream=stream,
            )
        except requests.exceptions.Timeout as exc:
            raise CIRCLTimeoutError(f"CIRCL request timed out: {url}") from exc
        except requests.exceptions.RequestException as exc:
            raise CIRCLClientError(f"CIRCL request failed: {exc}") from exc
        finally:
            self._last_request_time = time.time()

        if response.status_code == 401:
            raise CIRCLAuthError("Invalid CIRCL credentials (401 Unauthorized)")
        return response

    def _rate_limit(self) -> None:
        """Sleep if needed to respect CIRCL rate limit guidance."""
        if self._last_request_time is not None and self.rate_limit_delay > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - elapsed)

    @staticmethod
    def _parse_ndjson(text: str) -> List[Dict[str, Any]]:
        """Parse newline-delimited JSON returned by pDNS."""
        records = []
        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records

    @staticmethod
    def _parse_ndjson_stream(response: requests.Response) -> List[Dict[str, Any]]:
        """Parse newline-delimited JSON from a streaming response."""
        records = []
        for raw_line in response.iter_lines():
            if not raw_line:
                continue
            try:
                line = raw_line.decode("utf-8").strip()
                if line:
                    records.append(json.loads(line))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
        return records

    # -----------------------------------------------------------------------
    # pSSL v2
    # -----------------------------------------------------------------------

    def pssl_query_ip(self, ip: str) -> Dict[str, Any]:
        """Query pSSL for certificate history seen for an IP address."""
        response = self._request("GET", f"/v2pssl/query/{ip}")
        if response.status_code == 200:
            return response.json()
        return {"error": response.text, "status_code": response.status_code}

    def pssl_query_cidr(self, cidr: str) -> Dict[str, Any]:
        """Query pSSL for certificates seen for a CIDR block."""
        response = self._request("GET", f"/v2pssl/query/{cidr}")
        if response.status_code == 200:
            return response.json()
        return {"error": response.text, "status_code": response.status_code}

    def pssl_query_certificate(self, fingerprint: str) -> Dict[str, Any]:
        """Query pSSL for IP history seen for a certificate SHA1 fingerprint."""
        response = self._request("GET", f"/v2pssl/cquery/{fingerprint}")
        if response.status_code == 200:
            return response.json()
        return {"error": response.text, "status_code": response.status_code}

    def pssl_fetch_certificate(self, fingerprint: str) -> Dict[str, Any]:
        """Fetch certificate details for a SHA1 fingerprint."""
        response = self._request("GET", f"/v2pssl/cfetch/{fingerprint}")
        if response.status_code == 200:
            return response.json()
        return {"error": response.text, "status_code": response.status_code}

    # -----------------------------------------------------------------------
    # pDNS (best-effort; currently hangs for some CIRCL accounts)
    # -----------------------------------------------------------------------

    def pdns_query(
        self,
        query_value: str,
        paginate_count: Optional[int] = None,
        disable_active_query: bool = True,
        rrtype: Optional[str] = None,
        auto_paginate: bool = False,
        max_pages: int = 10,
    ) -> Dict[str, Any]:
        """
        Query CIRCL passive DNS for a domain or IP.

        Parameters
        ----------
        query_value:
            Domain or IP to query.
        paginate_count:
            Number of records to request per page. Strongly recommended for
            large/popular domains to avoid timeouts.
        disable_active_query:
            If True (default), disable the active resolver and use only the
            passive database.
        rrtype:
            Optional DNS record type to filter on (e.g. ``A``, ``AAAA``,
            ``CNAME``). This dramatically reduces response size.
        auto_paginate:
            If True and ``paginate_count`` is set, follow the
            ``x-dribble-paginate`` cursor until all pages are retrieved or
            ``max_pages`` is reached.
        max_pages:
            Hard limit on the number of pages to fetch when auto-paginating.

        Returns
        -------
        Dict with ``query``, ``records``, ``count``, ``timed_out`` and
        pagination metadata.
        """
        headers: Dict[str, str] = {}
        if paginate_count is not None:
            headers["dribble-paginate-count"] = str(paginate_count)
        if disable_active_query:
            headers["dribble-disable-active-query"] = "1"
        if rrtype:
            headers["dribble-filter-rrtype"] = rrtype

        records: List[Dict[str, Any]] = []
        pages_fetched = 0
        cursor: Optional[str] = None
        dribble_errors: List[Dict[str, Any]] = []
        timed_out = False

        while True:
            page_headers = dict(headers)
            if cursor is not None:
                page_headers["dribble-paginate-cursor"] = cursor

            try:
                response = self._request(
                    "GET",
                    f"/pdns/query/{query_value}",
                    timeout=self.pdns_timeout,
                    headers=page_headers,
                    stream=True,
                )
            except CIRCLTimeoutError:
                timed_out = True
                break

            if response.status_code != 200:
                return {
                    "query": query_value,
                    "records": records,
                    "count": len(records),
                    "status_code": response.status_code,
                    "error": response.text,
                    "timed_out": timed_out,
                    "pages_fetched": pages_fetched,
                }

            page_records = self._parse_ndjson_stream(response)
            records.extend(page_records)
            pages_fetched += 1

            # Capture server-side error/warning headers.
            raw_errors = response.headers.get("x-dribble-errors")
            if raw_errors:
                try:
                    parsed_errors = json.loads(raw_errors)
                    if isinstance(parsed_errors, list):
                        dribble_errors.extend(parsed_errors)
                    else:
                        dribble_errors.append(parsed_errors)
                except json.JSONDecodeError:
                    dribble_errors.append({"raw": raw_errors})

            # Pagination cursor handling.
            cursor = response.headers.get("x-dribble-paginate")
            if not auto_paginate or not cursor or pages_fetched >= max_pages:
                break

        result: Dict[str, Any] = {
            "query": query_value,
            "records": records,
            "count": len(records),
            "timed_out": timed_out,
            "pages_fetched": pages_fetched,
        }
        if rrtype:
            result["rrtype_filter"] = rrtype
        if dribble_errors:
            result["dribble_errors"] = dribble_errors
        if timed_out:
            result["note"] = (
                "CIRCL pDNS timed out before all pages could be retrieved. "
                "Try reducing paginate_count or narrowing the query with rrtype."
            )
        return result

    # -----------------------------------------------------------------------
    # C2 enrichment
    # -----------------------------------------------------------------------

    def enrich_c2_infrastructure(
        self,
        c2_list: List[Dict[str, Any]],
        include_pdns: bool = True,
        include_pssl: bool = True,
        pdns_rrtype: Optional[str] = "A",
        pdns_paginate_count: Optional[int] = 100,
        pdns_auto_paginate: bool = True,
        pdns_max_pages: int = 10,
        max_records: Optional[int] = None,
        time_budget: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """
        Enrich a list of C2 indicators with CIRCL pSSL/pDNS data.

        Expected input items have at least one of: ip, domain, url, cert_sha1.

        pDNS defaults are tuned for C2 lookups: A-records only, 100 records per
        page, auto-paginate up to 10 pages. This avoids the large responses and
        timeouts that plague unfiltered pDNS queries for popular domains.

        max_records: hard cap on the number of items enriched (enrich the
            first N in list order). Defaults to unlimited.
        time_budget: overall wall-clock budget in seconds, checked between
            records; enrichment stops when exceeded (items are skipped, never
            failed). Defaults to unlimited. Use this so a slow/unreachable
            CIRCL service cannot stall callers indefinitely.
        """
        enriched = []
        start_time = time.time()
        for idx, c2 in enumerate(c2_list):
            if max_records is not None and idx >= max_records:
                break
            if time_budget is not None and time.time() - start_time >= time_budget:
                break
            c2 = dict(c2)
            circl_data: Dict[str, Any] = {}

            # Extract host from URL if domain is missing
            domain = c2.get("domain") or self._extract_domain(c2.get("url"))
            ip = c2.get("ip")
            cert_sha1 = c2.get("cert_sha1")

            if include_pssl:
                if ip:
                    try:
                        circl_data["pssl_ip"] = self.pssl_query_ip(ip)
                    except CIRCLClientError as e:
                        circl_data["pssl_ip_error"] = str(e)

                if cert_sha1:
                    try:
                        circl_data["pssl_cert"] = self.pssl_query_certificate(cert_sha1)
                    except CIRCLClientError as e:
                        circl_data["pssl_cert_error"] = str(e)

            if include_pdns:
                if domain:
                    try:
                        circl_data["pdns_domain"] = self.pdns_query(
                            domain,
                            rrtype=pdns_rrtype,
                            paginate_count=pdns_paginate_count,
                            auto_paginate=pdns_auto_paginate,
                            max_pages=pdns_max_pages,
                        )
                    except CIRCLClientError as e:
                        circl_data["pdns_domain_error"] = str(e)

                if ip:
                    try:
                        circl_data["pdns_ip"] = self.pdns_query(
                            ip,
                            rrtype=None,
                            paginate_count=pdns_paginate_count,
                            auto_paginate=pdns_auto_paginate,
                            max_pages=pdns_max_pages,
                        )
                    except CIRCLClientError as e:
                        circl_data["pdns_ip_error"] = str(e)

            c2["circl"] = circl_data
            enriched.append(c2)

        return enriched

    @staticmethod
    def _extract_domain(url: Optional[str]) -> Optional[str]:
        """Naive domain extraction from a URL."""
        if not url:
            return None
        url = url.strip()
        if "://" in url:
            url = url.split("://", 1)[1]
        url = url.split("/", 1)[0]
        url = url.split(":", 1)[0]
        return url if url else None


# ---------------------------------------------------------------------------
# Convenience module-level functions
# ---------------------------------------------------------------------------


def get_client() -> CIRCLClient:
    """Return a configured CIRCLClient from environment variables."""
    return CIRCLClient()


def enrich_c2s(
    c2_list: List[Dict[str, Any]],
    include_pdns: bool = True,
    include_pssl: bool = True,
    pdns_rrtype: Optional[str] = "A",
    pdns_paginate_count: Optional[int] = 100,
    pdns_auto_paginate: bool = True,
    pdns_max_pages: int = 10,
) -> List[Dict[str, Any]]:
    """Convenience function to enrich C2s using env-var credentials."""
    client = get_client()
    return client.enrich_c2_infrastructure(
        c2_list,
        include_pdns=include_pdns,
        include_pssl=include_pssl,
        pdns_rrtype=pdns_rrtype,
        pdns_paginate_count=pdns_paginate_count,
        pdns_auto_paginate=pdns_auto_paginate,
        pdns_max_pages=pdns_max_pages,
    )


def test_credentials() -> Dict[str, Any]:
    """Quickly test whether CIRCL credentials are valid and services respond."""
    client = get_client()
    results = {
        "credentials_configured": True,
        "pssl": {},
        "pdns": {},
    }

    try:
        resp = client.pssl_query_ip("8.8.8.8")
        results["pssl"] = {"ok": "error" not in resp, "sample": resp}
    except Exception as e:
        results["pssl"] = {"ok": False, "error": str(e)}

    try:
        resp = client.pdns_query("circl.lu")
        results["pdns"] = {"ok": resp.get("timed_out") is False, "sample": resp}
    except Exception as e:
        results["pdns"] = {"ok": False, "error": str(e)}

    return results
