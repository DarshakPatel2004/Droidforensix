"""
Threat Intelligence Enrichment Module for DroidForensix

Queries multiple TI sources (VirusTotal, OTX, Shodan, Censys) for indicators.
Handles timeouts, rate limits, and missing API keys gracefully.

Usage:
    enricher = ThreatIntelligenceEnricher(
        vt_key="your-vt-key",
        otx_key="your-otx-key",
    )
    result = enricher.enrich("malicious.com", indicator_type="domain")
    print(result.risk_level)
    for evidence in result.evidence:
        print(f"  - {evidence}")
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

API_TIMEOUT = 5
MAX_WORKERS = 4


@dataclass
class TIResult:
    """Unified threat intelligence result across all sources."""

    indicator: str
    indicator_type: str

    vt_result: Dict[str, Any] = field(default_factory=dict)
    otx_result: Dict[str, Any] = field(default_factory=dict)
    shodan_result: Dict[str, Any] = field(default_factory=dict)
    censys_result: Dict[str, Any] = field(default_factory=dict)

    risk_level: str = "LOW"
    risk_score: float = 0.0
    evidence: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    queried_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    sources_available: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "evidence": self.evidence,
            "errors": self.errors,
            "sources_available": self.sources_available,
            "queried_at": self.queried_at,
            "raw": {
                "vt": self.vt_result,
                "otx": self.otx_result,
                "shodan": self.shodan_result,
                "censys": self.censys_result,
            },
        }


class ThreatIntelligenceEnricher:
    """Query multiple TI sources and consolidate results."""

    def __init__(
        self,
        vt_key: Optional[str] = None,
        otx_key: Optional[str] = None,
        shodan_key: Optional[str] = None,
        censys_token: Optional[str] = None,
        censys_org_id: Optional[str] = None,
        timeout: int = API_TIMEOUT,
        skip_sources: Optional[List[str]] = None,
    ):
        self.vt_key = vt_key
        self.otx_key = otx_key
        self.shodan_key = shodan_key
        self.censys_token = censys_token
        self.censys_org_id = censys_org_id
        self.timeout = timeout
        self.skip_sources = skip_sources or []

        if not any([self.vt_key, self.otx_key, self.shodan_key, self.censys_token]):
            logger.warning(
                "No TI sources configured. Enrichment will return empty results."
            )

    def enrich(
        self,
        indicator: str,
        indicator_type: str,
    ) -> TIResult:
        """Enrich an indicator with threat intelligence."""
        logger.info("Enriching %s: %s", indicator_type, indicator)

        result = TIResult(indicator=indicator, indicator_type=indicator_type)

        futures: Dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            if "vt" not in self.skip_sources and self.vt_key:
                futures["vt"] = executor.submit(
                    self._query_vt, indicator, indicator_type
                )

            if "otx" not in self.skip_sources and self.otx_key:
                futures["otx"] = executor.submit(self._query_otx, indicator)

            if (
                "shodan" not in self.skip_sources
                and self.shodan_key
                and indicator_type == "ip"
            ):
                futures["shodan"] = executor.submit(self._query_shodan, indicator)

            if (
                "censys" not in self.skip_sources
                and self.censys_token
                and indicator_type in ("domain", "ip")
            ):
                futures["censys"] = executor.submit(
                    self._query_censys, indicator, indicator_type
                )

            for source, future in futures.items():
                try:
                    data = future.result(timeout=self.timeout * 2)
                    if source == "vt":
                        result.vt_result = data
                    elif source == "otx":
                        result.otx_result = data
                    elif source == "shodan":
                        result.shodan_result = data
                    elif source == "censys":
                        result.censys_result = data
                    result.sources_available.append(source)
                except Exception as e:
                    error_msg = f"{source}: {e}"
                    result.errors.append(error_msg)
                    logger.warning("TI source failed: %s", error_msg)

        self._consolidate(result)

        logger.info(
            "Enrichment complete: %s risk, sources: %s",
            result.risk_level,
            result.sources_available,
        )

        return result

    # ============ Individual Source Queries ============

    def _query_vt(self, indicator: str, itype: str) -> Dict[str, Any]:
        try:
            if itype == "domain":
                url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
            elif itype == "ip":
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
            elif itype == "hash":
                url = f"https://www.virustotal.com/api/v3/files/{indicator}"
            else:
                return {"error": f"Unknown indicator type: {itype}"}

            headers = {"x-apikey": self.vt_key}
            resp = requests.get(url, headers=headers, timeout=self.timeout)

            if resp.status_code == 404:
                return {"found": False, "message": "Not in VirusTotal"}
            if resp.status_code == 401:
                raise ValueError("Invalid VirusTotal API key")
            if resp.status_code == 429:
                raise RuntimeError("VirusTotal rate limited")
            if resp.status_code != 200:
                raise RuntimeError(f"VirusTotal error: {resp.status_code}")

            data = resp.json().get("data", {})
            attributes = data.get("attributes", {})
            last_analysis = attributes.get("last_analysis_stats", {})

            return {
                "found": True,
                "detected": last_analysis.get("malicious", 0),
                "suspicious": last_analysis.get("suspicious", 0),
                "total_vendors": 70,
                "detection_ratio": f"{last_analysis.get('malicious', 0)}/70",
                "tags": attributes.get("tags", []),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "categories": attributes.get("categories", {}),
                "reputation": attributes.get("reputation", 0),
            }

        except requests.Timeout:
            return {"error": "Request timeout"}
        except Exception as e:
            return {"error": str(e)}

    def _query_otx(self, indicator: str) -> Dict[str, Any]:
        try:
            endpoints = [
                f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/pulses",
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/pulses",
            ]

            headers = {"X-OTX-API-KEY": self.otx_key}

            for endpoint in endpoints:
                try:
                    resp = requests.get(
                        endpoint, headers=headers, timeout=self.timeout
                    )

                    if resp.status_code == 401:
                        raise ValueError("Invalid OTX API key")
                    if resp.status_code == 429:
                        raise RuntimeError("OTX rate limited")

                    if resp.status_code == 200:
                        data = resp.json()
                        pulses = data.get("results", [])
                        return {
                            "found": len(pulses) > 0,
                            "pulse_count": len(pulses),
                            "campaigns": [p["name"] for p in pulses[:5]],
                            "tlp": data.get("tlp"),
                            "all_campaigns": [p["name"] for p in pulses],
                            "pulse_ids": [p["id"] for p in pulses[:5]],
                        }
                except requests.Timeout:
                    continue
                except Exception:
                    logger.debug("OTX endpoint failed", exc_info=True)
                    continue

            return {"found": False, "message": "Not found in OTX"}

        except Exception as e:
            return {"error": str(e)}

    def _query_shodan(self, ip: str) -> Dict[str, Any]:
        try:
            params = {"key": self.shodan_key}
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params=params,
                timeout=self.timeout,
            )

            if resp.status_code == 401:
                raise ValueError("Invalid Shodan API key")
            if resp.status_code == 404:
                return {"found": False, "message": "Not in Shodan"}
            if resp.status_code == 429:
                raise RuntimeError("Shodan rate limited")
            if resp.status_code != 200:
                raise RuntimeError(f"Shodan error: {resp.status_code}")

            data = resp.json()
            services = []
            for port_data in data.get("data", []):
                product = port_data.get("product")
                if product:
                    services.append(product)

            return {
                "found": True,
                "country": data.get("country_name"),
                "country_code": data.get("country_code"),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "ports": data.get("ports", []),
                "services": list(set(services)),
                "os": data.get("os"),
                "hostnames": data.get("hostnames", []),
                "last_update": data.get("last_update"),
            }

        except requests.Timeout:
            return {"error": "Request timeout"}
        except Exception as e:
            return {"error": str(e)}

    def _query_censys(self, indicator: str, itype: str) -> Dict[str, Any]:
        try:
            headers = {"Authorization": f"Bearer {self.censys_token}"}
            if self.censys_org_id:
                headers["X-Organization-ID"] = self.censys_org_id
            base = "https://api.platform.censys.io/v3"

            if itype == "domain":
                headers["Content-Type"] = "application/json"
                resp = requests.post(
                    f"{base}/global/asset/certificate/search",
                    json={"q": f"names: {indicator}", "per_page": 5},
                    headers=headers,
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("result", {}).get("hits", [])
                    return {
                        "found": len(results) > 0,
                        "cert_count": len(results),
                        "certificates": results[:5],
                        "fingerprints": [
                            c.get("fingerprint_sha256") for c in results[:5]
                        ],
                    }
                if resp.status_code == 401:
                    raise ValueError("Invalid Censys token")
                if resp.status_code == 429:
                    raise RuntimeError("Censys rate limited")
                return {"found": False, "message": "No certificates found"}

            if itype == "ip":
                headers["Accept"] = "application/vnd.censys.api.v3.host.v1+json"
                resp = requests.get(
                    f"{base}/global/asset/host/{indicator}",
                    headers=headers,
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    attrs = data.get("result", {})
                    services = attrs.get("services", [])
                    return {
                        "found": True,
                        "ip": indicator,
                        "asn": attrs.get("autonomous_system", {}).get("asn"),
                        "asn_name": attrs.get("autonomous_system", {}).get("name"),
                        "org": attrs.get("autonomous_system", {}).get(
                            "organization"
                        ),
                        "country": attrs.get("location", {}).get("country"),
                        "country_code": attrs.get("location", {}).get(
                            "country_code"
                        ),
                        "city": attrs.get("location", {}).get("city"),
                        "provider": attrs.get("autonomous_system", {}).get(
                            "organization"
                        ),
                        "ports": [s.get("port") for s in services],
                        "services": list(
                            set(
                                s.get("service_name", "")
                                for s in services
                                if s.get("service_name")
                            )
                        ),
                        "last_updated": attrs.get("last_updated_at"),
                    }
                if resp.status_code == 404:
                    return {"found": False, "message": "Host not found in Censys"}
                if resp.status_code == 401:
                    raise ValueError("Invalid Censys token")
                if resp.status_code == 429:
                    raise RuntimeError("Censys rate limited")
                return {"found": False, "message": f"HTTP {resp.status_code}"}

            return {"error": f"Unsupported indicator type: {itype}"}

        except requests.Timeout:
            return {"error": "Request timeout"}
        except Exception as e:
            return {"error": str(e)}

    # ============ Consolidation ============

    def _consolidate(self, result: TIResult) -> None:
        risk_signals = 0.0
        evidence = []

        vt = result.vt_result
        if vt.get("error"):
            evidence.append(f"VirusTotal: Unavailable ({vt.get('error')})")
        elif vt.get("detected", 0) > 20:
            evidence.append(
                f"VirusTotal: {vt['detected']}/70 vendors flag as malicious"
            )
            risk_signals += 2
        elif vt.get("detected", 0) > 5:
            evidence.append(
                f"VirusTotal: {vt['detected']}/70 vendors flag as malicious"
            )
            risk_signals += 1
        elif vt.get("suspicious", 0) > 0:
            evidence.append(f"VirusTotal: {vt['suspicious']} vendors flag as suspicious")
            risk_signals += 0.5
        elif vt.get("found"):
            evidence.append("VirusTotal: Not flagged as malicious")
        else:
            evidence.append("VirusTotal: Not found")

        otx = result.otx_result
        if otx.get("error"):
            evidence.append(f"OTX: Unavailable ({otx.get('error')})")
        elif otx.get("pulse_count", 0) > 0:
            campaigns = ", ".join(otx.get("campaigns", [])[:3])
            evidence.append(
                f"AlienVault OTX: Part of {otx['pulse_count']} campaigns: {campaigns}"
            )
            risk_signals += 2
        else:
            evidence.append("AlienVault OTX: No known threat campaigns")

        shodan = result.shodan_result
        if shodan.get("error"):
            evidence.append(f"Shodan: Unavailable ({shodan.get('error')})")
        elif shodan.get("found"):
            services = ", ".join(shodan.get("services", [])[:3])
            evidence.append(
                f"Shodan: Hosts {services} in {shodan.get('country', 'unknown')}"
            )
            services_lower = " ".join(shodan.get("services", [])).lower()
            if any(k in services_lower for k in ["bulletproof", "proxy", "vpn"]):
                evidence.append("  -> High-risk hosting provider detected")
                risk_signals += 1.5
            else:
                risk_signals += 0.5
        else:
            evidence.append("Shodan: No hosting info available")

        censys = result.censys_result
        if censys.get("error"):
            evidence.append(f"Censys: Unavailable ({censys.get('error')})")
        elif result.indicator_type == "domain" and censys.get("found"):
            cert_count = censys.get("cert_count", 0)
            evidence.append(f"Censys: {cert_count} SSL certificates found")
            if cert_count > 10:
                evidence.append("  -> Frequent certificate rotation (possible evasion)")
                risk_signals += 0.5
        elif result.indicator_type == "ip" and censys.get("found"):
            asn = censys.get("asn", "N/A")
            org = censys.get("org", "N/A")
            country = censys.get("country", "Unknown")
            services = ", ".join(censys.get("services", [])[:3])
            evidence.append(f"Censys: AS{asn} ({org}) in {country}")
            if services:
                evidence.append(f"  -> Services: {services}")
            risk_signals += 0.5
        else:
            evidence.append("Censys: No SSL certificate history")

        if risk_signals >= 4:
            result.risk_level = "HIGH"
            result.risk_score = 0.9
        elif risk_signals >= 2:
            result.risk_level = "MEDIUM"
            result.risk_score = 0.6
        else:
            result.risk_level = "LOW"
            result.risk_score = 0.3

        result.evidence = evidence


def batch_enrich(
    indicators: List[Tuple[str, str]],
    enricher: ThreatIntelligenceEnricher,
) -> List[TIResult]:
    """Enrich multiple (indicator, indicator_type) pairs."""
    results = []
    for indicator, itype in indicators:
        try:
            results.append(enricher.enrich(indicator, itype))
        except Exception as e:
            logger.error("Failed to enrich %s: %s", indicator, e)
            result = TIResult(indicator=indicator, indicator_type=itype)
            result.errors.append(f"Enrichment failed: {e}")
            results.append(result)
    return results
