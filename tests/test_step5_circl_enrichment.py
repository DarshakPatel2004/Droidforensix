"""Regression: CIRCL enrichment may return fewer items than it was given (record cap or time budget)."""

import analysis.step5_c2_extraction as step5


class _TruncatingClient:
    """Stands in for CIRCLClient: enriches only the first two items, as a capped run does."""

    def __init__(self):
        pass

    def enrich_c2_infrastructure(self, c2_list, max_records=None, time_budget=None):
        return [{"circl": {"position": i}} for i in range(min(2, len(c2_list)))]


def test_enrich_with_circl_tolerates_truncated_result(monkeypatch):
    monkeypatch.setattr(step5, "CIRCL_AVAILABLE", True)
    monkeypatch.setattr(step5, "CIRCLClient", _TruncatingClient)
    records = [{"ip": f"10.0.0.{i}"} for i in range(5)]

    result = step5.enrich_with_circl(records)

    assert [r.get("circl") for r in result[:2]] == [{"position": 0}, {"position": 1}]
    assert all("circl" not in r for r in result[2:])
