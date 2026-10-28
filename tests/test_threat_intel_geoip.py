"""GeoIP lookup against the real GeoLite2 database, to catch schema drift on refresh."""

import pytest

from backend import threat_intel

requires_geo_db = pytest.mark.skipif(
    threat_intel._GEO_READER is None,
    reason="GeoLite2-City.mmdb not present (git-ignored data file)",
)


@requires_geo_db
def test_known_ip_country_and_coordinates():
    geo = threat_intel._geo_lookup("8.8.8.8")
    assert geo["country"] == "United States"
    assert geo["lat"] == pytest.approx(37.751, abs=0.01)
    assert geo["lon"] == pytest.approx(-97.822, abs=0.01)


@requires_geo_db
def test_known_ip_region_and_city():
    geo = threat_intel._geo_lookup("81.2.69.142")
    assert geo["country"] == "United Kingdom"
    assert geo["region"] == "Bracknell Forest"
    assert geo["city"] == "Bracknell"


@requires_geo_db
def test_private_ip_returns_none():
    assert threat_intel._geo_lookup("192.168.1.1") is None
