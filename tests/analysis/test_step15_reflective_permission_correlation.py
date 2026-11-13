import pytest

from analysis.step15_reflective_permission_correlation import (
    PERMISSION_API_MAP,
    classify_permission_category,
    correlate_reflective_permission_usage,
)


class TestCorrelateReflectivePermissionUsage:
    def test_empty(self):
        result = correlate_reflective_permission_usage([], [])
        assert result["total_permissions"] == 0
        assert result["used_permissions"] == []

    def test_with_data(self):
        permissions = [
            "android.permission.SEND_SMS",
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
        ]
        reflective_calls = [
            {"resolved_class": "android.telephony.SmsManager", "sensitive": True},
            {"resolved_class": "java.net.URL", "sensitive": True},
        ]
        result = correlate_reflective_permission_usage(permissions, reflective_calls)
        assert result["total_permissions"] == 3
        used = {up["permission"]: up for up in result["used_permissions"]}
        assert set(used) == {"android.permission.SEND_SMS", "android.permission.INTERNET"}
        assert all(up["used_reflectively"] is True for up in used.values())
        assert [u["permission"] for u in result["unused_permissions"]] == ["android.permission.ACCESS_NETWORK_STATE"]
        assert result["total_used"] == 2
        assert result["total_unused"] == 1
        assert result["usage_ratio"] == 0.67
        assert result["category_summary"]["sms"] == {"total": 1, "used_reflectively": 1}
        assert result["category_summary"]["network"] == {"total": 2, "used_reflectively": 1}

    def test_none_permissions(self):
        with pytest.raises(TypeError):
            correlate_reflective_permission_usage(None, [])


class TestClassifyPermissionCategory:
    def test_sms(self):
        assert classify_permission_category("android.permission.SEND_SMS") == "sms"

    def test_network(self):
        assert classify_permission_category("android.permission.INTERNET") == "network"

    def test_other(self):
        assert classify_permission_category("android.permission.UNKNOWN_RANDOM") == "other"

    def test_location(self):
        assert classify_permission_category("android.permission.ACCESS_FINE_LOCATION") == "location"


class TestConstants:
    def test_permission_api_map_defined(self):
        assert len(PERMISSION_API_MAP) > 0
        assert "android.permission.SEND_SMS" in PERMISSION_API_MAP
