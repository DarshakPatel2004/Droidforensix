"""Unit tests for FamilySignature matching (synthetic results, no APK/LLM)."""

from backend.family_id import _match_family_signatures


def _result(strings=(), domains=(), perms=(), classes=0, native=0):
    return {
        "strings": {"string_literals": [{"value": s} for s in strings]},
        "c2_infrastructure": [{"domain": d} for d in domains],
        "manifest": {"uses_permissions": list(perms)},
        "extraction": {"decompiled_classes": classes, "native_libs_found": native},
    }


class TestKungFuGongfuC2:
    PERMS = [
        "android.permission.INTERNET",
        "android.permission.READ_PHONE_STATE",
        "android.permission.ACCESS_WIFI_STATE",
    ]

    def test_gongfu_c2_names_kungfu(self):
        match = _match_family_signatures(
            _result(
                domains=["search.gongfu-android.com"],
                perms=self.PERMS,
                classes=97,
                native=["libfoo.so"],
            )
        )
        assert match is not None
        assert match["family"] == "KungFu"

    def test_kungfu_wins_tiebreak_over_droiddream(self):
        # Both match generic root signals; KungFu's specific C2 must win.
        match = _match_family_signatures(
            _result(
                strings=["rageagainstthecage", "root"],
                domains=["search.gongfu-android.com"],
                perms=self.PERMS + ["android.permission.READ_LOGS"],
                classes=97,
                native=["libfoo.so"],
            )
        )
        assert match is not None
        assert match["family"] == "KungFu"
