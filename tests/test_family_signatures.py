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


class TestGenericBankerEvidenceNeedsC2:
    PERMS = [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
    ]

    def test_generic_strings_and_permissions_alone_do_not_name_ermac(self):
        # "accessibility" and "overlay" appear in countless benign apps; with no
        # family-specific C2 this evidence fired 48x on a 373-sample run, 0 correct.
        match = _match_family_signatures(
            _result(strings=["accessibility", "overlay"], perms=self.PERMS, classes=500, native=[])
        )
        assert match is None or match["family"] != "Ermac"

    def test_ermac_c2_domain_still_names_ermac(self):
        match = _match_family_signatures(
            _result(strings=["accessibility", "overlay"], domains=["panel.ermac-c2.net"],
                    perms=self.PERMS, classes=500, native=[])
        )
        assert match is not None
        assert match["family"] == "Ermac"


class TestKonfety:
    PERMS = ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"]

    def test_generic_compose_strings_do_not_name_konfety(self):
        # Compose/R8 markers ship in many ordinary apps; they named Konfety 36 times on 228 dev samples, 0 correct.
        match = _match_family_signatures(
            _result(strings=["androidx.compose.ui.uicomposable", "r8-map-id"], perms=self.PERMS, classes=100, native=[])
        )
        assert match is None or match["family"] != "Konfety"

    def test_konfety_name_still_names_konfety(self):
        match = _match_family_signatures(
            _result(strings=["konfety", "androidx.compose.ui.uicomposable"], perms=self.PERMS, classes=100, native=[])
        )
        assert match is not None
        assert match["family"] == "Konfety"
