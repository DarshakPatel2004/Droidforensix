"""Unit tests for the shared labelDefinitions (analysis/labels.py)."""

from analysis.labels import (
    canonical_family,
    is_catch_all,
    is_correct,
)


class TestIsCatchAll:
    def test_vendor_generics(self):
        for label in ("unknown", "AndroidOS", "GenericKD", "Agent", "Adware",
                      "Detected", "Trojan-Banker", "HEUR", "a"):
            assert is_catch_all(label), label

    def test_platform_prefix_stripped(self):
        assert is_catch_all("Android/Agent")
        assert is_catch_all("android/agent")

    def test_artifact_shapes(self):
        assert is_catch_all("Trojan ( 005cbb901 )")
        assert is_catch_all("trojan-sms.fake")

    def test_specific_families_not_catchall(self):
        for label in ("GinMaster", "Opfake", "SpyNote", "FakeInst", "Plankton"):
            assert not is_catch_all(label), label

    def test_sdk_and_packer_names_are_catchall(self):
        # Libraries/packers are not families (review verdict: a racing game
        # clustered as "Cnzz" via a shared analytics SDK).
        for label in ("Cnzz", "SecApk", "SMSreg", "AdLibrary"):
            assert is_catch_all(label), label
        # ...but families proposed from shared infra stay specific.
        for label in ("Xgen2-AYJ", "Mirax", "SmsSend"):
            assert not is_catch_all(label), label

    def test_empty_is_catchall(self):
        assert is_catch_all("")
        assert is_catch_all(None)


class TestAliasesAndLineage:
    def test_vendor_alias(self):
        assert is_correct("DroidKungFu", "KungFu")
        assert is_correct("NGate", "Andr/NGate-G")

    def test_fakeinstaller_lineage(self):
        assert is_correct("FakeInst", "FakeInstaller")
        assert is_correct("FakeInstaller", "FakeInst")
        assert is_correct("Opfake", "FakeInst")
        assert is_correct("FakeInst", "Opfake")

    def test_distinct_families_not_correct(self):
        assert not is_correct("Opfake", "GinMaster")
        assert not is_correct("SpyNote", "SpyMax")

    def test_canonical_family(self):
        assert canonical_family("Opfake") == "fakeinst"
        assert canonical_family("GinMaster") == "GinMaster"
