"""Family signatures: shape (class count, native libs) counts toward min_matches but never names a family alone.

Regression for 77e39b9, which stopped counting "native:no" without lowering min_matches. Dev recall on
real-family rows fell from 88% to 59% (FakeInst, Opfake, GinMaster lost their matches).
"""
from backend.family_id import _match_family_signatures

PERMS_SMS = [
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
]
PERMS_COMMON = ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"]


def _result(classes, **overrides):
    base = {
        "metadata": {"sha256": "cd" * 32, "package_name": "com.example.app"},
        "certificate_analysis": {},
        "strings": {"string_literals": []},
        "c2_infrastructure": [],
        "extraction": {"decompiled_classes": classes, "native_libs_found": []},
        "permissions": [],
    }
    base.update(overrides)
    return base


def test_known_c2_plus_permissions_plus_shape_still_names_fakeinst():
    result = _result(14, c2_infrastructure=[{"domain": "depositmobi.com", "protocol": "http"}],
                     manifest={"uses_permissions": PERMS_SMS})
    match = _match_family_signatures(result)
    assert match is not None and match["family"] == "FakeInst"


def test_common_permissions_and_class_count_alone_name_no_family():
    # INTERNET + ACCESS_NETWORK_STATE with an in-range class count: pure shape, no string or C2.
    result = _result(146, manifest={"uses_permissions": PERMS_COMMON})
    match = _match_family_signatures(result)
    assert match is None or match["family"] != "PixRevolution"


def test_pixrevolution_still_matches_with_one_of_its_own_strings():
    result = _result(146, strings={"string_literals": [{"value": "pixrevolution"}]},
                     manifest={"uses_permissions": PERMS_COMMON})
    match = _match_family_signatures(result)
    assert match is not None and match["family"] == "PixRevolution"
