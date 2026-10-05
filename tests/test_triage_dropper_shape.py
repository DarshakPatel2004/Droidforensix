"""Tests for dropper-shape manifest signals + KT §15 escalation (triage.py).

Covers three things the §15 matrix depends on:
1. FCM signal reads intent-filter <action> values, not component names
   (the pre-fix check could never fire on real FCM apps).
2. Unparseable manifests yield manifest_parse_error, never a phantom
   no_launcher_activity (androguard 4.x returns empties instead of raising).
3. Signals are emitted for every verdict; only `indeterminate` escalates.
"""

import pytest

from scripts.triage import (
    dropper_shape_signals,
    escalate_indeterminate,
    _has_push_messaging,
)

ANDROID_NS = "{http://schemas.android.com/apk/res/android}name"


# ---------------------------------------------------------------------------
# Fake APK: androguard 4.x only, controlled return values, no real parsing
# ---------------------------------------------------------------------------

class FakeAPK:
    def __init__(self, package="com.example.app", main_activity=".Main",
                 permissions=(), services=(), receivers=(), xml_doc=None):
        self._package = package
        self._main_activity = main_activity
        self._permissions = list(permissions)
        self._services = list(services)
        self._receivers = list(receivers)
        self._xml_doc = xml_doc

    def get_package(self):
        return self._package

    def get_main_activity(self):
        return self._main_activity

    def get_permissions(self):
        return self._permissions

    def get_services(self):
        return self._services

    def get_receivers(self):
        return self._receivers

    def get_android_manifest_xml(self):
        return self._xml_doc


class FakeAction:
    """Minimal lxml-element stand-in: only .get(attr) is used by the scan."""
    def __init__(self, action_name):
        self._name = action_name

    def get(self, attr, default=""):
        if attr == ANDROID_NS:
            return self._name
        return default


class FakeDoc:
    def __init__(self, actions):
        self._actions = actions

    def iter(self, tag):
        assert tag == "action", "scan must iterate <action> elements only"
        return iter(self._actions)


def install_fake(monkeypatch, fake):
    monkeypatch.setattr("androguard.core.apk.APK", lambda _p: fake)


def make_apk(tmp_path, name="sample.apk"):
    import zipfile
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
    return str(path)


# ---------------------------------------------------------------------------
# FCM signal: intent actions, not component names
# ---------------------------------------------------------------------------

def test_fcm_signal_fires_on_intent_action_not_component_name(monkeypatch, tmp_path):
    """Regression: component names never contain MESSAGING_EVENT; the
    action value does. Old logic checked names -> never fired."""
    fake = FakeAPK(
        services=["com.google.firebase.messaging.FirebaseMessagingService"],
        receivers=["com.google.firebase.iid.FirebaseInstanceIdReceiver"],
        xml_doc=FakeDoc([
            FakeAction("com.google.firebase.MESSAGING_EVENT"),
            FakeAction("com.google.android.c2dm.intent.RECEIVE"),
        ]),
    )
    install_fake(monkeypatch, fake)
    signals = dropper_shape_signals(make_apk(tmp_path))
    assert "fcm_receiver" in signals


def test_fcm_signal_absent_without_push_actions(monkeypatch, tmp_path):
    fake = FakeAPK(
        services=["com.example.SyncService"],  # name alone must not trigger
        xml_doc=FakeDoc([FakeAction("com.example.MY_ACTION")]),
    )
    install_fake(monkeypatch, fake)
    signals = dropper_shape_signals(make_apk(tmp_path))
    assert "fcm_receiver" not in signals


def test_component_name_containing_marker_does_not_fire(monkeypatch, tmp_path):
    """A service literally NAMED with the marker but no matching intent
    action is not push messaging - we check actions only."""
    fake = FakeAPK(
        services=["MESSAGING_EVENT"],
        xml_doc=FakeDoc([FakeAction("com.example.OTHER")]),
    )
    install_fake(monkeypatch, fake)
    signals = dropper_shape_signals(make_apk(tmp_path))
    assert "fcm_receiver" not in signals


def test_has_push_messaging_handles_none_doc():
    assert _has_push_messaging(FakeAPK(xml_doc=None)) is False


# ---------------------------------------------------------------------------
# Parse-failure guard
# ---------------------------------------------------------------------------

def test_unparseable_manifest_yields_parse_error_not_phantom_signals(monkeypatch, tmp_path):
    """androguard 4.x returns empty attrs on corrupt AXML instead of
    raising; empty package is the failure tell. 11/57 pendrive samples."""
    fake = FakeAPK(package="", main_activity=None, permissions=[],
                   services=[], receivers=[])
    install_fake(monkeypatch, fake)
    signals = dropper_shape_signals(make_apk(tmp_path))
    assert signals == ["manifest_parse_error:manifest_unparsed"]
    assert "no_launcher_activity" not in signals


def test_constructor_failure_yields_parse_error(monkeypatch, tmp_path):
    class RaisingAPK:
        def __init__(self, _path):
            raise ValueError("simulated APK() constructor failure")

    monkeypatch.setattr("androguard.core.apk.APK", RaisingAPK)
    signals = dropper_shape_signals(make_apk(tmp_path))
    assert len(signals) == 1
    assert signals[0].startswith("manifest_parse_error:")


def test_parse_ok_no_launcher_emits_single_signal(monkeypatch, tmp_path):
    fake = FakeAPK(main_activity=None, package="com.headless.app")
    install_fake(monkeypatch, fake)
    signals = dropper_shape_signals(make_apk(tmp_path))
    assert signals == ["no_launcher_activity"]


# ---------------------------------------------------------------------------
# Other signals (unchanged logic, pinned so refactors can't drift)
# ---------------------------------------------------------------------------

def test_self_install_signal(monkeypatch, tmp_path):
    fake = FakeAPK(permissions=["android.permission.REQUEST_INSTALL_PACKAGES"])
    install_fake(monkeypatch, fake)
    assert "self_install" in dropper_shape_signals(make_apk(tmp_path))


def test_shortcut_sms_combo_needs_both_permissions(monkeypatch, tmp_path):
    fake = FakeAPK(permissions=[
        "com.android.launcher.permission.INSTALL_SHORTCUT",
        "android.permission.READ_PHONE_STATE",
    ])
    install_fake(monkeypatch, fake)
    assert "shortcut_sms_combo" in dropper_shape_signals(make_apk(tmp_path))

    fake2 = FakeAPK(permissions=["android.permission.READ_PHONE_STATE"])
    install_fake(monkeypatch, fake2)
    assert "shortcut_sms_combo" not in dropper_shape_signals(make_apk(tmp_path))


def test_full_dropper_shape_headless_fcm_installer(monkeypatch, tmp_path):
    fake = FakeAPK(
        package="com.evil.dropper",
        main_activity=None,
        permissions=["android.permission.REQUEST_INSTALL_PACKAGES"],
        xml_doc=FakeDoc([FakeAction("com.google.firebase.MESSAGING_EVENT")]),
    )
    install_fake(monkeypatch, fake)
    signals = dropper_shape_signals(make_apk(tmp_path))
    assert set(signals) == {"no_launcher_activity", "fcm_receiver",
                            "self_install"}


# ---------------------------------------------------------------------------
# Escalation rule (pure function)
# ---------------------------------------------------------------------------

def test_escalation_fires_on_no_launcher_plus_two_hard_signals():
    verdict, conf = escalate_indeterminate(
        "indeterminate", 0.36,
        ["no_launcher_activity", "fcm_receiver"])
    assert verdict == "indeterminate(suspect:dropper-shape)"
    assert conf >= 0.7


def test_escalation_needs_at_least_two_hard_signals():
    verdict, conf = escalate_indeterminate(
        "indeterminate", 0.36, ["no_launcher_activity"])
    assert verdict == "indeterminate"
    assert conf == 0.36


def test_escalation_requires_no_launcher_even_with_two_signals():
    verdict, _ = escalate_indeterminate(
        "indeterminate", 0.36, ["fcm_receiver", "self_install"])
    assert verdict == "indeterminate"


def test_parse_errors_never_count_as_hard_signals():
    verdict, _ = escalate_indeterminate(
        "indeterminate", 0.36,
        ["manifest_parse_error:x", "no_launcher_activity"])
    assert verdict == "indeterminate"


@pytest.mark.parametrize("other_verdict", ["clean_static", "packed_known(x)",
                                           "packed_custom", "obfuscated_native"])
def test_escalation_gated_to_indeterminate_only(other_verdict):
    """Packed/clean verdicts carry signals as evidence, never escalate -
    preserves the §15 0FP/0FN matrix semantics."""
    verdict, conf = escalate_indeterminate(
        other_verdict, 0.9, ["no_launcher_activity", "fcm_receiver",
                             "self_install"])
    assert verdict == other_verdict
    assert conf == 0.9


def test_signals_emitted_for_all_verdicts(tmp_path, monkeypatch):
    """Core of option C: a clean_static sample still carries its
    manifest signals in suspect_reasons (verdict unchanged)."""
    from scripts import triage

    apk = make_apk(tmp_path)
    markers = {"brands": []}
    allowlist = {"asset_patterns": [], "native_share_exempt": 1.0,
                 "sha256_allowlist": {}}

    fake = FakeAPK(main_activity=None, package="com.x",
                   xml_doc=FakeDoc([FakeAction("com.google.firebase.MESSAGING_EVENT")]))
    install_fake(monkeypatch, fake)

    report = triage.triage_apk(apk, markers, allowlist)
    assert report["verdict"] == "clean_static"  # no escalation
    assert "no_launcher_activity" in report["suspect_reasons"]
    assert "fcm_receiver" in report["suspect_reasons"]
