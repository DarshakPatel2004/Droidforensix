from analysis.c2_corroboration import (
    annotate_device_data_signal,
    find_device_data_signal,
    is_behavior_confirmed,
    is_benign_sdk_host,
    is_corroborated_endpoint,
    is_endpoint_path,
    record_host,
)


def test_real_endpoint_paths_qualify():
    assert is_endpoint_path("/gate.php")
    assert is_endpoint_path("/api/v2/login")


def test_root_empty_and_missing_paths_do_not_qualify():
    assert not is_endpoint_path("/")
    assert not is_endpoint_path("")
    assert not is_endpoint_path(None)


def test_truncated_and_generic_segments_do_not_qualify():
    assert not is_endpoint_path("/bot")
    assert not is_endpoint_path("/api")
    assert not is_endpoint_path("/v1")


def test_fallback_bare_domain_is_never_corroborated():
    rec = {"is_fallback": True, "path": "/gate.php", "confidence": 0.99}
    assert is_corroborated_endpoint(rec) is False


def test_low_confidence_is_not_corroborated():
    rec = {"is_fallback": False, "path": "/gate.php", "confidence": 0.79}
    assert is_corroborated_endpoint(rec) is False


def test_full_url_with_real_path_is_corroborated():
    rec = {"is_fallback": False, "path": "/gate.php", "confidence": 0.8}
    assert is_corroborated_endpoint(rec) is True


# --- vendor host suppression and device-data signal -------------------------------------------

def _record(domain, path="/ad/nadp.php", confidence=1.0, **extra):
    return {"domain": domain, "path": path, "confidence": confidence, "is_fallback": False, **extra}


def test_known_ad_and_vendor_hosts_are_not_corroborated():
    assert not is_corroborated_endpoint(_record("r2.adwo.com", "/adfs"))
    assert not is_corroborated_endpoint(_record("android.bugly.qq.com", "/rqd/async"))


def test_unknown_host_with_real_path_still_corroborated():
    assert is_corroborated_endpoint(_record("ad.gongfu-android.com", "/ad/nadp.php"))


def test_suffix_match_does_not_match_lookalike_domains():
    assert is_benign_sdk_host("sdk.adwo.com")
    assert not is_benign_sdk_host("notadwo.com")
    assert not is_benign_sdk_host("adwo.com.evil.example")


def test_non_public_ips_are_not_corroborated():
    for ip in ("10.19.1.123", "100.69.165.28", "192.168.0.108", "127.0.0.1"):
        assert not is_corroborated_endpoint(_record(ip, "/agoo/report"))
    assert is_corroborated_endpoint(_record("47.112.113.131", "/Author/PhoneAuthor"))


def test_shared_hosting_platforms_stay_unsuppressed():
    # Real C2 is hosted on these, so a vendor list must never silence them.
    for host in ("github.com", "raw.githubusercontent.com", "firebaseio.com", "appspot.com", "amazonaws.com"):
        assert not is_benign_sdk_host(host)


def test_device_data_signal_true_false_none(tmp_path):
    smali = tmp_path / "smali" / "com" / "x"
    smali.mkdir(parents=True)
    (smali / "A.smali").write_text(
        'const-string v0, "http://gate.example/a.php"\n'
        "invoke-virtual {v1}, Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;\n")
    (smali / "B.smali").write_text('const-string v0, "http://docs.example/readme"\n')
    out = find_device_data_signal(["gate.example", "docs.example", "absent.example"], str(tmp_path))
    assert out == {"gate.example": True, "docs.example": False, "absent.example": None}


def test_device_data_signal_unknown_without_a_code_tree(tmp_path):
    assert find_device_data_signal(["gate.example"], None) == {"gate.example": None}
    assert find_device_data_signal(["gate.example"], str(tmp_path / "missing")) == {"gate.example": None}


def test_behavior_confirmed_needs_corroboration_and_signal(tmp_path):
    smali = tmp_path / "smali"
    smali.mkdir()
    (smali / "A.smali").write_text('"http://gate.example/a.php" getSubscriberId')
    records = [_record("gate.example", "/a.php"), _record("r2.adwo.com", "/adfs")]
    (smali / "B.smali").write_text('"http://r2.adwo.com/adfs" getDeviceId')
    annotate_device_data_signal(records, str(tmp_path))
    assert records[0]["device_data_signal"] is True and is_behavior_confirmed(records[0])
    # Vendor host has the signal but is never corroborated, so it is never behavior-confirmed.
    assert records[1]["device_data_signal"] is True and not is_behavior_confirmed(records[1])


def test_comma_joined_hosts_use_the_first_host():
    assert record_host({"domain": "sdk.appbrain.com,sdk-b.apptornado.com"}) == "sdk.appbrain.com"
    assert record_host({"raw_url": "sdk.appbrain.com,http://sdk-b.apptornado.com"}) == "sdk.appbrain.com"


def test_bracket_fragment_host_is_cleaned():
    assert record_host({"raw_url": "http://www.motorola.com/Consumers/x.alt]"}) == "www.motorola.com"


def test_comma_joined_ad_sdk_is_suppressed_not_confirmed():
    rec = {"domain": "sdk.appbrain.com,sdk-b.apptornado.com", "path": "/sdk", "confidence": 0.9,
           "is_fallback": False, "device_data_signal": True}
    assert not is_corroborated_endpoint(rec)
    assert not is_behavior_confirmed(rec)
