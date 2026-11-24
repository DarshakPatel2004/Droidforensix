from analysis.c2_corroboration import is_corroborated_endpoint, is_endpoint_path


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
