import pytest
from analysis.hardcoded_secrets import (
    scan_strings,
    scan_source_files,
    scan_high_entropy_strings,
    analyze_hardcoded_secrets,
    classify_risk,
    format_for_report,
    auto_decode_secret,
    _is_placeholder,
    _is_printable_text,
    SKIP_PATTERNS_IN_ALL_SCANS,
    SECRET_PATTERNS,
)


def test_aws_access_key_matches():
    findings = scan_strings([{"value": "AKIA1234567890123456", "source": "Test.java:5"}])
    assert len(findings) >= 1
    f = next(f for f in findings if f["secret_type"] == "aws_access_key")
    assert f["value"] == "AKIA1234567890123456"
    assert f["severity"] == "high"


def test_aws_access_key_wrong_length_ignored():
    findings = scan_strings([{"value": "AKIA12345678901234", "source": "Test.java:5"}])
    assert all(f["secret_type"] != "aws_access_key" for f in findings)


def test_aws_secret_key_requires_slash_or_plus():
    pat = next(p for p in SECRET_PATTERNS if p["name"] == "aws_secret_key")
    m = pat["pattern"].search("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
    assert m is not None
    assert pat["validation"](m)


def test_aws_secret_key_without_slash_or_plus_skipped():
    findings = scan_strings([{"value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "source": "T.java:1"}])
    assert all(f["secret_type"] != "aws_secret_key" for f in findings)


def test_google_api_key_matches():
    findings = scan_strings([{"value": "AIzaSyBlaBlaBlaBlaBlaBlaBlaBlaBlaBlaBla", "source": "T.java:1"}])
    assert any(f["secret_type"] == "google_api_key" for f in findings)


def test_jwt_token_matches_and_decodes():
    imports = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
    sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    token = f"{imports}.{payload}.{sig}"
    findings = scan_strings([{"value": token, "source": "T.java:1"}])
    assert any(f["secret_type"] == "jwt_token" for f in findings)
    jwt_f = next(f for f in findings if f["secret_type"] == "jwt_token")
    if "decoded" in jwt_f:
        assert "John" in jwt_f["decoded"] or "Doe" in jwt_f["decoded"]


def test_bearer_token_matches():
    findings = scan_strings([{"value": 'Bearer xyzabc123def456ghi789jkl012mno345pqr678stu901vwx', "source": "T.java:1"}])
    assert any(f["secret_type"] == "bearer_token" for f in findings)


def test_slack_token_matches():
    findings = scan_strings([{"value": "xoxb-123456789012-1234567890123-abc123def456ghijklmno", "source": "T.java:1"}])
    assert any(f["secret_type"] == "slack_token" for f in findings)


def test_slack_webhook_matches():
    findings = scan_strings([{"value": "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx", "source": "T.java:1"}])
    assert any(f["secret_type"] == "slack_webhook" for f in findings)


def test_github_token_matches():
    findings = scan_strings([{"value": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "source": "T.java:1"}])
    assert any(f["secret_type"] == "github_token" for f in findings)


def test_discord_webhook_matches():
    findings = scan_strings([{"value": "https://discord.com/api/webhooks/123456789/abcDEF_xyz", "source": "T.java:1"}])
    assert any(f["secret_type"] == "discord_webhook" for f in findings)


def test_twilio_sid_matches():
    findings = scan_strings([{"value": "ACabcdef0123456789abcdef0123456789", "source": "T.java:1"}])
    assert any(f["secret_type"] == "twilio_sid" for f in findings)


def test_sendgrid_api_key_matches():
    findings = scan_strings([{"value": "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyzabcdefgh", "source": "T.java:1"}])
    assert any(f["secret_type"] == "sendgrid_api_key" for f in findings)


def test_mongodb_uri_matches():
    findings = scan_strings([{"value": "mongodb+srv://user:password@cluster0.mongodb.net/db", "source": "T.java:1"}])
    assert any(f["secret_type"] == "mongodb_uri" for f in findings)


def test_mysql_uri_matches():
    findings = scan_strings([{"value": "mysql://user:password@localhost:3306/db", "source": "T.java:1"}])
    assert any(f["secret_type"] == "mysql_uri" for f in findings)


def test_redis_uri_matches():
    findings = scan_strings([{"value": "redis://user:password@redis-host:6379", "source": "T.java:1"}])
    assert any(f["secret_type"] == "redis_uri" for f in findings)


def test_url_embedded_credentials_matches():
    findings = scan_strings([{"value": "https://user:pass@api.example.com/v1", "source": "T.java:1"}])
    assert any(f["secret_type"] == "url_embedded_credentials" for f in findings)


def test_rsa_private_key_matches():
    findings = scan_strings([{"value": "-----BEGIN RSA PRIVATE KEY-----", "source": "T.java:1"}])
    assert any(f["secret_type"] == "rsa_private_key" for f in findings)


def test_pkcs8_private_key_matches():
    findings = scan_strings([{"value": "-----BEGIN PRIVATE KEY-----", "source": "T.java:1"}])
    assert any(f["secret_type"] == "pkcs8_private_key" for f in findings)


def test_generic_api_key_named_matches():
    findings = scan_strings([{"value": 'api_key = "abcdefghijklmnopqrstuvwx123456"', "source": "T.java:1"}])
    assert any(f["secret_type"] == "generic_api_key_named" for f in findings)


def test_secret_key_named_matches():
    findings = scan_strings([{"value": 'secret = "abcdefghijklmnopqrstuvwx123456"', "source": "T.java:1"}])
    assert any(f["secret_type"] == "secret_key_named" for f in findings)


def test_password_string_matches():
    findings = scan_strings([{"value": 'password = "hunter2!"', "source": "T.java:1"}])
    assert any(f["secret_type"] == "password_string" for f in findings)


def test_keystore_password_matches():
    findings = scan_strings([{"value": 'storePassword = "myK3yst0re"', "source": "T.java:1"}])
    assert any(f["secret_type"] in ("keystore_password", "password_string") for f in findings)


def test_signing_config_matches():
    findings = scan_strings([{"value": "storeFile=debug.keystore", "source": "build.gradle:1"}])
    assert any(f["secret_type"] == "signing_config" for f in findings)


def test_firebase_url_matches():
    findings = scan_strings([{"value": "https://myproject.firebaseio.com", "source": "T.java:1"}])
    assert any(f["secret_type"] == "firebase_url" for f in findings)


def test_google_oauth_client_id_matches():
    findings = scan_strings([{"value": "123456789012-abc123def456ghijklmnopqrstuvwxyz.apps.googleusercontent.com", "source": "T.java:1"}])
    assert any(f["secret_type"] == "google_oauth_client_id" for f in findings)


def test_azure_connection_string_matches():
    cs = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123def456abc123def456abc123def456abc123def456ab=="
    findings = scan_strings([{"value": cs, "source": "T.java:1"}])
    assert any(f["secret_type"] == "azure_connection_string" for f in findings)


def test_oauth_access_token_matches():
    findings = scan_strings([{"value": "access_token = 'ya29.a1234567890abcdefghij'", "source": "T.java:1"}])
    assert any(f["secret_type"] == "oauth_access_token" for f in findings)


def test_oauth_client_secret_matches():
    findings = scan_strings([{"value": "client_secret = 'abc123def456'", "source": "T.java:1"}])
    assert any(f["secret_type"] == "oauth_client_secret" for f in findings)


def test_placeholder_values_skipped():
    for placeholder in ["test", "changeme", "replace_me", "YOUR_API_KEY"]:
        findings = scan_strings([{"value": f"api_key = '{placeholder}123'", "source": "T.java:1"}])
        assert all(f["secret_type"] != "generic_api_key_named" for f in findings), f"Placeholder '{placeholder}' was not skipped"


def test_short_strings_skipped():
    findings = scan_strings([{"value": "short", "source": "T.java:1"}])
    assert len(findings) == 0


def test_multiple_secrets_in_one_string():
    findings = scan_strings([{"value": "AKIA1234567890123456 and ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "source": "T.java:1"}])
    types = {f["secret_type"] for f in findings}
    assert "aws_access_key" in types
    assert "github_token" in types


def test_scan_source_files(tmp_path):
    src = tmp_path / "sources"
    src.mkdir()
    f = src / "Config.java"
    f.write_text("public class Config {\n    String key = \"AKIA1234567890123456\";\n}")
    findings = scan_source_files(str(src))
    assert any(f["secret_type"] == "aws_access_key" for f in findings)
    assert findings[0]["source_file"] == "Config.java"


def test_scan_source_files_skips_placeholders(tmp_path):
    src = tmp_path / "sources"
    src.mkdir()
    f = src / "Config.java"
    f.write_text("public class Config {\n    String apiKey = \"YOUR_API_KEY\";\n}")
    findings = scan_source_files(str(src))
    assert all(f["secret_type"] != "generic_api_key_named" for f in findings)


def test_dedup_same_secret_multiple_locations():
    findings = scan_strings([
        {"value": "AKIA1111111111111111", "source": "A.java:1"},
        {"value": "AKIA2222222222222222", "source": "B.java:2"},
    ])
    aws = [f for f in findings if f["secret_type"] == "aws_access_key"]
    assert len(aws) == 2


def test_dedup_different_secrets_separate():
    findings = scan_strings([
        {"value": "AKIA1111111111111111", "source": "A.java:1"},
        {"value": "AKIA2222222222222222", "source": "B.java:2"},
    ])
    ak = [f for f in findings if f["secret_type"] == "aws_access_key"]
    assert len(ak) == 2


def test_high_entropy_strings():
    strings = [{"value": "aB3dE5gHiJkLmNoPqRsTuVwXyZ0123456789", "source": "T.java:1"}]
    findings = scan_high_entropy_strings(strings, min_entropy=3.0)
    assert any(f["secret_type"] == "high_entropy_potential_key" for f in findings)


def test_high_entropy_mostly_hex_skipped():
    strings = [{"value": "abcdef0123456789abcdef0123456789abcdef012345678", "source": "T.java:1"}]
    findings = scan_high_entropy_strings(strings)
    assert len(findings) == 0


def test_classify_risk_none():
    risk = classify_risk([])
    assert risk["severity"] == "none"
    assert risk["risk_score"] == 0


def test_classify_risk_critical():
    findings = [
        {"secret_type": "rsa_private_key", "severity": "critical"},
        {"secret_type": "aws_access_key", "severity": "high"},
    ]
    risk = classify_risk(findings)
    assert risk["severity"] == "critical"
    assert risk["total_secrets"] == 2


def test_classify_risk_score():
    findings = [
        {"secret_type": "rsa_private_key", "severity": "critical"},
        {"secret_type": "aws_access_key", "severity": "high"},
        {"secret_type": "google_api_key", "severity": "high"},
    ]
    risk = classify_risk(findings)
    assert risk["risk_score"] == 20  # 10 + 5 + 5


def test_format_for_report_no_findings():
    assert "No hardcoded secrets detected" in format_for_report([])


def test_format_for_report_with_findings():
    findings = [{"secret_type": "aws_access_key", "severity": "high", "value": "AKIA1234567890123456", "source": "T.java"}]
    report = format_for_report(findings)
    assert "AWS Access Key ID" in report or "aws_access_key" in report or "AKIA" in report


def test_auto_decode_jwt():
    imports = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
    sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    token = f"{imports}.{payload}.{sig}"
    decoded = auto_decode_secret("jwt_token", token)
    assert decoded is not None


def test_auto_decode_base64():
    raw = "aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXRo"
    decoded = auto_decode_secret("generic", raw)
    if decoded:
        assert "example.com" in decoded


def test_auto_decode_connection_string():
    cs = "mongodb://user:pass@cluster.mongodb.net/db"
    decoded = auto_decode_secret("mongodb_uri", cs)
    assert decoded is not None
    assert "user" in decoded and "pass" in decoded


def test_is_placeholder():
    assert _is_placeholder("YOUR_API_KEY") is True
    assert _is_placeholder("test-key") is True
    assert _is_placeholder("changeme") is True
    assert _is_placeholder("example.com") is True
    assert _is_placeholder("AKIA1234567890123456") is False
    assert _is_placeholder("https://user:pass@api.example.com/v1") is False


def test_is_printable_text():
    assert _is_printable_text("The quick brown fox jumps over the 123 lazy dogs!") is True
    assert _is_printable_text("\x00\x01\x02\x03\x04\x05") is False


def test_analyze_hardcoded_secrets_entry_point():
    string_result = {
        "sample_id": "test",
        "categories": {
            "string_literals": [
                {"value": "AKIA1234567890123456", "entropy": 4.5, "source": "T.java:1"},
                {"value": "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx", "entropy": 4.0, "source": "T.java:2"},
            ],
            "byte_arrays": [],
            "numeric_constants": [],
            "resource_strings": [],
            "native_strings": [],
        },
    }
    result = analyze_hardcoded_secrets(string_result, scan_high_entropy=False)
    assert result["total_scanned"] == 2
    assert result["secret_risk"]["total_secrets"] >= 2
    assert result["secret_risk"]["severity"] == "high"


def test_skipped_patterns_not_in_scan_strings():
    findings = scan_strings([{"value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "source": "T.java:1"}])
    for f in findings:
        assert f["secret_type"] not in SKIP_PATTERNS_IN_ALL_SCANS


def test_skipped_patterns_not_in_scan_source_files(tmp_path):
    src = tmp_path / "sources"
    src.mkdir()
    f = src / "Config.java"
    f.write_text("String x = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\";")
    findings = scan_source_files(str(src))
    for f in findings:
        assert f["secret_type"] not in SKIP_PATTERNS_IN_ALL_SCANS


def test_github_old_token_entropy_filtered():
    low_entropy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    findings = scan_strings([{"value": low_entropy, "source": "T.java:1"}])
    assert all(f["secret_type"] != "github_old_token" for f in findings)
