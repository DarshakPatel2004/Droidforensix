"""
Regression tests for previously-untested risky paths.

Each test here pins behaviour that no existing test exercised. Several of these
paths were silent-failure sites (a failed scan reported as a clean result), so
the tests assert the *error* is surfaced, not just that the call succeeds.
"""
import io
import struct
import zipfile

import pytest


# ---------------------------------------------------------------------------
# T-1: APKProcessor must not report success for steps that failed
# ---------------------------------------------------------------------------
class TestApkProcessorStepFailures:
    def test_soft_step_failures_are_recorded_not_dropped(self, monkeypatch):
        from backend.core.apk_processor import APKProcessor

        proc = APKProcessor.__new__(APKProcessor)
        proc.apk_path = "x.apk"
        proc.apk_hash = "deadbeef"
        proc.results = {"steps": {}}

        monkeypatch.setattr(APKProcessor, "step_1_androguard_analysis",
                            lambda self: {"success": True, "data": {}})
        monkeypatch.setattr(APKProcessor, "step_2_string_extraction",
                            lambda self, d: {"success": True, "data": {}})
        # Steps 3-7 all fail.
        monkeypatch.setattr(APKProcessor, "step_3_entropy_analysis",
                            lambda self, d: {"success": False, "error": "boom"})
        monkeypatch.setattr(APKProcessor, "step_4_encoding_detection",
                            lambda self, d: {"success": False, "error": "boom"})
        monkeypatch.setattr(APKProcessor, "step_5_payload_decoding",
                            lambda self, d: {"success": False, "error": "boom"})
        monkeypatch.setattr(APKProcessor, "step_6_c2_extraction",
                            lambda self, a, b: {"success": False, "error": "boom"})
        monkeypatch.setattr(APKProcessor, "step_7_threat_chain",
                            lambda self, a, b: {"success": False, "error": "boom"})

        out = proc.process()

        assert out["failed_steps"] == [
            "entropy_analysis", "encoding_detection",
            "payload_decoding", "c2_extraction", "threat_chain",
        ]
        assert out["partial"] is True
        assert out["data"]["failed_steps"] == out["failed_steps"]

    def test_hard_step_failure_returns_not_success(self, monkeypatch):
        """A failed step 1 must not be reported as success."""
        from backend.core.apk_processor import APKProcessor

        proc = APKProcessor.__new__(APKProcessor)
        proc.apk_path = "x.apk"
        proc.apk_hash = "x"
        proc.results = {"steps": {}}

        monkeypatch.setattr(APKProcessor, "step_1_androguard_analysis",
                            lambda self: {"success": False, "error": "DEX loading failed"})

        out = proc.process()
        assert out["success"] is False
        assert "DEX loading failed" in out["error"]


# ---------------------------------------------------------------------------
# T-2: classify_c2 verdict branches
# ---------------------------------------------------------------------------
class TestClassifyC2Verdicts:
    def test_malicious_classification(self):
        from backend.threat_intel import classify_c2

        verdict, _reason = classify_c2({
            "domain": "evil.example", "port": 4444,
            "path": "/gate.php", "protocol": "http",
        })
        assert verdict == "malicious"

    def test_benign_artifact(self):
        from backend.threat_intel import classify_c2

        verdict, reason = classify_c2({"domain": "libfoo.so"})
        assert verdict == "benign"

    def test_returns_a_known_verdict_enum(self):
        from backend.threat_intel import classify_c2

        for rec in ({"domain": "a.example"}, {"domain": "cdn.example.com", "port": 443}):
            verdict, _ = classify_c2(rec)
            assert verdict in ("malicious", "suspicious", "benign")


# ---------------------------------------------------------------------------
# T-3: analyst-facing exports
# ---------------------------------------------------------------------------
class TestThreatIntelExports:
    RESULT = {
        "c2_infrastructure": [{
            "domain": "bad.example", "raw_url": "https://bad.example/x",
            "c2_id": "c2_000",
        }],
        "metadata": {},
    }

    def test_to_csv_includes_the_domain(self):
        from backend.threat_intel import to_csv

        text = to_csv(self.RESULT)
        assert "bad.example" in text

    def test_to_stix_pattern_quoting(self):
        from backend.threat_intel import to_stix

        bundle = to_stix(self.RESULT, "sample1")
        pattern = bundle["objects"][0]["pattern"]
        assert pattern == "[domain-name:value = 'bad.example']"

    def test_to_yara_emits_a_string_for_a_malicious_c2(self):
        """to_yara filters on the live classification, so benign C2s emit no rule."""
        from backend.threat_intel import to_yara

        malicious = {
            "c2_infrastructure": [{
                "domain": "evil.example", "port": 4444,
                "raw_url": "http://evil.example/gate.php", "path": "/gate.php",
                "protocol": "http", "c2_id": "c2_001",
            }],
            "metadata": {},
        }
        rule = to_yara(malicious, "sample1")
        assert 'evil.example' in rule

    def test_to_yara_skips_benign_c2(self):
        from backend.threat_intel import to_yara

        rule = to_yara(self.RESULT, "sample1")
        assert "condition:" in rule
        assert "no malicious/suspicious C2 indicators extracted" in rule


# ---------------------------------------------------------------------------
# T-4: bare-domain / bare-IP fallback extraction (the commonest real source)
# ---------------------------------------------------------------------------
class TestC2BareTokenFallback:
    def _extract(self, literals):
        from analysis.step5_c2_extraction import extract_c2_infrastructure

        payload_res = {"sample_id": "s1", "payloads": [], "string_literals": literals}
        strings_res = {"sample_id": "s1", "string_literals": literals}
        out = extract_c2_infrastructure(payload_res, strings_res)
        if isinstance(out, dict):
            return out.get("c2_infrastructure", [])
        return out

    def test_java_package_token_is_not_a_c2_domain(self):
        out = self._extract([
            {"value": "com.evil.tracker", "category": "string_literal", "entropy": 3.0}
        ])
        domains = {r.get("domain") for r in out if isinstance(r, dict)}
        assert "com.evil.tracker" not in domains

    def test_private_ip_is_not_reported_as_c2(self):
        out = self._extract([
            {"value": "10.1.2.3", "category": "string_literal", "entropy": 2.0}
        ])
        ips = {r.get("ip") for r in out if isinstance(r, dict)}
        assert "10.1.2.3" not in ips


# ---------------------------------------------------------------------------
# T-6: ELFBreaker on corrupt input must return an error, not raise
# ---------------------------------------------------------------------------
class TestElfBreakerCorruptInput:
    @pytest.mark.parametrize("payload", [b"not an elf", b"", b"\x7fELF" + b"\x00" * 60])
    def test_corrupt_input_returns_error_dict(self, payload):
        from backend.elf_analyzer import ELFBreaker

        result = ELFBreaker("bad.so", payload).analyze()
        assert isinstance(result, dict)
        assert "error" in result


# ---------------------------------------------------------------------------
# T-7: IP legitimacy verdicts
# ---------------------------------------------------------------------------
class TestIpLegitimacyVerdicts:
    def test_reserved_private_is_likely_benign(self):
        from analysis.ip_validation import calculate_ip_legitimacy_score

        result = calculate_ip_legitimacy_score("192.168.1.1", "", "manifest")
        assert result["verdict"] == "likely_benign"
        assert "Reserved" in result["reason"]

    def test_cdn_vs_datacenter_asn_weighting(self):
        from analysis.ip_validation import calculate_ip_legitimacy_score

        cdn = calculate_ip_legitimacy_score("8.8.8.8", "", "manifest",
                                            asn_info={"type": "cdn"})
        dc = calculate_ip_legitimacy_score("8.8.8.8", "", "manifest",
                                           asn_info={"type": "datacenter"})
        cdn_pts = cdn["factors"]["asn"]["points"]
        dc_pts = dc["factors"]["asn"]["points"]
        assert dc_pts > cdn_pts


# ---------------------------------------------------------------------------
# T-9: obfuscation view / deobfuscate endpoints
# ---------------------------------------------------------------------------
class TestObfuscationView:
    def test_build_view_returns_expected_keys(self):
        from backend.obfuscation_view import build_obfuscation_view

        view = build_obfuscation_view(
            "sid", {"obfuscation_score": 70, "indicators": {"reflection": ["a"]}})
        assert "obfuscation_score" in view
        assert "obfuscation_level" in view

    def test_build_view_degrades_on_none(self):
        from backend.obfuscation_view import build_obfuscation_view

        view = build_obfuscation_view("sid", None)
        assert isinstance(view, dict)

    def test_deobfuscate_base64(self):
        from backend.obfuscation_view import deobfuscate_text

        out = deobfuscate_text("aGVsbG8=", "base64")
        assert "hello" in str(out)


# ---------------------------------------------------------------------------
# T-10: PDF report generation
# ---------------------------------------------------------------------------
class TestPdfReport:
    def test_minimal_report_still_produces_a_pdf(self, tmp_path):
        from backend.pdf_report import generate_report

        pdf = generate_report(
            sample_id="s", sample_result={}, threat_data={},
            obfuscation={}, annotated_methods=[])
        assert isinstance(pdf, (bytes, bytearray))
        assert bytes(pdf)[:5] == b"%PDF-"


# ---------------------------------------------------------------------------
# T-11b: container repair must survive damaged ZIPs (defect found in review)
# ---------------------------------------------------------------------------
class TestContainerRepairRobustness:
    def _zip(self, n=3):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for i in range(n):
                z.writestr("f%d.txt" % i, b"payload" * 10)
        return buf.getvalue()

    @pytest.mark.parametrize("truncate", [1, 10, 15, 25])
    def test_truncated_zip_does_not_crash(self, truncate):
        from analysis.step19_container_repair import _central_directory, _local_headers

        data = self._zip()[:-truncate]
        assert isinstance(_central_directory(data), list)
        assert isinstance(_local_headers(data), list)

    def test_extra_field_length_does_not_break_iteration(self):
        """elen/clen were double-counted, so one member was parsed and the rest lost."""
        from analysis.step19_container_repair import _central_directory

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for i in range(4):
                zi = zipfile.ZipInfo("m%d.txt" % i)
                zi.extra = b"\x99\x99\x0c\x00" + b"X" * 12
                z.writestr(zi, b"data-%d" % i)
        data = buf.getvalue()

        parsed = {e["name"] for e in _central_directory(data)}
        real = set(zipfile.ZipFile(io.BytesIO(data)).namelist())
        assert parsed == real
        assert len(parsed) == 4


# ---------------------------------------------------------------------------
# I-13/I-25: decoding engine shape consistency
# ---------------------------------------------------------------------------
class TestDecodingEngineShape:
    def test_short_input_does_not_raise_keyerror(self):
        """multi_layer_decode early-returned without c2_* keys."""
        from analysis.decoding_engine import run_decoding_engine

        out = run_decoding_engine([{"value": "YWJjZGU=", "entropy": 2.0}])
        assert out, "expected a result record"
        assert "c2_indicators" in out[0]["decoding"]

    def test_short_input_returns_empty_list_without_raising(self):
        from analysis.decoding_engine import run_decoding_engine

        assert run_decoding_engine([{"value": "abc", "entropy": 1.0}]) == []

# ---------------------------------------------------------------------------
# T-5: family_id knowledge-base strict gate
# ---------------------------------------------------------------------------
class TestFamilyKnowledgeGate:
    def test_strong_token_set_names_the_family(self):
        from backend.family_id import _kb_load, _match_family_knowledge

        kb = _kb_load()
        assert kb, "expected a populated knowledge base"
        fam = next(iter(kb))
        entries = kb[fam].get("strings", [])
        # entries are dicts: {"token": ..., "coverage": ..., "precision": ...}
        tokens = [e["token"] for e in entries
                  if isinstance(e, dict) and e.get("token")][:5]
        if len(tokens) < 3:
            pytest.skip("no family with >=3 KB tokens")

        result = {"strings": {"string_literals": [
            {"value": t, "category": "string_literal", "entropy": 3.0} for t in tokens]}}
        match = _match_family_knowledge(result)
        assert match is not None, "expected a KB match for 5 real tokens"
        assert match.get("family") == fam

    def test_single_generic_token_abstains(self):
        from backend.family_id import _match_family_knowledge

        result = {"strings": {"string_literals": [
            {"value": "android", "category": "string_literal", "entropy": 2.0}]}}
        match = _match_family_knowledge(result)
        # One generic token must not name a family (the 23-FP regression gate).
        assert match is None


# ---------------------------------------------------------------------------
# T-8: step 8 obfuscation entry point and its failure contract
# ---------------------------------------------------------------------------
class TestObfuscationStep:
    def test_minimal_zip_produces_a_verdict(self, tmp_path):
        from analysis.step8_obfuscation_analysis import analyze_obfuscation

        apk = tmp_path / "fake.apk"
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("AndroidManifest.xml", b"<manifest/>")

        result = analyze_obfuscation(str(apk), work_dir=str(tmp_path))
        assert "obfuscation_score" in result
        assert "obfuscation_level" in result

    def test_inner_exception_propagates(self, monkeypatch, tmp_path):
        from analysis import step8_obfuscation_analysis as s8

        apk = tmp_path / "fake.apk"
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("AndroidManifest.xml", b"<manifest/>")

        monkeypatch.setattr(s8, "_analyze_obfuscation_inner",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        with pytest.raises(RuntimeError):
            s8.analyze_obfuscation(str(apk), work_dir=str(tmp_path))


# ---------------------------------------------------------------------------
# I-11: cache self-heal - a pre-fix entry advertises a boost it never applied
# ---------------------------------------------------------------------------
class TestFamilyCacheSelfHeal:
    def test_entry_claiming_boost_at_base_confidence_is_stale(self):
        from backend.family_id import _cached_confidence_lacks_boost, FAMILY_SIGNATURES

        sig = next(s for s in FAMILY_SIGNATURES if s.family_name == "KungFu")
        base = sig.confidence

        stale = {"family": "KungFu", "confidence": base,
                 "method": "signature_v3", "reasoning": "x; class_boost:iq"}
        assert _cached_confidence_lacks_boost(stale) is True

        # Once the boost is applied the confidence no longer equals the base.
        fixed = {"family": "KungFu", "confidence": base + 0.05,
                 "method": "signature_v3", "reasoning": "x; class_boost:iq"}
        assert _cached_confidence_lacks_boost(fixed) is False

        # An entry with no boost claim is never stale.
        plain = {"family": "KungFu", "confidence": base,
                 "method": "signature_v3", "reasoning": "c2:x; perms(2.0)"}
        assert _cached_confidence_lacks_boost(plain) is False


# ---------------------------------------------------------------------------
# I-14b: identify_family must honour use_cache on WRITE, not just on read
# ---------------------------------------------------------------------------
class TestFamilyCacheWriteFlag:
    def test_use_cache_false_does_not_persist(self, tmp_path, monkeypatch):
        from backend import family_id
        from backend.family_id import identify_family

        monkeypatch.setattr(family_id.settings, "WORK_DIR", tmp_path)
        probe = "ff" * 32
        res = {
            "metadata": {"sha256": probe},
            "certificate_analysis": {},
            "strings": {"string_literals": []},
            "c2_infrastructure": [],
        }

        identify_family(probe, res, use_llm=False, use_cache=False)
        assert not (tmp_path / probe / "family.json").exists(), (
            "use_cache=False must not persist a verdict over the cache")

        identify_family(probe, res, use_llm=False, use_cache=True)
        assert (tmp_path / probe / "family.json").exists()

    def test_ground_truth_files_survive_the_cert_tests(self):
        """test_family_id_cert.py must not disable the override suite-wide."""
        from backend import family_id

        assert family_id.GROUND_TRUTH_FILES, "GROUND_TRUTH_FILES was left empty"
