"""Smoke tests: verify all backend and analysis modules import cleanly."""

import importlib
import pkgutil
from pathlib import Path


def _iter_modules(package_name: str, path: Path):
    """Yield (module_name, module_path) for all .py files in a package dir."""
    for f in path.iterdir():
        if f.suffix != ".py" or f.name.startswith("_"):
            continue
        yield f"{package_name}.{f.stem}", f


BACKEND_MODULES = list(_iter_modules("backend", Path("backend")))
ANALYSIS_MODULES = list(
    _iter_modules("analysis", Path("analysis"))
)


def _check_import(module_name: str, file_path: Path):
    """Try importing the module; raise descriptive error on failure."""
    try:
        importlib.import_module(module_name)
    except ImportError as e:
        raise AssertionError(
            f"Failed to import {module_name} ({file_path}): {e}"
        ) from e


class TestBackendImports:
    @staticmethod
    def _import(module_name, file_path):
        _check_import(module_name, file_path)

    def test_config(self):
        self._import("backend.config", Path("backend/config.py"))

    def test_events(self):
        self._import("backend.events", Path("backend/events.py"))

    def test_validators(self):
        self._import("backend.validators", Path("backend/validators.py"))

    def test_transformers(self):
        self._import("backend.transformers", Path("backend/transformers.py"))

    def test_censys_enrichment(self):
        self._import("backend.censys_enrichment", Path("backend/censys_enrichment.py"))

    def test_elf_analyzer(self):
        self._import("backend.elf_analyzer", Path("backend/elf_analyzer.py"))

    def test_family_id(self):
        self._import("backend.family_id", Path("backend/family_id.py"))

    def test_obfuscation_view(self):
        self._import("backend.obfuscation_view", Path("backend/obfuscation_view.py"))

    def test_pdf_report(self):
        self._import("backend.pdf_report", Path("backend/pdf_report.py"))

    def test_threat_intel(self):
        self._import("backend.threat_intel", Path("backend/threat_intel.py"))

    def test_threat_intelligence(self):
        self._import("backend.threat_intelligence", Path("backend/threat_intelligence.py"))

    def test_main(self):
        self._import("backend.main", Path("backend/main.py"))


class TestAnalysisImports:
    @staticmethod
    def _import(module_name, file_path):
        _check_import(module_name, file_path)

    def test_decoding_engine(self):
        self._import("analysis.decoding_engine", Path("analysis/decoding_engine.py"))

    def test_ip_validation(self):
        self._import("analysis.ip_validation", Path("analysis/ip_validation.py"))

    def test_hardcoded_secrets(self):
        self._import("analysis.hardcoded_secrets", Path("analysis/hardcoded_secrets.py"))

    def test_retry_utils(self):
        self._import("analysis.retry_utils", Path("analysis/retry_utils.py"))

    def test_step1_apk_extraction(self):
        self._import("analysis.step1_apk_extraction", Path("analysis/step1_apk_extraction.py"))

    def test_step2_string_enumeration(self):
        self._import("analysis.step2_string_enumeration", Path("analysis/step2_string_enumeration.py"))

    def test_step3_encoding_detection(self):
        self._import("analysis.step3_encoding_detection", Path("analysis/step3_encoding_detection.py"))

    def test_step4_decoding(self):
        self._import("analysis.step4_decoding", Path("analysis/step4_decoding.py"))

    def test_step5_c2_extraction(self):
        self._import("analysis.step5_c2_extraction", Path("analysis/step5_c2_extraction.py"))

    def test_step6_correlation(self):
        self._import("analysis.step6_correlation", Path("analysis/step6_correlation.py"))

    def test_step7_llm_assessment(self):
        self._import("analysis.step7_llm_assessment", Path("analysis/step7_llm_assessment.py"))

    def test_step8_obfuscation_analysis(self):
        self._import("analysis.step8_obfuscation_analysis", Path("analysis/step8_obfuscation_analysis.py"))

    def test_step9_post_process(self):
        self._import("analysis.step9_post_process", Path("analysis/step9_post_process.py"))

    def test_pipeline(self):
        self._import("analysis.pipeline", Path("analysis/pipeline.py"))
