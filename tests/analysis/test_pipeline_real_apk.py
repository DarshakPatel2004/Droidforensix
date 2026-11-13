"""Audit M8: run the real pipeline on a real APK, so steps 10-18 see real step-1 output.

The mocked integration tests cannot catch key or type mismatches between steps (audit
A2-H2..H6). This test needs an APK the repo does not ship, so it runs only when
DF_TEST_APK points at one, e.g. `set DF_TEST_APK=D:\samples\some.apk`.
"""
import os
from pathlib import Path

import pytest

from analysis.pipeline import run_pipeline

APK = os.environ.get("DF_TEST_APK", "")

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not APK or not Path(APK).is_file(), reason="set DF_TEST_APK to a real APK"),
]


def test_pipeline_runs_steps_10_to_18_on_real_apk(tmp_path):
    result = run_pipeline(APK, work_dir=str(tmp_path))
    # Each of these used to be silently empty or crash on real input (audit A2 H2-H6, M1).
    assert "reflective_tracing" in result
    assert "network_protocols" in result
    assert "binary_packing" in result
    assert "family_clustering" in result
    assert "threat_synthesis" in result
