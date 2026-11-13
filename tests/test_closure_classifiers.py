"""Unit tests for the malware/benign fast classifier and the family ML classifier (T-10).

The pickled models are tiny fakes defined at module level so they round-trip
through pickle. No real model file, pipeline run or LLM is involved.
"""

import json
import pickle
from pathlib import Path

import numpy as np
import pytest
from scipy.sparse import csr_matrix

import analysis.classify_fast as classify_fast
import analysis.ml_classifier as ml_classifier
import analysis.pipeline as pipeline_module


class FakeBinaryModel:
    """Stands in for the malben RandomForest: predict_proba returns [P(benign), P(malware)]."""

    def __init__(self, p_malware: float):
        self.p_malware = p_malware

    def predict_proba(self, X):
        return np.array([[1.0 - self.p_malware, self.p_malware]])


def _write_pickle(path: Path, obj) -> Path:
    with open(path, "wb") as f:
        pickle.dump(obj, f)
    return path


SYNTHETIC_RESULT = {
    "metadata": {"file_size_bytes": 2048},
    "extraction": {
        "total_strings_extracted": 120,
        "apktool_success": True,
        "native_libs_found": ["lib/arm64/a.so", "lib/x86/b.so"],
        "decompiled_classes": 42,
        "crypter_stub": False,
    },
    "manifest": {
        "uses_permissions": ["android.permission.SEND_SMS", "android.permission.INTERNET"],
        "target_sdk_version": 33,
        "min_sdk_version": 21,
    },
    "secret_risk": {"total_secrets": 3, "risk_score": 20},
    "c2_infrastructure": [],
    "encodings": [{}, {}],
    "payloads": [{}],
    "threat_chains": [{}, {}, {}],
    "master_key": {"verdict": "RECOVERED", "is_e_coded": True},
}


# ---------------------------------------------------------------------------
# classify_fast
# ---------------------------------------------------------------------------


class TestExtractFeatureVector:
    def test_vector_follows_declared_feature_order(self):
        vec = classify_fast.extract_feature_vector(SYNTHETIC_RESULT)
        assert len(vec) == len(classify_fast.FEATURES) == 15
        by_name = dict(zip(classify_fast.FEATURES, vec, strict=True))
        assert by_name["file_size_kb"] == 2.0
        assert by_name["total_strings"] == 120.0
        assert by_name["num_secrets"] == 3.0
        assert by_name["secret_risk_score"] == 20.0
        assert by_name["num_permissions"] == 2.0
        assert by_name["num_dangerous_perms"] == 1.0  # SEND_SMS only; INTERNET is not in the set
        assert by_name["target_sdk"] == 33.0
        assert by_name["min_sdk"] == 21.0
        assert by_name["apktool_success"] == 1.0
        assert by_name["native_libs_found"] == 2.0
        assert by_name["decompiled_classes"] == 42.0
        assert by_name["crypter_stub"] == 0.0
        assert by_name["master_key_verdict_recovered"] == 1.0
        assert by_name["master_key_e_coded"] == 1.0

    def test_empty_result_yields_zero_vector(self):
        assert classify_fast.extract_feature_vector({}) == [0.0] * 15

    def test_no_domains_means_no_c2_alignment(self):
        vec = classify_fast.extract_feature_vector({})
        assert vec[classify_fast.FEATURES.index("c2_alignment")] == 0.0


class TestClassifyMalwareFast:
    @pytest.fixture
    def fake_pipeline(self, monkeypatch):
        calls = []

        def run_pipeline(apk_path, work, event_emitter=None, pipeline_timeout=None, stop_after=None):
            calls.append({"apk": apk_path, "work": work, "stop_after": stop_after, "emitter": event_emitter})
            return SYNTHETIC_RESULT

        monkeypatch.setattr(pipeline_module, "run_pipeline", run_pipeline)
        return calls

    def _model(self, tmp_path, p_malware: float, features=None) -> Path:
        bundle = {"model": FakeBinaryModel(p_malware),
                  "features": list(classify_fast.FEATURES) if features is None else features}
        return _write_pickle(tmp_path / f"model_{p_malware}_{id(features)}.pkl", bundle)

    def test_malicious_at_or_above_threshold(self, tmp_path, fake_pipeline):
        model = self._model(tmp_path, 0.8)
        is_mal, conf = classify_fast.classify_malware_fast(
            "closure.apk", model_path=model, threshold=0.5, work_dir=str(tmp_path / "w"),
        )
        assert is_mal is True
        assert conf == 80.0

    def test_threshold_is_inclusive_and_respected(self, tmp_path, fake_pipeline):
        model = self._model(tmp_path, 0.5)
        is_mal, conf = classify_fast.classify_malware_fast(
            "closure.apk", model_path=model, threshold=0.5, work_dir=str(tmp_path / "w"),
        )
        assert (is_mal, conf) == (True, 50.0)
        is_mal, _ = classify_fast.classify_malware_fast(
            "closure.apk", model_path=model, threshold=0.6, work_dir=str(tmp_path / "w"),
        )
        assert is_mal is False

    def test_runs_only_steps_one_to_six_without_emitter(self, tmp_path, fake_pipeline):
        model = self._model(tmp_path, 0.1)
        classify_fast.classify_malware_fast("closure.apk", model_path=model, work_dir=str(tmp_path / "w"))
        assert fake_pipeline[0]["stop_after"] == 6
        assert fake_pipeline[0]["emitter"] is None
        assert fake_pipeline[0]["apk"] == "closure.apk"

    def test_temporary_work_dir_is_removed(self, tmp_path, fake_pipeline):
        model = self._model(tmp_path, 0.9)
        classify_fast.classify_malware_fast("closure.apk", model_path=model)
        used = Path(fake_pipeline[0]["work"])
        assert not used.exists()

    def test_caller_supplied_work_dir_is_kept(self, tmp_path, fake_pipeline):
        work = tmp_path / "keep_me"
        work.mkdir()
        model = self._model(tmp_path, 0.9)
        classify_fast.classify_malware_fast("closure.apk", model_path=model, work_dir=str(work))
        assert work.exists()
        assert fake_pipeline[0]["work"] == str(work)

    def test_feature_order_mismatch_is_rejected(self, tmp_path, fake_pipeline):
        model = self._model(tmp_path, 0.9, features=["file_size_kb"])
        with pytest.raises(ValueError, match="feature order mismatch"):
            classify_fast.classify_malware_fast("closure.apk", model_path=model, work_dir=str(tmp_path / "w"))


# ---------------------------------------------------------------------------
# ml_classifier (family prediction)
# ---------------------------------------------------------------------------


# Fakes are pickled into the model files, so they cannot keep per-instance state
# the test can read back. They record into this module-level dict instead.
RECORD: dict = {}


class FakeTfidf:
    def transform(self, docs):
        RECORD["docs"] = list(docs)
        return csr_matrix(np.array([[1.0, 0.0, 2.0]]))


class FakeMlb:
    def transform(self, perm_lists):
        # One column per known permission short name; the fake knows two.
        row = [1.0 if "SEND_SMS" in perm_lists[0] else 0.0,
               1.0 if "INTERNET" in perm_lists[0] else 0.0]
        return csr_matrix(np.array([row]))


class FakeFamilyClf:
    def __init__(self, probs, n_features=7):
        self.probs = probs
        self.n_features_in_ = n_features
        self.classes_ = np.array(["ClosureFamily", "OtherFamily"])

    def predict_proba(self, X):
        RECORD["shape"] = X.shape
        RECORD["row"] = X.toarray()[0].tolist()
        return np.array([self.probs])


@pytest.fixture
def ml_files(tmp_path, monkeypatch):
    model_path = tmp_path / "family_ml.pkl"
    vec_path = tmp_path / "family_ml_vectorizer.pkl"
    cache_path = tmp_path / "gap_features_cache.json"
    cache_path.write_text("{}", encoding="utf-8")  # empty gap cache: every sample takes the result-string path
    monkeypatch.setattr(ml_classifier, "MODEL_PATH", model_path)
    monkeypatch.setattr(ml_classifier, "VECTORIZER_PATH", vec_path)
    monkeypatch.setattr(ml_classifier, "CACHE_PATH", cache_path)
    RECORD.clear()
    return {"model": model_path, "vec": vec_path, "cache": cache_path}


def _install_model(files, clf, tfidf=None):
    _write_pickle(files["model"], clf)
    _write_pickle(files["vec"], {"tfidf": tfidf or FakeTfidf(), "mlb": FakeMlb()})


class TestPredictForResult:
    def test_unknown_when_no_model_is_trained(self, ml_files):
        assert ml_classifier.predict_for_result({"strings": {}}, "abc") == ("unknown", 0.0)

    def test_predicts_argmax_family_with_probability(self, ml_files):
        _install_model(ml_files, FakeFamilyClf([0.8, 0.2]))
        result = {
            "strings": {"k": "https://evil.example/gate"},
            "manifest": {"uses_permissions": ["android.permission.SEND_SMS"]},
            "extraction": {"decompiled_classes": 42},
        }
        family, conf = ml_classifier.predict_for_result(result)
        assert family == "ClosureFamily"
        assert conf == pytest.approx(0.8)

    def test_feature_row_is_tfidf_then_perms_then_numeric(self, ml_files):
        _install_model(ml_files, FakeFamilyClf([0.6, 0.4]))
        result = {
            "strings": {"k": "Hello"},
            "manifest": {"uses_permissions": ["android.permission.SEND_SMS"]},
            "extraction": {"decompiled_classes": 42},
        }
        ml_classifier.predict_for_result(result)
        assert RECORD["shape"] == (1, 7)
        # 3 tfidf dims, 2 permission dims, then [class_count, has_perms]
        assert RECORD["row"] == [1.0, 0.0, 2.0, 1.0, 0.0, 42.0, 1.0]
        # Only the gap-cache path lowercases; the result-string fallback keeps case.
        assert RECORD["docs"] == ["Hello"]

    def test_gap_cache_entry_is_preferred_over_result_strings(self, ml_files):
        _install_model(ml_files, FakeFamilyClf([0.6, 0.4]))
        sid = "a" * 64
        ml_files["cache"].write_text(
            json.dumps({sid: {"strings": ["Cached Payload Name"], "permissions": [], "class_count": 0}}),
            encoding="utf-8",
        )
        ml_classifier.predict_for_result({"strings": {"k": "ignored value"}}, sid)
        assert RECORD["docs"] == ["cached payload name"]
        # No permissions in the cache entry, so the has-perms flag is 0.
        assert RECORD["row"][-1] == 0.0

    def test_missing_gap_cache_falls_back_to_result_strings(self, ml_files):
        # A missing gap-cache file falls back to the result strings, keeping their case.
        _install_model(ml_files, FakeFamilyClf([0.6, 0.4]))
        ml_files["cache"].unlink()
        family, _ = ml_classifier.predict_for_result({"strings": {"k": "Hello"}}, "b" * 64)
        assert family == "ClosureFamily"
        assert RECORD["docs"] == ["Hello"]

    def test_dimension_mismatch_returns_unknown(self, ml_files):
        _install_model(ml_files, FakeFamilyClf([0.6, 0.4], n_features=99))
        assert ml_classifier.predict_for_result({"strings": {"k": "x"}}) == ("unknown", 0.0)
