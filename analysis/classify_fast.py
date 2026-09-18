"""
Fast mal/ben inference: steps 1-6 only (no LLM), then RandomForest predict.
Usage: from analysis.classify_fast import classify_malware_fast
       is_mal, conf = classify_malware_fast("path/to.apk")
"""
import pickle
import tempfile
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent.parent / "evaluation" / "classifier_data" / "malben_rf.pkl"

FEATURES = ['file_size_kb','total_strings','num_encodings','num_payloads','num_c2','num_c2_real','num_c2_fb_ip','num_chains','num_secrets','secret_risk_score','num_permissions','num_dangerous_perms','target_sdk','min_sdk','apktool_success','native_libs_found','decompiled_classes','crypter_stub','master_key_verdict_recovered','master_key_e_coded']

DANGEROUS_PERMS = {
    'android.permission.SEND_SMS','android.permission.RECEIVE_SMS','android.permission.READ_SMS',
    'android.permission.CALL_PHONE','android.permission.READ_CONTACTS','android.permission.WRITE_CONTACTS',
    'android.permission.GET_ACCOUNTS','android.permission.READ_CALL_LOG','android.permission.WRITE_CALL_LOG',
    'android.permission.PROCESS_OUTGOING_CALLS','android.permission.READ_PHONE_STATE','android.permission.READ_PHONE_NUMBERS',
    'android.permission.USE_SIP','android.permission.ACCESS_FINE_LOCATION','android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.ACCESS_BACKGROUND_LOCATION','android.permission.RECORD_AUDIO','android.permission.CAMERA',
    'android.permission.ACTIVITY_RECOGNITION','android.permission.READ_EXTERNAL_STORAGE','android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.WRITE_SETTINGS','android.permission.REQUEST_INSTALL_PACKAGES','android.permission.SYSTEM_ALERT_WINDOW',
    'android.permission.BIND_DEVICE_ADMIN','android.permission.READ_CALENDAR','android.permission.WRITE_CALENDAR',
}

_model = None

def _load_model():
    global _model
    if _model is None:
        with open(MODEL_PATH, 'rb') as f:
            _model = pickle.load(f)
    return _model


def extract_feature_vector(result: dict) -> list:
    meta = result.get('metadata', {})
    extr = result.get('extraction', {})
    manifest = result.get('manifest', {})
    secrets = result.get('secret_risk', {})
    c2 = result.get('c2_infrastructure', []) or []
    perms = manifest.get('uses_permissions', []) or []
    real = [c for c in c2 if not c.get('is_fallback')]
    fb_ip = [c for c in c2 if c.get('is_fallback') and c.get('ip')]
    feats = {
        'file_size_kb': round(meta.get('file_size_bytes', 0) / 1024, 1),
        'total_strings': extr.get('total_strings_extracted', 0),
        'num_encodings': len(result.get('encodings', []) or []),
        'num_payloads': len(result.get('payloads', []) or []),
        'num_c2': len(c2),
        'num_c2_real': len(real),
        'num_c2_fb_ip': len(fb_ip),
        'num_chains': len(result.get('threat_chains', []) or []),
        'num_secrets': secrets.get('total_secrets', 0) if isinstance(secrets, dict) else 0,
        'secret_risk_score': secrets.get('risk_score', 0) if isinstance(secrets, dict) else 0,
        'num_permissions': len(perms),
        'num_dangerous_perms': sum(1 for p in perms if p in DANGEROUS_PERMS),
        'target_sdk': manifest.get('target_sdk_version') or 0,
        'min_sdk': manifest.get('min_sdk_version') or 0,
        'apktool_success': 1 if extr.get('apktool_success') else 0,
        'native_libs_found': len(extr.get('native_libs_found', [])) if isinstance(extr.get('native_libs_found'), list) else 0,
        'decompiled_classes': extr.get('decompiled_classes', 0) or 0,
        'crypter_stub': 1 if extr.get('crypter_stub') else 0,
        'master_key_verdict_recovered': 1 if (result.get('master_key') or {}).get('verdict') == 'RECOVERED' else 0,
        'master_key_e_coded': 1 if (result.get('master_key') or {}).get('is_e_coded') else 0,
    }
    return [float(feats[f]) for f in FEATURES]


def classify_malware_fast(apk_path: str, pipeline_timeout: int = 600, work_dir: str | None = None) -> tuple:
    """
    Returns (is_malicious: bool, confidence: float 0-100).
    Runs steps 1-6 fresh (no cache), no LLM calls.
    """
    from analysis.pipeline import run_pipeline
    bundle = _load_model()
    clf, feats_order = bundle['model'], bundle['features']
    assert feats_order == FEATURES, "feature order mismatch with trained model"
    work = work_dir or tempfile.mkdtemp(prefix="fastcls_")
    result = run_pipeline(apk_path, work, event_emitter=None,
                          pipeline_timeout=pipeline_timeout, stop_after=6)
    vec = extract_feature_vector(result)
    proba = clf.predict_proba([vec])[0]
        # classes_ = [0, 1] -> proba[1] = P(malware)
    conf = round(float(proba[1]) * 100, 1)
    return bool(proba[1] >= 0.5), conf
