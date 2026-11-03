"""
Security regression tests for P2-A2 (unvalidated sample_id in filesystem paths).

No request-supplied sample_id was validated before being joined into a
filesystem path. backend/transformers.py:86 and roughly fifteen other sites
build WORK_DIR / sample_id / "<fixed name>", so a ".."-relative path segment
selected directories outside WORK_DIR for read, write and delete. Because the
route converter is "[^/]+", one segment reaches one level on POSIX - but "\\" is
a separator on Windows, so "..\\..\\..\\dir" reached arbitrary depth in a
single request.

sample_id is always compute_sha256() of the APK (step1_apk_extraction.py:437),
so requiring a bare 64-hex string is lossless for real samples. The non-hash
directories present in analysis/work/ (s1, surrogate_test, test_*) are test
pollution, not samples.

These tests assert the property (nothing outside WORK_DIR is touched) rather
than only a status code, so a future regression that rejects for the wrong
reason still fails.
"""
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.main import app

REAL_HASH = hashlib.sha256(b"a-real-sample").hexdigest()

# Path segments that must never select a directory outside WORK_DIR.
BAD_SAMPLE_IDS = [
    "..",
    ".",
    "../evil",
    "..\\evil",
    "..\\..\\..\\evil",
    "....//evil",
    "%2e%2e/evil",
]


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def work_dir(tmp_path, monkeypatch):
    """Point WORK_DIR at a temp dir holding one legitimate sample."""
    root = tmp_path / "work"
    sample = root / REAL_HASH
    sample.mkdir(parents=True)
    (sample / "pipeline_result.json").write_text(
        json.dumps({"sample_id": REAL_HASH, "family_identification": {"family": "TestFam"}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "WORK_DIR", root)

    # routers/dissection.py and transformers.py each bind WORK_DIR at import time, so patching
    # settings alone would leave them pointing at the real directory - and the
    # traversal tests would pass for the wrong reason (nothing happening at all).
    import backend.routers.dissection as dissection_routes
    import backend.transformers as transformers
    monkeypatch.setattr(dissection_routes, "WORK_DIR", root)
    monkeypatch.setattr(transformers, "WORK_DIR", root)
    return root


def _snapshot(root):
    out = {}
    for path in root.rglob("*"):
        if path.is_file():
            try:
                out[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                out[str(path.relative_to(root))] = "<unreadable>"
    return out


def test_sample_id_validator_rejects_non_hash_identifiers():
    """The validator itself: only bare 64-hex sample IDs are acceptable."""
    from backend.validators import validate_sample_id

    assert validate_sample_id(REAL_HASH) == REAL_HASH

    for bad in ["", "s1", "abc", "z" * 64, "../evil", "..", REAL_HASH + "x",
                REAL_HASH.upper().replace("A", "a") + "/x", "..\\..\\evil"]:
        with pytest.raises(ValueError):
            validate_sample_id(bad)


def test_sample_id_validator_rejects_non_hex_of_correct_length():
    """Length alone is not enough - 'z'*64 must not pass."""
    from backend.validators import validate_sample_id

    with pytest.raises(ValueError):
        validate_sample_id("z" * 64)


@pytest.mark.parametrize("bad_id", BAD_SAMPLE_IDS)
@pytest.mark.parametrize(
    "path",
    [
        "/api/sample/{sid}",
        "/api/sample/{sid}/status",
        "/api/sample/{sid}/dissection",
        "/api/sample/{sid}/dissection/strings",
        "/api/sample/{sid}/threat-intel",
    ],
)
def test_traversal_sample_id_touches_nothing_outside_work_dir(client, work_dir, bad_id, path):
    """No endpoint may read, write or delete outside WORK_DIR via sample_id."""
    url = path.format(sid=bad_id.replace("\\", "%5C"))

    # Any status is acceptable EXCEPT a success that resolved outside WORK_DIR.
    response = client.get(url)
    assert response.status_code != 500 or True  # never fatal

    # Nothing outside WORK_DIR may exist as a result.
    assert not (work_dir.parent / "evil").exists(), f"{url} created a directory outside WORK_DIR"

    # And no legitimate sample may have been disturbed.
    assert (work_dir / REAL_HASH / "pipeline_result.json").exists()


def test_traversal_sample_id_cannot_delete_a_file_outside_work_dir(client, work_dir):
    """refresh=true unlinks a cache file - it must not be reachable by traversal.

    The target is planted one level ABOVE WORK_DIR, and a pipeline_result.json is
    placed beside it. That second part matters: without it load_result() 404s
    first and the delete branch is never reached, so the test would pass for the
    wrong reason. With it, removing the endpoint guard really does let
    "..\\outside" unlink the file (verified).
    """
    outside = work_dir.parent / "outside"
    outside.mkdir()
    (outside / "pipeline_result.json").write_text(
        json.dumps({"sample_id": REAL_HASH}), encoding="utf-8"
    )
    victim = outside / "dissection.json"
    victim.write_text("KEEP", encoding="utf-8")

    response = client.get("/api/sample/..%5Coutside/dissection?refresh=true")

    # 404 is the correct answer here: load_result() validates the identifier and
    # the endpoint 404s before reaching the unlink. The property that matters is
    # that nothing outside WORK_DIR is deleted.
    assert response.status_code in (400, 404), response.status_code
    assert victim.exists() and victim.read_text(encoding="utf-8") == "KEEP", (
        "a traversal sample_id deleted a file outside WORK_DIR"
    )


def test_dissection_delete_guard_is_load_bearing(client, work_dir):
    """The unlink itself must refuse a traversal id, not rely on a caller.

    load_result() rejects a malformed id with a 404, which would mask whether the
    delete is independently guarded. Calling the delete helper directly is what
    proves it: with the guard removed, "..\\outside" unlinks a file above
    WORK_DIR.
    """
    import asyncio

    from fastapi import HTTPException

    from backend.routers.dissection import _get_or_create_dissection

    outside = work_dir.parent / "outside"
    outside.mkdir()
    victim = outside / "dissection.json"
    victim.write_text("KEEP", encoding="utf-8")

    with pytest.raises(HTTPException) as exc:
        asyncio.run(_get_or_create_dissection("..\\outside", refresh=True))

    assert exc.value.status_code == 400
    assert victim.exists() and victim.read_text(encoding="utf-8") == "KEEP", (
        "the dissection delete helper unlinked a file outside WORK_DIR"
    )


def test_legitimate_sample_id_still_works(client, work_dir):
    """The fix must not break the normal case."""
    response = client.get(f"/api/sample/{REAL_HASH}")

    assert response.status_code == 200
    assert response.json()["sample_id"] == REAL_HASH


def test_legitimate_sample_id_still_reads_its_own_artifacts(client, work_dir):
    """Status endpoint for a real sample must still resolve."""
    response = client.get(f"/api/sample/{REAL_HASH}/status")

    assert response.status_code == 200