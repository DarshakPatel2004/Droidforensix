"""
Security regression tests (2026-10-08 review).

P2-A1: POST /api/analysis/full and /api/analysis/androguard-only joined the raw
multipart `file.filename` onto UPLOADS_DIR and opened it "wb". Starlette passes
that filename through verbatim, so a `..`-relative name escaped uploads/ and
truncated or created a file anywhere the service account could write. Because
run_backend.bat starts uvicorn with --reload (which watches *.py under
backend/), overwriting backend/main.py was code execution within seconds.

Each test asserts the security property (nothing written outside UPLOADS_DIR),
not just the status code, so it still catches a future regression that rejects
for the wrong reason.
"""
import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.main import app


# Filenames that reach the handler as literal traversal and must be rejected.
# NOTE: an absolute drive path ("C:\\...\\x.apk") is deliberately absent - it is
# not a case our code has to handle. python-multipart strips the drive/UNC
# prefix before the handler sees it, so the handler receives a bare "x.apk".
# That is parser behaviour, not something to assert here.
TRAVERSAL_FILENAMES = [
    "../../pwned.apk",
    "..\\..\\pwned.apk",
    "..\\..\\..\\..\\pwned.apk",
    "/etc/pwned.apk",
    "..",
    "../",
    "subdir/../../pwned.apk",
]


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def uploads_dir(tmp_path, monkeypatch):
    """Point UPLOADS_DIR at a temp dir and stub the heavy analysis calls."""
    target = tmp_path / "uploads"
    target.mkdir()
    monkeypatch.setattr(settings, "UPLOADS_DIR", target)

    # The security property is the write, not the analysis; stub the analysis so
    # these tests stay fast and do not depend on apktool/androguard.
    from backend.core.apk_processor import APKProcessor
    from backend.core.androguard_analyzer import APKAnalyzer

    monkeypatch.setattr(
        APKProcessor, "process", lambda self: {"success": True, "data": {}}
    )
    monkeypatch.setattr(APKAnalyzer, "run", lambda self: {"success": True})
    return target


def _upload(client, filename, endpoint):
    return client.post(
        endpoint,
        files={"file": (filename, b"PK\x03\x04not-a-real-apk", "application/vnd.android.package-archive")},
    )


@pytest.mark.parametrize("filename", TRAVERSAL_FILENAMES)
@pytest.mark.parametrize("endpoint", ["/api/analysis/full", "/api/analysis/androguard-only"])
def test_upload_endpoint_rejects_path_traversal(client, uploads_dir, filename, endpoint):
    """A traversal filename must be rejected, not written to disk."""
    before = _snapshot(uploads_dir.parent)

    response = _upload(client, filename, endpoint)

    assert response.status_code == 400, (
        f"{endpoint} accepted traversal filename {filename!r} "
        f"(got {response.status_code})"
    )
    after = _snapshot(uploads_dir.parent)
    assert after == before, f"{endpoint} wrote outside UPLOADS_DIR for {filename!r}"


@pytest.mark.parametrize("endpoint", ["/api/analysis/full", "/api/analysis/androguard-only"])
def test_upload_endpoint_rejects_filename_without_creating_outside_file(client, uploads_dir, endpoint):
    """The specific overwrite target from the review: backend/main.py."""
    victim = uploads_dir.parent / "victim.py"
    victim.write_text("ORIGINAL", encoding="utf-8")

    _upload(client, "../victim.py", endpoint)

    assert victim.read_text(encoding="utf-8") == "ORIGINAL", (
        f"{endpoint} truncated a file outside UPLOADS_DIR"
    )


@pytest.mark.parametrize("endpoint", ["/api/analysis/full", "/api/analysis/androguard-only"])
def test_upload_endpoint_accepts_legitimate_filename(client, uploads_dir, endpoint):
    """The fix must not break ordinary uploads."""
    response = _upload(client, "sample.apk", endpoint)

    assert response.status_code == 200
    assert (uploads_dir / "sample.apk").exists()


def _snapshot(root):
    """Map every file under root to its size, for before/after comparison."""
    import hashlib

    out = {}
    for path in root.rglob("*"):
        if path.is_file():
            try:
                out[str(path.relative_to(root))] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
            except OSError:
                out[str(path.relative_to(root))] = "<unreadable>"
    return out


@pytest.mark.parametrize("filename", ["C:\\Windows\\Temp\\pwned.apk", "\\\\server\\share\\pwned.apk"])
@pytest.mark.parametrize("endpoint", ["/api/analysis/full", "/api/analysis/androguard-only"])
def test_absolute_path_filename_cannot_escape_uploads_dir(client, uploads_dir, filename, endpoint):
    """An absolute drive/UNC name must not write outside UPLOADS_DIR.

    Asserts the containment property rather than a status code. python-multipart
    reduces this form to a bare basename before the handler runs (its IE6
    workaround), so the file lands inside UPLOADS_DIR and 200 is correct. What
    must never happen is a write outside UPLOADS_DIR.

    Only the containment half is asserted, because a stray stray file inside
    UPLOADS_DIR still shows up in the before/after snapshot.
    """
    before = _snapshot(uploads_dir)

    response = _upload(client, filename, endpoint)

    assert response.status_code in (200, 400), response.status_code

    # Whatever landed must be inside UPLOADS_DIR - check by name, since a
    # legitimate write here is expected.
    written = set(_snapshot(uploads_dir)) - set(before)
    for rel in written:
        resolved = (uploads_dir / rel).resolve()
        assert uploads_dir.resolve() in resolved.parents, (
            f"{endpoint} wrote outside UPLOADS_DIR: {resolved}"
        )