"""Upload filename guard tests.

`_resolve_upload_path` is the containment check for client-supplied multipart
filenames. POST /api/upload does not call it: that route always stores the body
at UPLOADS_DIR/<uuid>/file.apk and keeps the client filename only as metadata.
So the guard is exercised directly, and /api/upload is checked for the property
that matters there - a traversal filename writes nothing outside UPLOADS_DIR.
"""
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.config import settings
from backend.main import app
from backend.routers.jobs import _resolve_upload_path


@pytest.mark.parametrize("filename", [None, "", "   "])
def test_empty_filename_rejected(filename):
    # Called directly: multipart clients drop an empty filename, so the field
    # arrives as a plain form value and FastAPI answers 422 before any guard runs.
    with pytest.raises(HTTPException) as exc_info:
        _resolve_upload_path(filename)
    assert exc_info.value.status_code == 400


def test_traversal_filename_rejected_by_guard():
    with pytest.raises(HTTPException) as exc_info:
        _resolve_upload_path("../escape.apk")
    assert exc_info.value.status_code == 400


def test_upload_traversal_filename_writes_nothing_outside_uploads():
    uploads_root = settings.UPLOADS_DIR.resolve()
    # Unique body so the module-level SHA-256 dedup map cannot short-circuit the write.
    body = b"PK\x03\x04" + b"upload-guard-test"
    response = TestClient(app).post(
        "/api/upload", files={"file": ("../escape.apk", body, "application/octet-stream")}
    )

    # Accepted: the filename never touches the filesystem path on this route.
    assert response.status_code == 200
    assert not (uploads_root.parent / "escape.apk").exists()
    written = [p.resolve() for p in uploads_root.parent.rglob("*") if p.is_file()]
    assert all(uploads_root in p.parents for p in written)
    upload_id = response.json()["upload_id"]
    assert (uploads_root / upload_id / "file.apk").read_bytes() == body
