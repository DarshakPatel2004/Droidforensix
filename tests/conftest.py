"""Shared pytest fixtures.

The autouse ``isolate_work_dir`` fixture is a test-isolation guard, not a
convenience. Without it, any test that calls a step function without passing an
explicit ``work_dir`` writes into the real ``analysis/work/``, which leaves
non-hash directories named after the test's sample_id behind. Those directories
are indistinguishable from real samples to ``/api/samples``, and they are not
gitignored, so they keep reappearing after cleanup.

The fixture redirects WORK_DIR (and UPLOADS_DIR) to a per-test tmp dir. Two
things make that necessary rather than merely tidy:

- ``backend.routers.dissection`` and ``backend.transformers`` bind ``WORK_DIR = settings.WORK_DIR``
  at import time, so patching ``settings`` alone leaves those modules pointing at
  the real directory.
- the analysis step functions read ``settings.WORK_DIR`` at call time.

A test that genuinely needs the real directory opts out with
``@pytest.mark.use_real_work_dir``.
"""

import os

import pytest

os.environ["DROIDFORENSIX_TESTING"] = "1"

# Modules that bind WORK_DIR at import time; patching settings alone is not enough.
_MODULES_BINDING_WORK_DIR = ("backend.routers.dissection", "backend.transformers")


@pytest.fixture(autouse=True)
def isolate_work_dir(request, tmp_path, monkeypatch):
    """Point WORK_DIR and UPLOADS_DIR at a per-test tmp dir.

    Skipped for tests marked ``use_real_work_dir`` (e.g. the end-to-end pipeline
    test, which asserts against the real WORK_DIR).
    """
    if request.node.get_closest_marker("use_real_work_dir"):
        yield
        return

    from backend.config import settings

    work_dir = tmp_path / "work"
    work_dir.mkdir(exist_ok=True)
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)

    monkeypatch.setattr(settings, "WORK_DIR", work_dir)
    monkeypatch.setattr(settings, "UPLOADS_DIR", uploads_dir)

    import importlib

    for name in _MODULES_BINDING_WORK_DIR:
        module = importlib.import_module(name)
        if hasattr(module, "WORK_DIR"):
            monkeypatch.setattr(module, "WORK_DIR", work_dir)

    yield work_dir


# Process-wide caches that are not keyed on WORK_DIR. transformer's caches hold a
# 5s TTL and are keyed on nothing, so a test that reads an empty WORK_DIR poisons
# the next test's view of the corpus - which makes the suite order-dependent.
_CACHES_TO_RESET = (
    ("backend.transformers", "_ALL_RESULTS_CACHE"),
    ("backend.transformers", "_ALL_RESULTS_MTIME"),
    ("backend.transformers", "_FAMILY_INDEX_CACHE"),
    ("backend.transformers", "_FAMILY_INDEX_MTIME"),
    ("backend.dissection", "_DISSECTION_CACHE"),
    ("backend.dissection", "_CLASS_OBJECTS_CACHE"),
)


@pytest.fixture(autouse=True)
def reset_module_caches():
    """Clear backend process-wide caches so tests cannot influence each other."""
    import importlib

    for module_name, attr in _CACHES_TO_RESET:
        module = importlib.import_module(module_name)
        if hasattr(module, attr):
            setattr(module, attr, {} if isinstance(getattr(module, attr), dict) else None)

    yield

    for module_name, attr in _CACHES_TO_RESET:
        module = importlib.import_module(module_name)
        if hasattr(module, attr):
            setattr(module, attr, {} if isinstance(getattr(module, attr), dict) else None)