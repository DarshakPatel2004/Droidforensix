import json

from analysis.custody import CUSTODY_NAME, GENESIS_HASH, append_event, digest_value, read_entries, verify


def _write_three(sample_dir):
    append_event(sample_dir, "input_received", {"apk_sha256": "a" * 64})
    append_event(sample_dir, "step_succeeded", {"step_number": 2, "output_sha256": "b" * 64})
    append_event(sample_dir, "result_written", {"result_sha256": "c" * 64})


def test_clean_chain_verifies_and_links_entries(tmp_path):
    _write_three(tmp_path)
    result = verify(tmp_path)
    entries = read_entries(tmp_path)

    assert result["valid"] is True
    assert result["entries"] == 3
    assert result["head_hash"] == entries[-1]["hash"]
    assert entries[0]["prev"] == GENESIS_HASH
    assert entries[1]["prev"] == entries[0]["hash"]


def test_edited_entry_breaks_chain_at_that_seq(tmp_path):
    _write_three(tmp_path)
    path = tmp_path / CUSTODY_NAME
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["data"]["output_sha256"] = "f" * 64
    lines[1] = json.dumps(tampered, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify(tmp_path)
    assert result["valid"] is False
    assert result["broken_at"] == 1


def test_truncated_chain_still_verifies_so_head_hash_must_be_anchored(tmp_path):
    _write_three(tmp_path)
    anchored_head = verify(tmp_path)["head_hash"]

    path = tmp_path / CUSTODY_NAME
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    result = verify(tmp_path)
    assert result["valid"] is True
    assert result["head_hash"] != anchored_head


def test_missing_log_is_reported_not_valid(tmp_path):
    result = verify(tmp_path)
    assert result["valid"] is False
    assert result["reason"] == "no custody log"


def test_digest_value_ignores_key_order():
    assert digest_value({"a": 1, "b": [2, 3]}) == digest_value({"b": [2, 3], "a": 1})


def test_custody_endpoint_verifies_and_rejects_bad_ids(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from backend import main
    from backend.config import settings

    monkeypatch.setattr(settings, "WORK_DIR", tmp_path)
    sample_id = "a" * 64
    _write_three(tmp_path / sample_id)
    client = TestClient(main.app)

    body = client.get(f"/api/sample/{sample_id}/custody").json()
    assert body["verification"]["valid"] is True
    assert len(body["entries"]) == 3
    assert client.get("/api/sample/not-a-hash/custody").status_code == 400
    assert client.get(f"/api/sample/{'b' * 64}/custody").status_code == 404
