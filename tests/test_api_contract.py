from backend.api_contract import SNAPSHOT, current_schema, render


def test_openapi_matches_committed_snapshot():
    committed = SNAPSHOT.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert committed == render(current_schema()), (
        "API contract changed. If intended, run `python -m backend.api_contract --write` and review the diff."
    )
