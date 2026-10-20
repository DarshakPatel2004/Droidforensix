"""Frozen snapshot of the public HTTP contract.

``docs/api/openapi.json`` is the reviewed OpenAPI schema. The test suite compares
the live app against it, so any route, parameter, or response change is a
deliberate diff. After an intended change, regenerate with:

    python -m backend.api_contract --write
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SNAPSHOT = Path(__file__).resolve().parent.parent / "docs" / "api" / "openapi.json"


def current_schema() -> Dict[str, Any]:
    from backend.main import app

    return app.openapi()


def render(schema: Dict[str, Any]) -> str:
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    text = render(current_schema())
    if "--write" in args:
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(text, encoding="utf-8")
        print(f"wrote {SNAPSHOT}")
        return 0
    committed = SNAPSHOT.read_text(encoding="utf-8").replace("\r\n", "\n")
    if committed == text:
        print("API contract matches the snapshot")
        return 0
    print("API contract differs from docs/api/openapi.json; run with --write after review")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
