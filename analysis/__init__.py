import os
from pathlib import Path

# Automatically detect and append local tools in tools/ directory to system PATH on startup.
# The walk is bounded to 3 directory levels (tools/<tool>/<version>/bin), which covers every
# bundled binary, and runs once per process at import (audit A1-48).
tools_dir = Path(__file__).parent.parent / "tools"
_TOOL_BINARIES = ("java.exe", "apktool.bat", "r2.exe", "rabin2.exe")
_MAX_TOOL_DEPTH = 3
if tools_dir.exists():
    paths_to_add = set()
    for r, d, f in os.walk(str(tools_dir)):
        if len(Path(r).relative_to(tools_dir).parts) >= _MAX_TOOL_DEPTH:
            d[:] = []
        for file in f:
            if file.lower() in _TOOL_BINARIES:
                paths_to_add.add(r)

    if paths_to_add:
        # Prepend to PATH so local tools override any system versions
        os.environ["PATH"] = os.pathsep.join(sorted(paths_to_add)) + os.pathsep + os.environ.get("PATH", "")
