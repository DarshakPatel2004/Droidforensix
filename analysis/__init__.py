import os
from pathlib import Path

# Automatically detect and append local tools in tools/ directory to system PATH on startup
tools_dir = Path(__file__).parent.parent / "tools"
if tools_dir.exists():
    paths_to_add = set()
    for r, d, f in os.walk(str(tools_dir)):
        for file in f:
            if file.lower() in ("java.exe", "apktool.bat", "r2.exe", "rabin2.exe"):
                paths_to_add.add(r)
                
    if paths_to_add:
        # Prepend to PATH so local tools override any system versions
        os.environ["PATH"] = os.pathsep.join(paths_to_add) + os.pathsep + os.environ.get("PATH", "")
