import os
import sys
import zipfile
import urllib.request
import shutil
from pathlib import Path

# Config
TOOLS = {
    "java": {
        "url": "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jre/hotspot/normal/eclipse",
        "filename": "jre17.zip",
        "is_zip": True,
        "dest_folder": "java"
    },
    "apktool": {
        "url": "https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar",
        "filename": "apktool.jar",
        "is_zip": False,
        "dest_folder": "apktool"
    },
    "apktool_bat": {
        "url": "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat",
        "filename": "apktool.bat",
        "is_zip": False,
        "dest_folder": "apktool"
    },
    "radare2": {
        "url": "https://github.com/radareorg/radare2/releases/download/5.9.8/radare2-5.9.8-w64.zip",
        "filename": "radare2-5.9.8-w64.zip",
        "is_zip": True,
        "dest_folder": "radare2"
    }
}

def report_progress(block_num, block_size, total_size):
    read_so_far = block_num * block_size
    if total_size > 0:
        percent = min(100, read_so_far * 100 / total_size)
        sys.stdout.write(f"\r    Downloading... {percent:.1f}%")
    else:
        sys.stdout.write(f"\r    Downloading... {read_so_far / 1024 / 1024:.1f} MB")
    sys.stdout.flush()

def main():
    if os.name != "nt":
        print("[!] Warning: This script is designed for Windows native environment setup.")
        print("[*] Continuing anyway...")

    root_dir = Path(__file__).parent.parent.resolve()
    tools_dir = root_dir / "tools"
    tools_dir.mkdir(exist_ok=True)
    temp_dir = tools_dir / "temp"
    temp_dir.mkdir(exist_ok=True)

    print(f"[*] Tools directory: {tools_dir}")

    for name, info in TOOLS.items():
        print(f"\n[*] Setting up {name}...")
        dest_folder = tools_dir / info["dest_folder"]
        dest_folder.mkdir(exist_ok=True)

        temp_file = temp_dir / info["filename"]

        # 1. Download
        if temp_file.exists():
            print(f"    Found existing temp file: {temp_file.name}, skipping download.")
        else:
            print(f"    Downloading from: {info['url']}")
            try:
                # Use a request headers to avoid blockages
                opener = urllib.request.build_opener()
                opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
                urllib.request.install_opener(opener)
                urllib.request.urlretrieve(info["url"], temp_file, report_progress)
                print("\n    Download complete.")
            except Exception as e:
                print(f"\n    [!] Download failed: {e}")
                continue

        # 2. Extract or copy
        if info["is_zip"]:
            print(f"    Extracting to: {dest_folder}")
            try:
                with zipfile.ZipFile(temp_file, 'r') as zip_ref:
                    zip_ref.extractall(dest_folder)
                print("    Extraction complete.")
            except Exception as e:
                print(f"    [!] Extraction failed: {e}")
        else:
            dest_file = dest_folder / info["filename"]
            print(f"    Copying to: {dest_file}")
            try:
                shutil.copy2(temp_file, dest_file)
                print("    Copy complete.")
            except Exception as e:
                print(f"    [!] Copy failed: {e}")

    # Cleanup temp dir
    print("\n[*] Cleaning up temporary files...")
    shutil.rmtree(temp_dir, ignore_errors=True)

    print("\n[+] Windows binary dependencies setup complete!")
    print("[*] Please restart your python process or CLI to load the new paths automatically.")

if __name__ == "__main__":
    main()
