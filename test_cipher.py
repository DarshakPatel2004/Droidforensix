import sys
sys.path.insert(0, r'D:\DroidForensix')
import os
from analysis.cipher_tracing import find_cipher_files, resolve_source_dirs, solve_file

sha = '00012e8f2e49e601edc786cabab52fa844d50add7d3d09efd7f8b23e6ba42efb'
work_dir = r'D:\DroidForensix\analysis\work'
sample_path = os.path.join(work_dir, sha)
apk_info = {'apk_path': os.path.join(sample_path, 'apktool'), 'extracted_path': sample_path, 'work_dir': sample_path}

dirs = resolve_source_dirs(apk_info)
files = find_cipher_files(dirs)
print(f'Found {len(files)} cipher files')
for f in files:
    text = f.read_text(encoding='utf-8', errors='ignore')
    # Check for transformations
    import re
    TRANSFORMATION_RE = re.compile(r'"((?:AES|DES|DESede|TripleDES)(?:/[A-Za-z0-9_]+){0,2})"')
    transformations = sorted(set(TRANSFORMATION_RE.findall(text)))
    print(f'File: {f.name}')
    print(f'  Transformations: {transformations}')
    
    # Try solving
    solved, has_dofinal, found_key = solve_file(text, f.name, True)
    print(f'  solved: {len(solved)}, has_dofinal: {has_dofinal}, found_key: {found_key}')
    if solved:
        for s in solved:
            print(f'    {s}')
    print()