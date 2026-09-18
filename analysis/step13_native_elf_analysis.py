import logging
import math
import zipfile
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

CRYPTO_SYMBOL_PATTERNS = [
    "AES", "DES", "RSA", "SHA", "MD5", "encrypt", "decrypt",
    "cipher", "EVP_", "AES_encrypt", "MD5_", "SHA256_", "HMAC",
    "EVP_CipherInit", "EVP_EncryptInit", "EVP_DecryptInit",
]

ANTI_ANALYSIS_PATTERNS = [
    "ptrace", "debugger", "debug_begin", "isDebugging",
    "anti_debug", "jdwp", "trace", "strace", "frida",
    "ptrace_disable", "tracerPid",
]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_elf_files(apk_path: str) -> List[Dict[str, Any]]:
    native_libs = []
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".so"):
                    info = zf.getinfo(name)
                    native_libs.append({
                        "path": name,
                        "size": info.file_size,
                        "compress_size": info.compress_size,
                    })
    except Exception:
        pass
    return native_libs


def parse_elf_header(lib_info: Dict[str, Any]) -> Dict[str, Any]:
    if not lib_info:
        return {}
    return {
        "arch": lib_info.get("arch", "unknown"),
        "bits": lib_info.get("bits", 32),
        "endian": lib_info.get("endian", "little"),
        "entry_point": lib_info.get("entry_point", ""),
    }


def detect_elf_obfuscation(sections: Dict[str, Dict]) -> Dict[str, Any]:
    indicators = []
    score = 0.0

    for name, info in sections.items():
        size = info.get("size", 0)
        entropy = info.get("entropy", 0.0)

        if entropy > 7.0:
            indicators.append({
                "type": "high_entropy_section",
                "detail": f"Section '{name}' entropy {entropy:.2f}",
            })
            score += 30

        if name in (".text", ".plt", ".init", ".fini") and size > 100000:
            indicators.append({
                "type": "oversized_code_section",
                "detail": f"Section '{name}' size {size} bytes",
            })
            score += 15

    if len(sections) < 3:
        indicators.append({
            "type": "minimal_sections",
            "detail": f"Only {len(sections)} sections found (expected at least 6 for a normal .so)",
        })
        score += 20

    return {
        "obfuscation_score": min(score, 100),
        "obfuscation_detected": score >= 30,
        "indicators": indicators,
    }


def extract_symbols_from_elf(elf_path: str) -> List[str]:
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
        symbols = []
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if isinstance(section, SymbolTableSection):
                    for sym in section.iter_symbols():
                        if sym.name:
                            symbols.append(sym.name)
        return symbols
    except Exception:
        return []


def match_symbols(symbols: List[str]) -> Dict[str, List[str]]:
    crypto = []
    anti = []
    for sym in symbols:
        for pat in CRYPTO_SYMBOL_PATTERNS:
            if pat.lower() in sym.lower():
                crypto.append(sym)
                break
        for pat in ANTI_ANALYSIS_PATTERNS:
            if pat.lower() in sym.lower():
                anti.append(sym)
                break
    return {"crypto_functions": crypto, "anti_analysis": anti}


def _build_elf_sections(elf_path: str) -> Dict[str, Dict]:
    sections = {}
    try:
        from elftools.elf.elffile import ELFFile
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                name = section.name
                size = section.data_size
                data = section.data()[:4096] if size > 0 else b""
                sections[name] = {
                    "size": size,
                    "entropy": round(shannon_entropy(data), 2),
                }
    except Exception:
        pass
    return sections


def analyze_native_libraries_from_apk(
    apk_path: str,
    extracted_path: Optional[str] = None,
) -> Dict[str, Any]:
    libs = extract_elf_files(apk_path)
    if not libs:
        return {"native_libraries": [], "total_libraries": 0, "has_native_code": False}

    results = []
    for lib in libs:
        lib_result = {
            "path": lib["path"],
            "size": lib["size"],
            "obfuscation": {},
            "symbols": {"total": 0, "crypto_functions": [], "anti_analysis": []},
        }

        elf_full_path = None
        if extracted_path:
            candidate = Path(extracted_path) / lib["path"]
            if candidate.exists():
                elf_full_path = str(candidate)

        if elf_full_path:
            symbols = extract_symbols_from_elf(elf_full_path)
            lib_result["symbols"]["total"] = len(symbols)
            matched = match_symbols(symbols)
            lib_result["symbols"]["crypto_functions"] = matched["crypto_functions"]
            lib_result["symbols"]["anti_analysis"] = matched["anti_analysis"]

            sections = _build_elf_sections(elf_full_path)
            if sections:
                lib_result["obfuscation"] = detect_elf_obfuscation(sections)

        results.append(lib_result)

    return {
        "native_libraries": results,
        "total_libraries": len(results),
        "has_native_code": True,
    }
