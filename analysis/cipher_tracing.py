"""
Cipher.doFinal tracing: recover AES/DES-encrypted strings from smali sources.

Covers the common packer pattern with static pattern-matching only:
  const-string <transformation, e.g. "AES/CBC/PKCS5Padding">
  Cipher.getInstance(...) -> init(DECRYPT_MODE, key, iv) -> doFinal(blob)

Scope cap (deliberate): const-string keys/IVs only. Keys arriving via
method args, reflection, or byte-array construction are counted as
``traced-unsolved`` rather than solved. Full data-flow tracking is
overkill for the packers seen in this corpus.

Output feeds the existing encodings -> payloads -> C2 chain as new
encoding types (``cipher_aes`` / ``cipher_des`` / ``cipher_3des``),
decrypted deterministically by Step 4 via the stored key/IV.
"""

import base64
import binascii
import bisect
import logging
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Patterns and constants
# ---------------------------------------------------------------------------

TRANSFORMATION_RE = re.compile(
    r'"((?:AES|DES|DESede|TripleDES)(?:/[A-Za-z0-9_]+){0,2})"'
)
SMALI_CONST_STRING_RE = re.compile(
    r'const-string(?:/jumbo)?\s+\S+,\s*"((?:[^"\\]|\\.)*)"'
)
JAVA_STRING_RE = re.compile(r'"((?:[^"\\]|\\.){8,})"')
BASE64_SHAPE_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
HEX_SHAPE_RE = re.compile(r'^[0-9A-Fa-f]{32,}$')
URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b'
)
WORD_RE = re.compile(r'[a-z]{4,}')

DOFINAL_MARKER = "Cipher;->doFinal"
GETINSTANCE_SMALI = "Cipher;->getInstance"
GETINSTANCE_JAVA = "Cipher.getInstance"
SECRETKEY_MARKER = "SecretKeySpec"
IV_MARKER = "IvParameterSpec"

AES_KEY_LENS = frozenset({16, 24, 32})
DES_KEY_LENS = frozenset({8})
DES3_KEY_LENS = frozenset({16, 24})
AES_IV_LEN = 16
DES_IV_LEN = 8

# Bounds so a huge APK cannot stall the pipeline step.
MAX_BLOBS_PER_FILE = 20
MAX_KEYS_PER_FILE = 5
MAX_IVS_PER_FILE = 3
MAX_CIPHER_FILES = 200
MAX_DERIVED_KEYS_PER_FILE = 10


# ---------------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------------


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    length = len(data)
    freq: Dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def classify_entropy(entropy: float) -> str:
    """Coarse entropy bucket, mirroring step3/decoding_engine labels."""
    if entropy < 2.5:
        return "very_low"
    if entropy < 4.0:
        return "low"
    if entropy < 5.5:
        return "medium"
    if entropy < 6.5:
        return "high"
    return "very_high"


def parse_transformation(literal: str) -> Tuple[str, str, str]:
    """Split e.g. ``AES/CBC/PKCS5Padding`` into (algorithm, mode, padding)."""
    parts = literal.split("/")
    algorithm = parts[0]
    if algorithm == "TripleDES":
        algorithm = "DESede"
    mode = parts[1].upper() if len(parts) > 1 else ""
    padding = parts[2] if len(parts) > 2 else ""
    return algorithm, mode, padding


def cipher_encoding_type(algorithm: str) -> str:
    """Map JCA algorithm name to the encodings-chain type."""
    if algorithm == "AES":
        return "cipher_aes"
    if algorithm == "DES":
        return "cipher_des"
    return "cipher_3des"


def valid_key_lens(algorithm: str) -> frozenset:
    """Accepted raw key lengths for an algorithm."""
    if algorithm == "AES":
        return AES_KEY_LENS
    if algorithm == "DES":
        return DES_KEY_LENS
    return DES3_KEY_LENS


def pkcs7_unpad(data: bytes, block_size: int) -> Optional[bytes]:
    """Remove PKCS5/7 padding; None when the padding is invalid."""
    if not data or len(data) % block_size != 0:
        return None
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        return None
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return None
    return data[:-pad_len]


def printable_ratio(data: bytes) -> float:
    """Ratio of printable ASCII / whitespace bytes."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)


def looks_decoded(data: bytes) -> Tuple[bool, float]:
    """Gate decrypt candidates: wrong-key/IV output must not pass.

    Wrong-key AES output is uniformly random, so a high printable bar
    already rejects it with overwhelming probability. The subtle case is
    CBC with a wrong IV: only the first block garbles while the tail
    stays readable, so a tail-only word check would accept garbage. The
    first-block run requirement closes that hole: a real plaintext
    starts with readable content (or carries a scheme-URL/IP, which
    implies a clean decrypt on its own).
    """
    if not data:
        return False, 0.0
    ratio = printable_ratio(data)
    if ratio < 0.95:
        return False, round(ratio * 0.5, 4)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False, round(ratio * 0.5, 4)
    if URL_RE.search(text) or IP_RE.search(text):
        return True, 0.95
    if not re.search(r'[a-z]{3,}', text[:16].lower()):
        return False, round(ratio * 0.5, 4)
    if len(WORD_RE.findall(text.lower())) >= 2:
        return True, round(min(0.9, 0.5 + ratio * 0.4), 4)
    return False, round(ratio * 0.5, 4)


def decode_blob_text(blob: str) -> Tuple[Optional[bytes], Optional[str]]:
    """Decode a base64/hex blob literal to bytes.
    
    Tries hex first for strings that match hex pattern, then base64.
    """
    clean = blob.strip().strip('"').strip("'")
    # Try hex first for hex-shaped strings
    if HEX_SHAPE_RE.match(clean):
        try:
            return binascii.unhexlify(clean), "hex"
        except Exception as exc:
            logger.debug("Suppressed error in decode_blob_text: %s", exc)
    try:
        return base64.b64decode(clean, validate=True), "base64"
    except Exception as exc:
        logger.debug("Suppressed error in decode_blob_text: %s", exc)
    try:
        padding = 4 - len(clean) % 4
        padded = clean + ("=" * padding if padding != 4 else "")
        return base64.urlsafe_b64decode(padded), "base64"
    except Exception as exc:
        logger.debug("Suppressed error in decode_blob_text: %s", exc)
    try:
        return binascii.unhexlify(clean), "hex"
    except Exception:
        return None, None


# ---------------------------------------------------------------------------
# Smali / Java scanning
# ---------------------------------------------------------------------------


def _newline_ends(text: str) -> List[int]:
    """Offsets just past each newline, so bisect gives a 1-based line number (L2: no per-match rescans)."""
    return [m.end() for m in re.finditer("\n", text)]


def extract_const_strings(text: str, is_smali: bool) -> List[Tuple[str, int]]:
    """All string literals in a source file with 1-based line numbers."""
    pattern = SMALI_CONST_STRING_RE if is_smali else JAVA_STRING_RE
    found = []
    newline_ends = _newline_ends(text)
    for match in pattern.finditer(text):
        found.append((match.group(1), bisect.bisect_right(newline_ends, match.start()) + 1))
    return found


def find_cipher_files(base_dirs: List[Path]) -> List[Path]:
    """Smali/Java files mentioning Cipher.getInstance (bounded)."""
    hits = []
    for base in base_dirs:
        if not base or not base.is_dir():
            continue
        for ext in ("*.smali", "*.java"):
            for path in base.rglob(ext):
                try:
                    if path.stat().st_size > 2_000_000:
                        continue
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if GETINSTANCE_SMALI in text or GETINSTANCE_JAVA in text:
                    hits.append(path)
                if len(hits) >= MAX_CIPHER_FILES:
                    return hits
    return hits


def key_candidates(
    literals: List[Tuple[str, int]], algorithm: str
) -> List[Tuple[bytes, str, int]]:
    """Const-string literals usable as raw keys for an algorithm.

    Returns (key_bytes, literal, line), raw UTF-8 bytes first, then a
    hex-decoded variant when the literal itself is hex (keys are often
    stored hex-encoded). Capped so decrypt combos stay bounded.
    """
    accepted = valid_key_lens(algorithm)
    out: List[Tuple[bytes, str, int]] = []
    for literal, line in literals:
        raw = literal.encode("utf-8", errors="ignore")
        if len(raw) in accepted:
            out.append((raw, literal, line))
        elif HEX_SHAPE_RE.match(literal):
            try:
                decoded = binascii.unhexlify(literal)
            except Exception as exc:
                logger.warning("Suppressed error in key_candidates: %s", exc)
                continue
            if len(decoded) in accepted:
                out.append((decoded, literal, line))
        if len(out) >= MAX_KEYS_PER_FILE:
            break
    return out


def iv_candidates(literals: List[Tuple[str, int]]) -> List[Tuple[bytes, str, int]]:
    """Const-string literals with a valid IV length (8 or 16 bytes)."""
    out = []
    for literal, line in literals:
        raw = literal.encode("utf-8", errors="ignore")
        if len(raw) in (DES_IV_LEN, AES_IV_LEN):
            out.append((raw, literal, line))
        if len(out) >= MAX_IVS_PER_FILE:
            break
    return out


def blob_candidates(
    literals: List[Tuple[str, int]],
) -> List[Tuple[str, bytes, str, int]]:
    """Base64/hex literals that could be block-cipher ciphertext.

    Ciphertext must span whole blocks, so require a multiple of 8 bytes
    (covers both DES and AES) with a minimum of one AES block.
    
    Exclude literals that are valid hex keys (16/24/32 bytes) to avoid
    treating keys as ciphertext blobs.
    """
    out = []
    for literal, line in literals:
        if len(literal) < 20:
            continue
        if not (BASE64_SHAPE_RE.match(literal) or HEX_SHAPE_RE.match(literal)):
            continue
        blob_bytes, blob_enc = decode_blob_text(literal)
        if not blob_bytes or len(blob_bytes) < 16 or len(blob_bytes) % 8 != 0:
            continue
        # Skip literals that look like hex-encoded keys (16/24/32 bytes when hex-decoded)
        if HEX_SHAPE_RE.match(literal):
            try:
                decoded_len = len(binascii.unhexlify(literal))
                if decoded_len in (16, 24, 32):  # common AES key lengths
                    continue
            except Exception as exc:
                logger.warning("Suppressed error in blob_candidates: %s", exc)
        out.append((literal, blob_bytes, blob_enc or "base64", line))
        if len(out) >= MAX_BLOBS_PER_FILE:
            break
    return out


# One pass over the literal, so an escaped backslash ("\n" in smali) is not re-read as an escape (L6).
SMALI_ESCAPE_RE = re.compile(r'\\(u[0-9a-fA-F]{4}|[\\"nrt])')
_SMALI_SIMPLE_ESCAPES = {"\\": "\\", '"': '"', "n": "\n", "r": "\r", "t": "\t"}
SMALI_INVOKE_RE = re.compile(r"invoke-\S+\s+\{([^}]*)\},\s*(\S+)")
SMALI_METHOD_RE = re.compile(r"^\s*\.method\b.*?\n(.*?)^\s*\.end method", re.MULTILINE | re.DOTALL)

# Callee markers for the transforms the emulator understands.
GETBYTES_MARKERS = ("String;->getBytes",)
B64DECODE_MARKERS = ("Base64;->decode", "Base64;->decodeNoPad")
HEXDECODE_MARKERS = ("decodeHex", "parseHexBinary", "decodeHexString")
TOSTRING_MARKERS = ("StringBuilder;->toString", "StringBuffer;->toString")
APPEND_MARKERS = ("StringBuilder;->append", "StringBuffer;->append")

# Additional decoder markers for runtime hex/base64 decoding (common in packers)
HEX_TO_BYTES_MARKERS = ("hex_to_bytes", "hexToBytes", "decodeHex", "hexStringToBytes", "parseHexString")
B64_TO_BYTES_MARKERS = ("base64_to_bytes", "base64ToBytes", "decodeBase64", "b64decode", "base64Decode")


def smali_unescape(literal: str) -> str:
    """Undo common smali string escapes so emulated keys match runtime."""
    def _unescape(match: "re.Match[str]") -> str:
        body = match.group(1)
        if body[0] == "u":
            return chr(int(body[1:], 16))
        return _SMALI_SIMPLE_ESCAPES[body]

    return SMALI_ESCAPE_RE.sub(_unescape, literal)


def iter_smali_methods(text: str):
    """Method bodies containing SecretKeySpec (slicer only looks at those)."""
    for match in SMALI_METHOD_RE.finditer(text):
        body = match.group(1)
        if SECRETKEY_MARKER in body:
            yield body


# Maximum backward-slice recursion (chains deeper than this are dynamic).
MAX_SLICE_DEPTH = 12


def _skip_line(line: str) -> bool:
    """Labels, directives, comments, and blanks carry no dataflow."""
    return (
        not line
        or line.startswith("#")
        or line.startswith(":")
        or line.startswith(".")
    )


def _dest_write(line: str) -> Optional[str]:
    """Register written by a dest-first instruction, else None.

    Excludes move-result (handled with its invoke) and aput (writes array
    contents, not the register).
    """
    match = re.match(
        r"(?:const\S+|new-\S+|iget\S+|sget\S+|aget\S+|move\S+)\s+(\S+?),?",
        line,
    )
    if match:
        return match.group(1).rstrip(",")
    return None


def _as_bytes(value) -> Optional[bytes]:
    """Normalise a resolved str/bytes value to bytes."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", errors="ignore")


def _b64decode_loose(value: bytes) -> Optional[bytes]:
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        try:
            return base64.b64decode(value + b"=" * ((-len(value)) % 4))
        except Exception as exc:
            logger.debug("Suppressed error in _b64decode_loose: %s", exc)
            return None


def _unhexlify_loose(value: bytes) -> Optional[bytes]:
    try:
        return binascii.unhexlify(value.decode("ascii", errors="strict").strip())
    except Exception as exc:
        logger.debug("Suppressed error in _unhexlify_loose: %s", exc)
        return None


def _resolve_builder(lines, use_idx: int, builder: str, depth: int, seen) -> Optional[str]:
    """StringBuilder contents at use_idx via bounded region scan.

    Finds the nearest `new-instance builder, StringBuilder` above the use,
    seeds from `new StringBuilder("const")` when present, then concatenates
    const/str-known `append` args in order. Any unknown op on the builder
    (or a missing constructor) fails closed to None.
    """
    ctor_idx = None
    seed: Optional[str] = ""
    for j in range(use_idx - 1, -1, -1):
        line = lines[j].strip()
        if _skip_line(line):
            continue
        new_match = re.match(r"new-instance\s+(\S+?),\s*(\S+)", line)
        if new_match and new_match.group(1) == builder:
            if "StringBuilder" not in new_match.group(2):
                return None
            ctor_idx = j
            break
        if _dest_write(line) == builder:
            return None  # builder overwritten by unknown means: unknowable
    if ctor_idx is None:
        return None
    parts = [seed]
    for k in range(ctor_idx + 1, use_idx):
        line = lines[k].strip()
        if _skip_line(line):
            continue
        invoke_match = SMALI_INVOKE_RE.search(line)
        if not invoke_match:
            continue
        regs = [r.strip() for r in invoke_match.group(1).split(",")]
        callee = invoke_match.group(2)
        if not regs or regs[0] != builder:
            continue
        if "StringBuilder;-><init>" in callee and len(regs) == 2:
            seed_value = _resolve_value(lines, k, regs[1], depth + 1, seen)
            if not isinstance(seed_value, str):
                return None
            parts[0] = seed_value
        elif any(m in callee for m in APPEND_MARKERS) and len(regs) > 1:
            extra = _resolve_value(lines, k, regs[1], depth + 1, seen)
            extra_bytes = _as_bytes(extra)
            if extra_bytes is None:
                return None
            try:
                parts.append(extra_bytes.decode("utf-8"))
            except UnicodeDecodeError:
                return None
    return "".join(parts)


def _resolve_value(lines, use_idx: int, reg: str, depth: int, seen) -> Optional[object]:
    """Backward slice: value of reg at use_idx as str or bytes (None=unknown).

    Walks to the nearest preceding write of reg and resolves it
    recursively. Fail-closed: anything unrecognized returns None, so
    unknown ops never manufacture keys.
    """
    if depth > MAX_SLICE_DEPTH or (reg, use_idx) in seen:
        return None
    seen = seen | {(reg, use_idx)}
    for j in range(use_idx - 1, -1, -1):
        raw = lines[j]
        line = raw.strip()
        if _skip_line(line):
            continue

        const_match = SMALI_CONST_STRING_RE.search(raw)
        if const_match and line.startswith("const-string"):
            if line.split(",", 1)[0].split()[-1] == reg:
                return smali_unescape(const_match.group(1))
            continue

        move_match = re.match(r"move(?:-object|/from16|/16)?\s+(\S+?),\s*(\S+)", line)
        if move_match and move_match.group(1) == reg:
            return _resolve_value(lines, j, move_match.group(2), depth + 1, seen)

        # Static field access: sget-object reg, Lclass;->field:Ltype
        sget_match = re.match(r"sget-object\s+(\S+?),\s*([^:]+):(\S+)", line)
        if sget_match and sget_match.group(1) == reg:
            # Return a special marker indicating this is a static field
            # The field value would need to be resolved from <clinit>
            # For now, we'll try to find the field initialization in the same file
            field_class = sget_match.group(2)
            field_name = sget_match.group(3)
            # Look for the field initialization in <clinit>
            field_value = _find_static_field_init(lines, field_class, field_name)
            if field_value is not None:
                return field_value
            # Unresolved: fail closed. Walking past this write would return an older value (L5).
            return None

        result_match = re.match(r"move-result(?:-object)?\s+(\S+)", line)
        if result_match and result_match.group(1) == reg:
            # The producing invoke is the nearest non-skipped line above.
            k = j - 1
            while k >= 0 and _skip_line(lines[k].strip()):
                k -= 1
            if k < 0:
                return None
            invoke_match = SMALI_INVOKE_RE.search(lines[k])
            if not invoke_match:
                return None
            regs = [r.strip() for r in invoke_match.group(1).split(",")]
            callee = invoke_match.group(2)
            if any(m in callee for m in GETBYTES_MARKERS) and regs:
                return _as_bytes(_resolve_value(lines, k, regs[0], depth + 1, seen))
            if any(m in callee for m in B64DECODE_MARKERS) and regs:
                inner = _resolve_value(lines, k, regs[0], depth + 1, seen)
                return _b64decode_loose(_as_bytes(inner) or b"") if inner is not None else None
            if any(m in callee for m in HEXDECODE_MARKERS) and regs:
                inner = _resolve_value(lines, k, regs[0], depth + 1, seen)
                return _unhexlify_loose(_as_bytes(inner) or b"") if inner is not None else None
            if any(m in callee for m in HEX_TO_BYTES_MARKERS) and regs:
                inner = _resolve_value(lines, k, regs[0], depth + 1, seen)
                return _unhexlify_loose(_as_bytes(inner) or b"") if inner is not None else None
            if any(m in callee for m in B64_TO_BYTES_MARKERS) and regs:
                inner = _resolve_value(lines, k, regs[0], depth + 1, seen)
                return _b64decode_loose(_as_bytes(inner) or b"") if inner is not None else None
            if any(m in callee for m in TOSTRING_MARKERS) and regs:
                return _resolve_builder(lines, k, regs[0], depth + 1, seen)
            return None

        written = _dest_write(line)
        if written == reg:
            return None  # nearest write is opaque (const/field/new-array/...)

    return None


def _find_static_field_init(lines, field_class: str, field_name: str) -> Optional[object]:
    """Find static field initialization in <clinit> method.
    
    Looks for sput-object or sput patterns that initialize the field.
    """
    # Look for <clinit> method
    in_clinit = False
    for j, raw in enumerate(lines):
        line = raw.strip()
        if line.startswith(".method") and "<clinit>" in line:
            in_clinit = True
            continue
        if line.startswith(".method") and in_clinit:
            in_clinit = False
            continue
        if not in_clinit:
            continue
        if _skip_line(line):
            continue
        
        # Look for sput-object field_class, field_name, reg
        sput_match = re.match(r"sput-object\s+(\S+?),\s*([^:]+):(\S+)", line)
        if sput_match and sput_match.group(2) == field_class and sput_match.group(3) == field_name:
            src_reg = sput_match.group(1)
            # Resolve the source register
            return _resolve_value(lines, j, src_reg, 0, frozenset())
        
        # Also check sput (primitives) - less common for keys but possible
        sput_match = re.match(r"sput\s+(\S+?),\s*([^:]+):(\S+)", line)
        if sput_match and sput_match.group(2) == field_class and sput_match.group(3) == field_name:
            src_reg = sput_match.group(1)
            return _resolve_value(lines, j, src_reg, 0, frozenset())
    
    return None


def emulate_key_chain(body: str) -> List[Tuple[bytes, str]]:
    """Backward-slice const->transform chains feeding SecretKeySpec.

    For each SecretKeySpec.<init> site, resolves the key register (2nd reg,
    first is `this`) backward through const-string, moves, getBytes,
    Base64/hex decoders, and StringBuilder chains. Returns (key_bytes,
    chain_desc). Fail-closed: unresolvable keys yield nothing.
    """
    # Join invoke targets split across lines: "},\n    Ljavax/..." -> "}, Ljavax/..."
    body = re.sub(r"\},\s*\n\s*(L)", r"}, \1", body)
    lines = body.splitlines()
    derived: List[Tuple[bytes, str]] = []
    for idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        if SECRETKEY_MARKER not in line or "-><init>" not in line:
            continue
        invoke_match = SMALI_INVOKE_RE.search(line)
        if not invoke_match:
            continue
        regs = [r.strip() for r in invoke_match.group(1).split(",")]
        if len(regs) < 2:
            continue
        key_bytes = _as_bytes(_resolve_value(lines, idx, regs[1], 0, frozenset()))
        if key_bytes:
            derived.append((key_bytes, "slice"))
    return derived


def derived_key_candidates(text: str, algorithm: str) -> List[Tuple[bytes, str, int]]:
    """Emulated transform-chain keys (smali only), capped per file."""
    accepted = valid_key_lens(algorithm)
    out: List[Tuple[bytes, str, int]] = []
    seen = set()
    for body in iter_smali_methods(text):
        for key_bytes, _ in emulate_key_chain(body):
            if len(key_bytes) not in accepted or key_bytes in seen:
                continue
            seen.add(key_bytes)
            out.append((key_bytes, "<derived>", 0))
            if len(out) >= MAX_DERIVED_KEYS_PER_FILE:
                return out
    return out


def try_decrypt(
    blob_bytes: bytes,
    key_bytes: bytes,
    iv_bytes: Optional[bytes],
    algorithm: str,
    mode: str,
    padding: str,
) -> Optional[bytes]:
    """Single AES/DES decrypt attempt; None on any failure."""
    try:
        from Crypto.Cipher import AES, DES, DES3
    except ImportError:
        return None
    try:
        if algorithm == "AES":
            block = 16
            if len(key_bytes) not in AES_KEY_LENS:
                return None
            if mode == "ECB" or not mode:
                cipher = AES.new(key_bytes, AES.MODE_ECB)
            elif mode == "CBC":
                if iv_bytes is None or len(iv_bytes) != AES_IV_LEN:
                    return None
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            elif mode == "CTR":
                if iv_bytes is None or len(iv_bytes) != AES_IV_LEN:
                    return None
                cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=iv_bytes[:8], initial_value=int.from_bytes(iv_bytes[8:], 'big'))
            else:
                return None
        elif algorithm == "DES":
            block = 8
            if len(key_bytes) not in DES_KEY_LENS:
                return None
            if mode == "ECB" or not mode:
                cipher = DES.new(key_bytes, DES.MODE_ECB)
            elif mode == "CBC":
                if iv_bytes is None or len(iv_bytes) != DES_IV_LEN:
                    return None
                cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)
            else:
                return None
        else:  # DESede
            block = 8
            if len(key_bytes) not in DES3_KEY_LENS:
                return None
            if mode == "ECB" or not mode:
                cipher = DES3.new(key_bytes, DES3.MODE_ECB)
            elif mode == "CBC":
                if iv_bytes is None or len(iv_bytes) != DES_IV_LEN:
                    return None
                cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv_bytes)
            else:
                return None
        if len(blob_bytes) % block != 0:
            return None
        plain = cipher.decrypt(blob_bytes)
        if "NoPadding" in padding or mode == "CTR":
            # CTR mode and NoPadding: return raw decrypted bytes (stream cipher)
            return plain if plain else None
        return pkcs7_unpad(plain, block)
    except Exception as exc:
        logger.debug("Suppressed error in try_decrypt: %s", exc)
        return None


def marker_lines(text: str, marker: str) -> List[int]:
    """1-based line numbers where a smali/Java marker occurs."""
    newline_ends = _newline_ends(text)
    return [
        bisect.bisect_right(newline_ends, match.start()) + 1
        for match in re.finditer(re.escape(marker), text)
    ]


def order_by_proximity(
    candidates: List[Tuple[bytes, str, int]], targets: List[int]
) -> List[Tuple[bytes, str, int]]:
    """Nearest-to-constructor first (key near SecretKeySpec, IV near IvParameterSpec).

    The literal consumed by a crypto constructor sits lines away from it;
    unrelated same-length constants sit farther. Ordering by distance makes
    the correct key/IV tried first so a first-hit loop reports the true
    decrypt rather than a coincidental partial pass.
    """
    if not targets:
        return candidates

    def distance(candidate: Tuple[bytes, str, int]) -> int:
        return min(abs(candidate[2] - line) for line in targets)

    return sorted(candidates, key=distance)


def solve_file(
    text: str, file_label: str, is_smali: bool
) -> Tuple[List[Dict[str, Any]], bool, bool]:
    """Attempt decrypts for one source file.

    Returns (solved_encoding_dicts, has_dofinal, has_const_key).
    Dicts carry no encoding_id; the pipeline assigns those so ids stay
    contiguous with the Step 3 sequence.
    """
    has_dofinal = DOFINAL_MARKER in text or "doFinal" in text
    transformations = sorted(set(TRANSFORMATION_RE.findall(text)))
    if not transformations:
        # getInstance with a non-literal transformation: traceable but the
        # algorithm is unknown, so nothing to attempt.
        return [], has_dofinal, False

    literals = extract_const_strings(text, is_smali)
    secret_lines = marker_lines(text, SECRETKEY_MARKER)
    iv_lines = marker_lines(text, IV_MARKER)
    solved: List[Dict[str, Any]] = []
    seen_blobs = set()
    found_key = False

    for transformation in transformations:
        algorithm, mode, padding = parse_transformation(transformation)
        if algorithm not in ("AES", "DES", "DESede"):
            continue
        keys = order_by_proximity(key_candidates(literals, algorithm), secret_lines)
        if keys:
            found_key = True
        if is_smali:
            # Transform-slicer chains (const -> getBytes/Base64/concat).
            # Tried after bare consts; gated by looks_decoded like all keys.
            derived = derived_key_candidates(text, algorithm)
            if derived:
                found_key = True
                have = {k for k, _, _ in keys}
                keys.extend(entry for entry in derived if entry[0] not in have)
        ivs = order_by_proximity(iv_candidates(literals), iv_lines)
        blobs = blob_candidates(literals)
        if not keys or not blobs:
            continue

        iv_options: List[Optional[bytes]] = [None]
        iv_label: Dict[int, Optional[str]] = {id(None): None}
        if mode == "CBC":
            iv_options = []
            iv_label = {}
            for iv_bytes, _, _ in ivs:
                if (algorithm == "AES" and len(iv_bytes) == AES_IV_LEN) or (
                    algorithm != "AES" and len(iv_bytes) == DES_IV_LEN
                ):
                    iv_options.append(iv_bytes)
                    iv_label[id(iv_bytes)] = base64.b64encode(iv_bytes).decode()
            # Lazy packers reuse a zero IV; cheap to try, gated by looks_decoded.
            zero_iv = bytes(16 if algorithm == "AES" else 8)
            iv_options.append(zero_iv)
            iv_label[id(zero_iv)] = base64.b64encode(zero_iv).decode()  # M3: replay needs a real IV

        # Handle CTR mode IV options (similar to CBC)
        if mode == "CTR":
            ctr_iv_options = []
            ctr_iv_label = {}
            for iv_bytes, _, _ in ivs:
                if algorithm == "AES" and len(iv_bytes) == AES_IV_LEN:
                    ctr_iv_options.append(iv_bytes)
                    ctr_iv_label[id(iv_bytes)] = base64.b64encode(iv_bytes).decode()
            # Zero IV fallback for CTR
            zero_iv = bytes(16)
            ctr_iv_options.append(zero_iv)
            ctr_iv_label[id(zero_iv)] = base64.b64encode(zero_iv).decode()  # M3
        else:
            ctr_iv_options = []
            ctr_iv_label = {}

        modes_to_try = [mode] if mode in ("ECB", "CBC", "CTR") else ["ECB", "CBC"]
        for blob_literal, blob_bytes, blob_enc, blob_line in blobs:
            if blob_literal in seen_blobs:
                continue
            hit = False
            for try_mode in modes_to_try:
                if try_mode == "ECB":
                    options: List[Optional[bytes]] = [None]
                elif try_mode == "CTR":
                    options = ctr_iv_options if ctr_iv_options else [None]
                else:
                    options = iv_options if mode == "CBC" or not mode else [None]
                # M3: CTR hits carry the CTR IV labels; every other mode uses the CBC/none map
                active_iv_label = ctr_iv_label if try_mode == "CTR" else iv_label
                for key_bytes, _, _ in keys:
                    for iv_bytes in options:
                        plain = try_decrypt(
                            blob_bytes, key_bytes, iv_bytes,
                            algorithm, try_mode, padding,
                        )
                        if plain is None:
                            continue
                        ok, confidence = looks_decoded(plain)
                        if not ok:
                            continue
                        try:
                            preview = plain.decode("utf-8")[:200]
                        except UnicodeDecodeError:
                            continue
                        entropy = shannon_entropy(blob_literal.encode("utf-8"))
                        solved.append(
                            {
                                "type": cipher_encoding_type(algorithm),
                                "original_string": blob_literal,
                                "confidence": round(
                                    min(0.95, confidence + 0.1), 4
                                ),
                                "entropy": round(entropy, 4),
                                "entropy_classification": classify_entropy(entropy),
                                "source_location": f"{file_label}:{blob_line}",
                                "decoded_preview": preview,
                                "validation_status": (
                                    "valid"
                                    if URL_RE.search(preview) or IP_RE.search(preview)
                                    else "uncertain"
                                ),
                                "cipher_transformation": transformation,
                                "cipher_algorithm": algorithm,
                                "cipher_mode": try_mode,
                                "cipher_key_length": len(key_bytes),
                                "cipher_iv_present": iv_bytes is not None
                                and active_iv_label.get(id(iv_bytes)) is not None,
                                "cipher_key_b64": base64.b64encode(key_bytes).decode(),
                                "cipher_iv_b64": active_iv_label.get(id(iv_bytes)),
                                "cipher_blob_encoding": blob_enc,
                            }
                        )
                        seen_blobs.add(blob_literal)
                        hit = True
                        break
                    if hit:
                        break
                if hit:
                    break

    return solved, has_dofinal, found_key


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def resolve_source_dirs(apk_info: Dict[str, Any]) -> List[Path]:
    """Collect smali/Java roots from the shapes Step 1 emits.

    Step 1 stores ``apktool_output_dir`` (whose ``smali*`` subdirs hold the
    code); older callers pass ``extracted_path`` with ``smali``/``sources``
    beneath it. Accept both so the tracer works from either.
    """
    dirs: List[Path] = []
    apktool_dir = apk_info.get("apktool_output_dir")
    if apktool_dir:
        candidate = Path(apktool_dir)
        if candidate.is_dir():
            dirs.append(candidate)
    extracted = apk_info.get("extracted_path") or apk_info.get("work_dir", "")
    if extracted:
        base = Path(extracted)
        for sub in ("smali", "sources"):
            candidate = base / sub
            if candidate.is_dir():
                dirs.append(candidate)
        if not dirs and base.is_dir():
            dirs.append(base)
    seen = set()
    unique = []
    for path in dirs:
        key = str(path.resolve()) if path.exists() else str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def trace_cipher_in_apk(apk_info: Dict[str, Any]) -> Dict[str, Any]:
    """Scan an extracted APK for Cipher.doFinal sites and solve const-key ones.

    Returns ``{total_sites, solved, traced_unsolved, encodings}`` where
    ``traced_unsolved`` counts files with Cipher usage but no recovered
    plaintext (key via args/reflection, byte-array keys, unknown
    transformation, or failed decrypts).
    """
    source_dirs = resolve_source_dirs(apk_info)
    if not source_dirs:
        return {
            "total_sites": 0,
            "solved": 0,
            "traced_unsolved": 0,
            "encodings": [],
        }

    encodings: List[Dict[str, Any]] = []
    total_sites = 0
    unsolved = 0
    for path in find_cipher_files(source_dirs):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        total_sites += 1
        try:
            relative = path.relative_to(source_dirs[0]).as_posix()
        except ValueError:
            relative = path.name
        solved, has_dofinal, _ = solve_file(text, relative, path.suffix == ".smali")
        if solved:
            encodings.extend(solved)
        elif has_dofinal:
            unsolved += 1

    return {
        "total_sites": total_sites,
        "solved": len(encodings),
        "traced_unsolved": unsolved,
        "encodings": encodings,
    }
