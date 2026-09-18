"""ELF binary analysis for Android native libraries (.so files).

Provides full breakdown: headers, sections, symbols, packing detection,
anti-analysis indicators, embedded blobs, suspicious strings, and
string deobfuscation.
"""

import re
import math
import logging
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter

logger = logging.getLogger(__name__)

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.constants import SH_FLAGS
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import Section, SymbolTableSection
    HAS_PYELFFLTOOLS = True
except ImportError:
    HAS_PYELFFLTOOLS = False
    ELFFile = None

SUSPICIOUS_API_PATTERNS = [
    (r'ptrace', 'anti_debug'),
    (r'prctl', 'anti_debug'),
    (r'popen', 'shell_exec'),
    (r'system\s*\(', 'shell_exec'),
    (r'execv[pel]?\s*\(', 'shell_exec'),
    (r'fork\s*\(', 'process_fork'),
    (r'kill\s*\(', 'process_kill'),
    (r'open\s*\(.*\/proc\/self', 'anti_debug'),
    (r'dlopen', 'dynamic_loading'),
    (r'dlsym', 'dynamic_loading'),
    (r'__android_log_print', 'logging'),
    (r'fopen\s*\(.*\/data', 'data_access'),
    (r'mprotect', 'memory_protection'),
    (r'__arm_eabi_', 'arm_eabi'),
]

ANTI_ANALYSIS_STRINGS = [
    'ptrace', 'TracerPid', '/proc/self/status', '/proc/self/maps',
    '/proc/self/cmdline', 'android_server', 'gdb.setup',
    'gdbserver', 'frida', 'frida-server', 'Frida', 'FRIDA',
    'xposed', 'Xposed', 'substrate', 'Substrate',
    'magisk', 'su', 'supersu', '/system/bin/su',
    'busybox', 'superuser.apk', 'com.noshufou.android.su',
    'ro.debuggable', 'ro.secure', 'build.prop',
    '/system/app/Superuser', 'samsung.knox', 'knox',
    'dex2jar', 'apktool', 'jadx', 'jeb',
    'android killer', 'AndroidKiller',
    '/data/local/tmp', 'runtime.exec', 'getprop',
    'reflect', 'Class.newInstance', 'Method.invoke',
    'native_set', 'setNative', 'hook',
    'no_exception', 'FindClass', 'GetFieldID',
    'dvmObject', 'Dalvik', 'art::',
    '__wrap_', '__interceptor_',
    'frida-gadget', 'frida-agent',
    'noox', 'nox', 'nox-adb',
]

ANTI_ANALYSIS_PATTERNS = [
    re.compile(p)
    for p in [
        r'isDebuggerConnected\s*\(',
        r'Debug\s*\.\s*isDebuggerConnected',
        r'android\.os\.Debug',
        r'Process\s*\.\s*myTid\s*\(',
        r'kill\s*\(\s*getpid\s*\(',
        r'Signal\s*\.\s*raise\s*\(',
        r'Runtime\.getRuntime\(\).*exec',
        r'java\.lang\.reflect',
        r'Class\.forName\s*\(',
    ]
]

PACKER_SIGNATURES = [
    (b'UPX!', 'upx', 'UPX packed'),
    (b'UPX0', 'upx_section', 'UPX section'),
    (b'UPX1', 'upx_section', 'UPX section'),
    (b'UPX2', 'upx_section', 'UPX section'),
    (b'llvm-', 'llvm_obfuscator', 'LLVM obfuscation'),
    (b'OLLVM', 'ollvm', 'OLLVM obfuscator'),
    (b'ARMORED', 'armored', 'Armored packer'),
    (b'!<arch>\n', 'ar_archive', 'AR archive'),
    (b'\x7fELF', 'embedded_elf', 'Embedded ELF binary'),
    (b'dex\n', 'embedded_dex', 'Embedded DEX file'),
    (b'\x03\x00\x00\x00\x00\x00\x00\x00', 'embedded_dex_035', 'Embedded DEX 035'),
]

ARCH_NAMES = {
    0x03: 'i386',
    0x28: 'ARM',
    0x29: 'AArch64',
    0x3E: 'x86_64',
    0x02: 'SPARC',
    0x08: 'MIPS',
    0x14: 'PowerPC',
    0x2A: 'Thumb',
    0x32: 'IA-64',
    0xF7: 'AArch64',
}


class ELFBreaker:
    """Break down an ELF .so binary for Android malware analysis."""

    def __init__(self, lib_name: str, content: bytes):
        self.lib_name = lib_name
        self.content = content
        self.elffile = None
        self._parsed = False
        self._parse_error = None

    def analyze(self) -> Dict[str, Any]:
        """Full analysis entry point. Returns structured dict."""
        result: Dict[str, Any] = {
            'name': self.lib_name,
            'size_bytes': len(self.content),
        }

        if not HAS_PYELFFLTOOLS:
            result['error'] = 'pyelftools not installed - falling back to binary scan'
            result['suspicious_strings'] = self._scan_strings()
            result['embedded_blobs'] = self._scan_magic_presence()
            result['deobfuscated_strings'] = self._deobfuscate_strings()
            return result

        if not self._parse():
            result['error'] = self._parse_error or 'Failed to parse ELF'
            result['suspicious_strings'] = self._scan_strings()
            result['embedded_blobs'] = self._scan_magic_presence()
            result['deobfuscated_strings'] = self._deobfuscate_strings()
            return result

        result['header'] = self._extract_header_info()
        result['sections'] = self._extract_sections()
        result['segments'] = self._extract_segments()
        result['symbols'] = self._extract_symbols()
        result['jni_exports'] = self._extract_jni_exports()
        result['init_array'] = self._extract_init_array()
        result['relocations'] = self._extract_relocations()
        result['packing'] = self._detect_packing()
        result['anti_analysis'] = self._detect_anti_analysis()
        result['suspicious_strings'] = self._scan_strings()
        result['suspicious_apis'] = self._find_suspicious_apis()
        result['embedded_blobs'] = self._scan_magic_presence()
        result['deobfuscated_strings'] = self._deobfuscate_strings()
        result['import_summary'] = self._summarize_imports()
        result['risk_score'] = self._compute_risk(result)

        return result

    def _parse(self) -> bool:
        if self._parsed:
            return True
        try:
            import io
            self.elffile = ELFFile(io.BytesIO(self.content))
            self._parsed = True
            return True
        except Exception as e:
            self._parse_error = str(e)
            return False

    def _extract_header_info(self) -> Dict[str, Any]:
        h = self.elffile.header
        ei_class = '64-bit' if h.e_ident.EI_CLASS == 2 else '32-bit'
        ei_data = 'Little' if h.e_ident.EI_DATA == 1 else 'Big'
        arch = ARCH_NAMES.get(h.e_machine, h.e_machine)

        return {
            'class': ei_class,
            'endian': ei_data,
            'arch': arch,
            'entry_point': hex(h.e_entry),
            'osabi': h.e_ident.EI_OSABI,
            'abi_version': h.e_ident.EI_ABIVERSION,
            'type': h.e_type,
            'section_count': h.e_shnum,
            'segment_count': h.e_phnum,
            'is_stripped': h.e_shstrndx == 0,
        }

    def _extract_sections(self) -> List[Dict[str, Any]]:
        sections = []
        try:
            for sec in self.elffile.iter_sections():
                sec_name = sec.name
                sec_size = sec.data_size
                sec_raw = sec.data()
                entropy = self._compute_entropy(sec_raw) if sec_raw else 0.0

                flags = []
                if sec.sh_flags & SH_FLAGS.SHF_WRITE:
                    flags.append('W')
                if sec.sh_flags & SH_FLAGS.SHF_ALLOC:
                    flags.append('A')
                if sec.sh_flags & SH_FLAGS.SHF_EXECINSTR:
                    flags.append('X')

                sections.append({
                    'name': sec_name,
                    'type': sec['sh_type'],
                    'size': sec_size,
                    'entropy': round(entropy, 4),
                    'flags': ''.join(flags),
                    'addr': hex(sec['sh_addr']) if sec['sh_addr'] else None,
                    'offset': hex(sec['sh_offset']),
                })
        except Exception:
            pass
        return sections

    def _extract_segments(self) -> List[Dict[str, Any]]:
        segments = []
        try:
            for seg in self.elffile.iter_segments():
                flags = []
                if seg['p_flags'] & 1:
                    flags.append('X')
                if seg['p_flags'] & 2:
                    flags.append('W')
                if seg['p_flags'] & 4:
                    flags.append('R')

                segments.append({
                    'type': seg['p_type'],
                    'flags': ''.join(flags),
                    'vaddr': hex(seg['p_vaddr']),
                    'filesz': seg['p_filesz'],
                    'memsz': seg['p_memsz'],
                    'offset': hex(seg['p_offset']),
                })
        except Exception:
            pass
        return segments

    def _extract_symbols(self) -> Dict[str, List[str]]:
        imports = []
        exports = []
        try:
            for sec in self.elffile.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        name = sym.name
                        if not name:
                            continue
                        st_type = sym['st_info']['type']
                        st_bind = sym['st_info']['bind']
                        if st_bind in ('STB_GLOBAL', 'STB_WEAK') and st_type == 'STT_FUNC':
                            exports.append(name)
                        elif st_bind == 'STB_LOCAL' and name.startswith('$'):
                            continue
                        elif sym['st_shndx'] == 'SHN_UNDEF':
                            imports.append(name)
        except Exception:
            pass
        return {
            'imports': sorted(set(imports)),
            'exports': sorted(set(exports)),
        }

    def _extract_jni_exports(self) -> List[Dict[str, str]]:
        jnis = []
        try:
            for sec in self.elffile.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        name = sym.name
                        if name.startswith('Java_'):
                            parts = name.split('_')
                            jnis.append({
                                'symbol': name[:120],
                                'class': '_'.join(parts[1:-1]) if len(parts) > 2 else '',
                                'method': parts[-1] if parts else '',
                            })
        except Exception:
            pass
        return jnis

    def _extract_init_array(self) -> Optional[List[str]]:
        try:
            init_data = []
            for sec in self.elffile.iter_sections():
                if isinstance(sec, DynamicSection):
                    for tag in sec.iter_tags():
                        if tag.entry.d_tag in ('DT_INIT',):
                            init_data.append(('init', hex(tag.entry.d_val)))
                        if tag.entry.d_tag in ('DT_INIT_ARRAY',):
                            init_data.append(('init_array', hex(tag.entry.d_val)))
                        if tag.entry.d_tag in ('DT_INIT_ARRAYSZ',):
                            init_data.append(('init_array_size', str(tag.entry.d_val)))
                        if tag.entry.d_tag in ('DT_FINI_ARRAYSZ',):
                            init_data.append(('fini_array_size', str(tag.entry.d_val)))
            return init_data if init_data else None
        except Exception:
            return None

    def _extract_relocations(self) -> Optional[List[Dict[str, Any]]]:
        relocs = []
        try:
            for sec in self.elffile.iter_sections():
                if hasattr(sec, 'iter_relocations'):
                    for rel in sec.iter_relocations():
                        relocs.append({
                            'offset': hex(rel['r_offset']),
                            'type': rel['r_info_type'],
                            'symbol': rel.symbol.name if rel.symbol else '',
                        })
        except Exception:
            pass
        return relocs if relocs else None

    def _detect_packing(self) -> Dict[str, Any]:
        indicators = []
        score = 0
        high_entropy_sections = []

        try:
            for sec in self.elffile.iter_sections():
                name = sec.name
                raw = sec.data()
                if not raw:
                    continue
                entropy = self._compute_entropy(raw)

                if entropy > 7.5:
                    high_entropy_sections.append({'name': name, 'entropy': round(entropy, 2)})
                    indicators.append(f'High entropy section "{name}" ({entropy:.2f})')
                    score += 2

            if high_entropy_sections:
                score += 1

        except Exception:
            pass

        for sig_bytes, sig_name, sig_desc in PACKER_SIGNATURES:
            pos = 0
            count = 0
            while True:
                idx = self.content.find(sig_bytes, pos)
                if idx == -1:
                    break
                pos = idx + 1
                count += 1
            if count > 0:
                indicators.append(f'{sig_desc} ({count} occurrence(s))')
                score += 2

        total_secs = 0
        stripped = False
        try:
            total_secs = self.elffile.header.e_shnum
            stripped = self.elffile.header.e_shstrndx == 0
        except Exception:
            pass

        if stripped and total_secs > 3:
            indicators.append('Section headers stripped (packed/stripped binary)')
            score += 1

        level = 'none'
        if score >= 4:
            level = 'high'
        elif score >= 2:
            level = 'medium'
        elif score > 0:
            level = 'low'

        return {
            'level': level,
            'score': score,
            'indicators': indicators,
            'high_entropy_sections': high_entropy_sections,
        }

    def _detect_anti_analysis(self) -> List[Dict[str, Any]]:
        findings = []
        seen = set()

        content_str = self.content.decode('ascii', errors='ignore')
        content_str_lower = content_str.lower()

        for pattern in ANTI_ANALYSIS_STRINGS:
            p_lower = pattern.lower()
            if p_lower in content_str_lower:
                if p_lower not in seen:
                    seen.add(p_lower)
                    findings.append({
                        'type': 'string',
                        'value': pattern,
                        'count': content_str_lower.count(p_lower),
                    })

        for pattern in ANTI_ANALYSIS_PATTERNS:
            matches = list(pattern.finditer(content_str))
            if matches:
                for m in matches:
                    raw = m.group()[:80]
                    if raw not in seen:
                        seen.add(raw)
                        findings.append({
                            'type': 'pattern',
                            'value': raw,
                            'count': len(matches),
                        })

        return findings

    def _find_suspicious_apis(self) -> List[Dict[str, Any]]:
        findings = []
        symbols = self._extract_symbols()
        all_names = symbols.get('imports', []) + symbols.get('exports', [])

        for name in all_names:
            for pat, cat in SUSPICIOUS_API_PATTERNS:
                if re.search(pat, name, re.I):
                    findings.append({
                        'category': cat,
                        'symbol': name,
                    })
                    break
        return findings

    def _scan_strings(self) -> List[Dict[str, Any]]:
        strings = []
        seen = set()

        raw_strings = re.findall(b'[\x20-\x7e]{4,}', self.content)
        for s in raw_strings:
            try:
                decoded = s.decode('ascii', errors='ignore').strip()
            except Exception:
                continue

            if any(x in decoded for x in [
                'clang version', 'Android (', 'based on', 'GNU C', 'Build ID',
                'LLVM', '.comment', '.debug_', '.note.',
            ]):
                continue

            typ = self._classify_string(decoded)
            if typ:
                key = f'{typ}:{decoded[:60]}'
                if key not in seen:
                    seen.add(key)
                    strings.append({
                        'type': typ,
                        'value': decoded[:120],
                        'source': self.lib_name,
                    })
        strings.sort(key=lambda x: {'url': 0, 'ip_address': 1, 'c2_indicator': 2,
                        'shell_command': 3, 'file_path': 4, 'package_name': 5,
                        'crypto_key': 6, 'sql_query': 7, 'base64': 8,
                        'domain': 9, 'other_suspicious': 10}.get(x['type'], 99))
        return strings

    def _classify_string(self, s: str) -> Optional[str]:
        if re.search(r'https?://[^\s"\'<>]{5,}', s, re.I):
            return 'url'
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s):
            return 'ip_address'
        if re.search(r'\b[a-zA-Z0-9.-]+\.(com|net|org|io|co|cc|info|xyz|top|cn|ru|tk|ml|cf|ga|gq)\b', s, re.I):
            if not re.search(r'(example|sample|test|localhost)\.', s, re.I):
                return 'domain'
        if any(x in s.lower() for x in ['c2', 'c&c', 'command', 'panel', 'gate', 'payload', 'bot', 'backconnect',
                                           'shell', 'exploit', 'dropper', 'cnc', 'server']):
            return 'c2_indicator'
        if re.search(r'\b(bash|sh|cmd|powershell|curl|wget|chmod|chown|rm\s+-rf|rmdir|mkfifo|nc\s+-e)\b', s, re.I):
            return 'shell_command'
        if re.search(r'^/data/|^/system/|^/sdcard/|^/mnt/|^/proc/', s):
            return 'file_path'
        if re.search(r'com\.[a-zA-Z][a-zA-Z0-9_.]{4,}', s):
            return 'package_name'
        if re.search(r'\b[A-Za-z0-9+/=]{40,}\b', s):
            return 'base64'
        if re.search(r'\b(select|insert|update|delete|drop)\b.*\b(from|into|set|where|table)\b', s, re.I):
            return 'sql_query'
        if re.search(r'\b[A-Fa-f0-9]{32}\b', s):
            return 'crypto_key'
        if re.search(r'(AES|RSA|DES|RC4|MD5|SHA|Blowfish|Twofish|private.key|public.key|cert)', s, re.I):
            if not re.search(r'(AARCH64|ARM)', s, re.I):
                return 'crypto_key'
        if re.search(r'(password|secret|token|apikey|api_key|apisecret|jwt|auth)', s, re.I):
            return 'other_suspicious'
        return None

    def _deobfuscate_strings(self) -> List[Dict[str, Any]]:
        """Try to deobfuscate hidden strings in the binary.

        Techniques attempted:
          1. Single-byte XOR brute-force on high-entropy byte runs
          2. Multi-byte XOR with keys found in the binary
          3. SUB/ADD cipher (byte - key) & 0xFF on small shifts
          4. ROT47 on printable strings
        """
        results = []
        seen_deob = set()

        candidates = self._find_obfuscated_arrays()[:50]

        for offset, data in candidates:
            for key in range(1, 256):
                decoded = bytes(b ^ key for b in data)
                score = self._score_readable(decoded)
                if score >= 0.6 and len(decoded) >= 8:
                    clean = self._extract_clean_text(decoded)
                    if not clean or len(clean) < 5:
                        continue
                    dedup_key = f'xor_single_0x{key:02x}:{clean[:40]}'
                    if dedup_key not in seen_deob:
                        seen_deob.add(dedup_key)
                        results.append({
                            'technique': 'xor_single',
                            'key': hex(key),
                            'key_value': key,
                            'original_offset': offset,
                            'original_size': len(data),
                            'decoded': clean[:200],
                            'decoded_length': len(clean),
                            'score': round(score, 3),
                        })

        extracted_keys = self._extract_xor_keys()[:10]
        for offset, data in candidates:
            for key_bytes in extracted_keys:
                if not key_bytes:
                    continue
                decoded = bytes(
                    data[i] ^ key_bytes[i % len(key_bytes)]
                    for i in range(len(data))
                )
                score = self._score_readable(decoded)
                if score >= 0.6 and len(decoded) >= 10:
                    clean = self._extract_clean_text(decoded)
                    if len(clean) < 6:
                        continue
                    key_repr = ':'.join(f'{b:02x}' for b in key_bytes[:8])
                    dedup_key = f'xor_multi_{key_repr}:{clean[:40]}'
                    if dedup_key not in seen_deob:
                        seen_deob.add(dedup_key)
                        results.append({
                            'technique': 'xor_multi',
                            'key': key_repr + ('...' if len(key_bytes) > 8 else ''),
                            'key_length': len(key_bytes),
                            'original_offset': offset,
                            'original_size': len(data),
                            'decoded': clean[:200],
                            'decoded_length': len(clean),
                            'score': round(score, 3),
                        })

        for offset, data in candidates:
            for key in range(1, 33):
                for op_name, op_func in [('sub', lambda b, k: (b - k) & 0xFF),
                                          ('add', lambda b, k: (b + k) & 0xFF)]:
                    decoded = bytes(op_func(b, key) for b in data)
                    score = self._score_readable(decoded)
                    if score >= 0.6 and len(decoded) >= 8:
                        clean = self._extract_clean_text(decoded)
                        if not clean or len(clean) < 5:
                            continue
                        dedup_key = f'{op_name}_{key}:{clean[:40]}'
                        if dedup_key not in seen_deob:
                            seen_deob.add(dedup_key)
                            results.append({
                                'technique': f'{op_name}_cipher',
                                'key': hex(key),
                                'key_value': key,
                                'original_offset': offset,
                                'original_size': len(data),
                                'decoded': clean[:200],
                                'decoded_length': len(clean),
                                'score': round(score, 3),
                            })

        raw_strings = re.findall(b'[\x21-\x7e]{6,}', self.content)
        for s in raw_strings:
            if len(s) < 6 or len(s) > 200:
                continue
            decoded = self._try_rot47(s.decode('ascii', errors='ignore'))
            if decoded and len(decoded) >= 6:
                score = self._score_readable(decoded.encode('ascii', errors='ignore'))
                if score >= 0.6:
                    typ = self._classify_string(decoded)
                    dedup_key = f'rot47:{decoded[:40]}'
                    if dedup_key not in seen_deob:
                        seen_deob.add(dedup_key)
                        results.append({
                            'technique': 'rot47',
                            'original_value': s.decode('ascii', errors='ignore')[:80],
                            'decoded': decoded[:200],
                            'decoded_type': typ or 'unknown',
                            'score': round(score, 3),
                        })

        results.sort(key=lambda x: (x.get('score', 0) + x.get('decoded_length', 0) / 100), reverse=True)
        return results[:30]

    def _find_obfuscated_arrays(self) -> List[Tuple[int, bytes]]:
        """Find contiguous byte arrays that look obfuscated/encrypted.

        Returns list of (file_offset, data_bytes).
        """
        candidates: List[Tuple[int, bytes]] = []

        if HAS_PYELFFLTOOLS and self.elffile:
            try:
                for sec in self.elffile.iter_sections():
                    raw = sec.data()
                    if not raw or len(raw) < 8:
                        continue
                    ent = self._compute_entropy(raw)
                    if ent > 5.5:
                        step = max(len(raw) // 20, 16)
                        for i in range(0, len(raw), step):
                            chunk = raw[i:i + step]
                            if len(chunk) < 8:
                                continue
                            c_ent = self._compute_entropy(chunk)
                            ascii_ratio = sum(1 for b in chunk if 0x20 <= b <= 0x7e) / len(chunk)
                            if c_ent > 4.5 and ascii_ratio < 0.3:
                                sec_offset = getattr(sec, 'header', None)
                                if sec_offset is not None:
                                    base = getattr(sec_offset, 'sh_offset', 0)
                                else:
                                    base = 0
                                candidates.append((int(base) + i, chunk))
            except Exception:
                pass

        for win_size in (24, 32, 48):
            step = max(win_size * 2, 128)
            for i in range(0, len(self.content) - win_size, step):
                chunk = self.content[i:i + win_size]
                ascii_ratio = sum(1 for b in chunk if 0x20 <= b <= 0x7e) / len(chunk)
                null_ratio = sum(1 for b in chunk if b == 0) / len(chunk)
                if ascii_ratio < 0.3 and null_ratio < 0.4:
                    ent = self._compute_entropy(chunk)
                    if 3.5 <= ent <= 7.8:
                        candidates.append((i, chunk))

        # Limit candidates to avoid excessive deobfuscation time
        return candidates[:100]

    _ENGLISH_DIGRAPHS = {
        'th', 'he', 'in', 'er', 'an', 're', 'nd', 'on', 'en', 'at',
        'ou', 'ed', 'ha', 'to', 'or', 'it', 'is', 'hi', 'ea', 'ti',
        'es', 'ng', 'st', 'nt', 'ar', 'le', 've', 'as', 'de', 'ra',
        'se', 'me', 'ne', 'ec', 'te', 'll', 'ch', 'al', 'io', 'rt',
    }
    _RARE_DIGRAPHS = {
        'aa', 'uu', 'vv', 'xx', 'zz', 'qq', 'jj', 'kk', 'yy',
        'bq', 'cq', 'dx', 'fb', 'fc', 'fd', 'ff', 'fg', 'fh',
        'gq', 'gx', 'hx', 'hq', 'jf', 'jg', 'jh', 'jj', 'jk',
        'kq', 'kx', 'mx', 'px', 'qb', 'qc', 'qd', 'qf', 'qg',
        'qh', 'qj', 'qk', 'ql', 'qm', 'qn', 'qo', 'qp', 'qq',
        'qr', 'qs', 'qt', 'qv', 'qw', 'qx', 'qy', 'qz', 'rx',
        'sz', 'tx', 'ux', 'vb', 'vc', 'vd', 'vf', 'vg', 'vh',
        'vj', 'vk', 'vl', 'vm', 'vn', 'vp', 'vq', 'vr', 'vs',
        'vt', 'vv', 'vw', 'vx', 'vy', 'vz', 'wx', 'xj', 'xk',
        'xx', 'xz', 'zj', 'zq', 'zx', 'zz',
    }
    _ENGLISH_FREQ = {
        'a': 8.17, 'b': 1.49, 'c': 2.78, 'd': 4.25, 'e': 12.70,
        'f': 2.23, 'g': 2.02, 'h': 6.09, 'i': 6.97, 'j': 0.15,
        'k': 0.77, 'l': 4.03, 'm': 2.41, 'n': 6.75, 'o': 7.51,
        'p': 1.93, 'q': 0.10, 'r': 5.99, 's': 6.33, 't': 9.06,
        'u': 2.76, 'v': 0.98, 'w': 2.36, 'x': 0.15, 'y': 1.97, 'z': 0.07,
    }
    _VOWELS = set('aeiouAEIOU')

    _MINI_DICT = frozenset({
        'the', 'and', 'for', 'are', 'not', 'you', 'all', 'any', 'can', 'had',
        'her', 'was', 'one', 'our', 'out', 'get', 'has', 'him', 'his',
        'how', 'its', 'may', 'new', 'now', 'old', 'see', 'way', 'who',
        'use', 'app', 'key', 'set', 'put', 'add', 'del',
        'run', 'log', 'msg', 'url', 'cmd', 'src', 'ref', 'bin', 'lib', 'tmp',
        'var', 'etc', 'dev', 'usr', 'www', 'net', 'com', 'org',
        'api', 'uid', 'gid', 'int', 'str', 'len', 'end',
        'init', 'exec', 'call', 'bind', 'read', 'write', 'open', 'close',
        'send', 'recv', 'sleep', 'wait', 'lock', 'free', 'alloc',
        'class', 'const', 'enum', 'char', 'byte', 'long', 'void',
        'catch', 'throw', 'this', 'http', 'https', 'file', 'text',
        'init', 'load', 'save', 'edit', 'find', 'view', 'help',
        'custom', 'config', 'create', 'delete', 'update', 'insert',
        'result', 'error', 'success', 'timeout', 'attempt',
        'malware', 'trojan', 'virus', 'payload', 'exploit',
        'admin', 'login', 'password', 'token', 'secret',
        'aes', 'des', 'rsa', 'md5', 'sha1', 'sha256', 'hash',
        'thread', 'process', 'object', 'method', 'function',
        'check', 'verify', 'allow', 'block', 'grant', 'deny',
        'request', 'response', 'message', 'command',
        'format', 'parse', 'convert', 'cache', 'memory',
        'debug', 'trace', 'monitor', 'backup',
        'address', 'port', 'host', 'proxy', 'route', 'gateway',
        'google', 'cloud', 'server', 'client', 'socket',
        'version', 'release', 'build', 'binary', 'source',
        'native', 'shared', 'module', 'package', 'archive',
        'upload', 'download', 'install', 'extract',
        'network', 'device', 'system', 'driver', 'kernel',
        'inject', 'hook', 'proxy', 'shell', 'exec',
        'android', 'java', 'string', 'intent', 'service',
        'receiver', 'activity', 'manager', 'provider', 'content',
        'handle', 'receive', 'process', 'dispatch', 'forward',
        'register', 'notify', 'subscribe', 'publish',
        'broadcast', 'notification', 'alarm', 'schedule',
        'connect', 'listen', 'accept', 'request', 'respond',
    })

    @staticmethod
    def _score_readable(data: bytes) -> float:
        if not data or len(data) < 4:
            return 0.0

        printable = sum(1 for b in data if 0x20 <= b <= 0x7e)
        if printable / len(data) < 0.85:
            return 0.0

        text = data.decode('ascii', errors='replace')
        lower = text.lower()

        has_url = bool(re.search(r'https?://', text, re.IGNORECASE))
        has_ip = bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text))
        has_domain = bool(re.search(r'(?:[a-zA-Z]\w*\.){2,}[a-zA-Z]{2,}', text))

        alpha_chars = sum(1 for c in text if c.isalpha())
        digit_chars = sum(1 for c in text if c.isdigit())

        if has_url:
            return 0.85
        if has_ip:
            return 0.80
        if has_domain and digit_chars > 0:
            return 0.75

        if alpha_chars == 0:
            return 0.0

        tokens = re.findall(r'[a-zA-Z]{3,}', text)
        if not tokens:
            return 0.0

        max_tok = max(len(t) for t in tokens)
        if max_tok < 5:
            return 0.0

        total_alpha = sum(len(t) for t in tokens)
        total_vowels = sum(sum(1 for c in t if c in ELFBreaker._VOWELS) for t in tokens)
        vowel_ratio = total_vowels / total_alpha if total_alpha > 0 else 0

        if vowel_ratio < 0.12 or vowel_ratio > 0.55:
            return 0.0

        common_dg = 0
        rare_dg = 0
        total_dg = 0
        for i in range(len(lower) - 1):
            dg = lower[i:i+2]
            if dg.isalpha():
                total_dg += 1
                if dg in ELFBreaker._ENGLISH_DIGRAPHS:
                    common_dg += 1
                elif dg in ELFBreaker._RARE_DIGRAPHS:
                    rare_dg += 1

        common_dg_ratio = common_dg / total_dg if total_dg > 0 else 0
        rare_dg_ratio = rare_dg / total_dg if total_dg > 0 else 0

        if rare_dg_ratio > 0.25:
            return 0.0

        has_camel = bool(re.search(r'[a-z]+[A-Z][a-z]+', text))
        has_path = bool(re.search(r'^/[\w/.\-~]{2,}|^[a-zA-Z]:[/\\]', text))

        if common_dg_ratio < 0.15 and not has_camel and not has_path:
            return 0.0

        dict_hits = 0
        for t in tokens:
            if len(t) >= 3:
                tl = t.lower()
                if tl in ELFBreaker._MINI_DICT or (len(tl) >= 6 and tl[-3:] in {'ing', 'ion', 'ate', 'ive', 'ble', 'ted', 'ted', 'ter', 'tor', 'ser'}):
                    dict_hits += 1

        has_dict_word = dict_hits >= 2

        if not has_camel and not has_path:
            if not has_dict_word:
                return 0.0

        chi2 = 0
        if total_alpha > 0:
            letter_counts = {}
            for c in lower:
                if c in ELFBreaker._ENGLISH_FREQ:
                    letter_counts[c] = letter_counts.get(c, 0) + 1
            for letter, expected_pct in ELFBreaker._ENGLISH_FREQ.items():
                observed = letter_counts.get(letter, 0) / total_alpha * 100
                chi2 += (observed - expected_pct) ** 2 / expected_pct

        score = (
            common_dg_ratio * 0.35 +
            (1.0 - min(abs(vowel_ratio - 0.35) * 5, 1.0)) * 0.25 +
            (1.0 - min(rare_dg_ratio * 10, 1.0)) * 0.10 +
            (1.0 - min(chi2 / 600, 1.0)) * 0.15 +
            min(dict_hits * 0.20, 0.6) * 0.15
        )

        if has_path:
            score += 0.10
        if has_camel:
            score += 0.08

        return max(0.0, min(score, 1.0))

    @staticmethod
    def _extract_clean_text(data: bytes) -> str:
        """Extract the longest printable ASCII substring from decoded data."""
        best = ''
        current = ''
        for byte in data:
            if 0x20 <= byte <= 0x7e:
                current += chr(byte)
            else:
                if len(current) > len(best):
                    best = current
                current = ''
        if len(current) > len(best):
            best = current
        return best

    def _extract_xor_keys(self) -> List[bytes]:
        """Extract potential XOR keys from the binary itself."""
        keys = []

        for common_key in [
            b'secret', b'key', b'KEY', b'enc', b'ENC', b'xor', b'XOR',
            b'encrypt', b'decrypt', b'decode', b'magic', b'crypt',
            b'key_str', b'k', b'K',
        ]:
            keys.append(common_key)

        if HAS_PYELFFLTOOLS and self.elffile:
            try:
                for sec in self.elffile.iter_sections():
                    raw = sec.data()
                    if not raw:
                        continue
                    for m in re.finditer(b'[\x21-\x7e]{2,16}', raw):
                        k = m.group()
                        if k.lower() not in (b'secret', b'key', b'xor', b'enc') and len(k) >= 2:
                            keys.append(k)
            except Exception:
                pass

        seen = set()
        unique = []
        for k in keys:
            if k not in seen:
                seen.add(k)
                unique.append(k)
        unique.sort(key=len, reverse=True)
        return unique[:20]

    @staticmethod
    def _try_rot47(s: str) -> Optional[str]:
        """Try ROT47 decode on a string."""
        if not s:
            return None
        result = []
        for c in s:
            o = ord(c)
            if 33 <= o <= 126:
                result.append(chr(33 + ((o - 33 + 47) % 94)))
            else:
                result.append(c)
        decoded = ''.join(result)
        return decoded if decoded != s else None

    def _scan_magic_presence(self) -> List[Dict[str, Any]]:
        blobs = []
        for sig_bytes, sig_name, _ in PACKER_SIGNATURES:
            pos = 0
            while True:
                idx = self.content.find(sig_bytes, pos)
                if idx == -1:
                    break
                blobs.append({
                    'type': sig_name,
                    'offset': idx,
                    'context': self.content[max(0, idx-4):idx+20].hex()[:60],
                })
                pos = idx + 1
        blobs.sort(key=lambda x: x['offset'])
        return blobs[:30]

    def _summarize_imports(self) -> Dict[str, List[str]]:
        libs = set()
        api_map: Dict[str, List[str]] = {}
        try:
            for sec in self.elffile.iter_sections():
                if isinstance(sec, DynamicSection):
                    for tag in sec.iter_tags():
                        if tag.entry.d_tag == 'DT_NEEDED':
                            libs.add(tag.needed)
        except Exception:
            pass

        imports = self._extract_symbols().get('imports', [])
        for name in imports:
            cat = 'unknown'
            if name.startswith('Java_'):
                cat = 'jni'
            elif name.startswith(('JNI_', 'JSC_', 'JS_', 'RegisterNatives')):
                cat = 'jni'
            elif name.startswith('_Z'):
                cat = 'cpp_runtime'
                name = name[:60]
            elif name.startswith(('AES_', 'EVP_', 'RSA_', 'SHA', 'MD5', 'HMAC', 'BN_', 'BIO_', 'SSL_')):
                cat = 'crypto'
            elif name.startswith(('socket', 'connect', 'send', 'recv', 'gethostbyname', 'inet_', 'htons', 'ntohs')):
                cat = 'network'
            elif name.startswith(('fopen', 'fwrite', 'fread', 'open', 'read', 'write', 'mmap', 'stat', 'lseek')):
                cat = 'file_io'
            elif name.startswith(('dlopen', 'dlsym', 'dlclose', 'dlerror')):
                cat = 'dynamic_loader'
            elif name.startswith(('pthread', 'mutex', 'cond_')):
                cat = 'threading'
            elif name.startswith(('JNI', 'NewString', 'GetString', 'FindClass', 'GetMethodID', 'GetFieldID')):
                cat = 'jni_bridge'
            api_map.setdefault(cat, []).append(name[:60])
        return {
            'libraries': sorted(libs),
            'api_breakdown': {k: len(v) for k, v in api_map.items()},
            'notable_apis': {k: v[:10] for k, v in api_map.items() if v},
        }

    def _compute_risk(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        score = 0
        factors = []

        jni_count = len(analysis.get('jni_exports', []))
        if jni_count > 0:
            score += min(jni_count, 5)
            factors.append(f'{jni_count} JNI exports')

        packing = analysis.get('packing', {})
        if packing.get('level') == 'high':
            score += 5
            factors.append('High packing indicators')
        elif packing.get('level') == 'medium':
            score += 3
            factors.append('Medium packing indicators')

        anti = analysis.get('anti_analysis', [])
        if anti:
            score += min(len(anti), 4)
            factors.append(f'{len(anti)} anti-analysis indicators')

        apis = analysis.get('suspicious_apis', [])
        cat_scores = {
            'shell_exec': 3, 'anti_debug': 3, 'dynamic_loading': 2,
            'process_fork': 2, 'memory_protection': 2,
        }
        for item in apis:
            cat = item.get('category', '')
            score += cat_scores.get(cat, 1)
        if apis:
            factors.append(f'{len(apis)} suspicious API calls')

        if any(s.get('type') == 'c2_indicator' for s in analysis.get('suspicious_strings', [])):
            score += 3
            factors.append('C2 indicators')

        deob = analysis.get('deobfuscated_strings', [])
        if deob:
            score += min(len(deob), 3)
            factors.append(f'{len(deob)} deobfuscated strings')

        embedded = analysis.get('embedded_blobs', [])
        if embedded:
            embedded_types = Counter(b['type'] for b in embedded)
            for etype, count in embedded_types.most_common(3):
                if count > 2:
                    score += 3
                    factors.append(f'{count} embedded {etype} blobs')
                    break
            else:
                score += 2
                factors.append(f'{len(embedded)} embedded blobs')

        level = 'LOW'
        if score >= 15:
            level = 'CRITICAL'
        elif score >= 10:
            level = 'HIGH'
        elif score >= 5:
            level = 'MEDIUM'

        return {
            'level': level,
            'score': score,
            'factors': factors[:10],
        }

    @staticmethod
    def _compute_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        size = len(data)
        freq = Counter(data)
        for count in freq.values():
            p = count / size
            entropy -= p * (p and math.log2(p))
        return entropy

