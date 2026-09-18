"""
APK dissection engine for DroidForensix.

Extracts structural metadata, manifest data, permissions, components, native
libraries, resources, DEX statistics, and file structure from an APK without
running the full analysis pipeline.
"""

import json
import logging
import math
import os
import threading
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from androguard.core.apk import APK
from androguard.core.dex import DEX
from lxml import etree

from backend.config import settings
from backend.elf_analyzer import ELFBreaker

logger = logging.getLogger(__name__)


def _iter_instructions(code: Any):
    """Iterate a method's Dalvik instructions across androguard versions.

    androguard 4.x moved get_instructions() from DalvikCode to its
    internal DCode (DalvikCode.code); 3.x exposed it directly.
    """
    for obj in (code, getattr(code, "code", None)):
        getter = getattr(obj, "get_instructions", None)
        if getter is not None:
            return getter()
    raise TypeError(f"Cannot iterate instructions on {type(code).__name__}")

# Per-sample locks for atomic class cache writes
_class_cache_locks: Dict[str, threading.Lock] = {}
_class_cache_locks_lock = threading.Lock()

# In-memory class objects cache (avoids re-reading 841KB JSON from disk on every API call)
_CLASS_OBJECTS_CACHE: Dict[str, Tuple[List[Dict[str, Any]], float]] = {}
_CLASS_OBJECTS_TTL = 300  # 5 minutes

# In-memory dissection.json cache (avoids re-reading 2.7MB JSON per endpoint call)
_DISSECTION_CACHE: Dict[str, Tuple[Dict[str, Any], float]] = {}
_DISSECTION_TTL = 300  # 5 minutes

# Android namespace used in binary XML manifests
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Common permission protection levels for quick classification
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
}

SIGNATURE_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_AUTOFILL_SERVICE",
    "android.permission.BIND_APPWIDGET",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_DREAM_SERVICE",
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.BIND_MIDI_DEVICE_SERVICE",
    "android.permission.BIND_NFC_SERVICE",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_PRINT_SERVICE",
    "android.permission.BIND_SCREENING_SERVICE",
    "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
    "android.permission.BIND_TEXT_SERVICE",
    "android.permission.BIND_TV_INPUT",
    "android.permission.BIND_VISUAL_VOICEMAIL_SERVICE",
    "android.permission.BIND_VOICE_INTERACTION",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.BIND_VR_LISTENER_SERVICE",
    "android.permission.BIND_WALLPAPER",
    "android.permission.CLEAR_APP_USER_DATA",
    "android.permission.MANAGE_DEVICE_POLICY",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
}


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte string."""
    if not data:
        return 0.0
    length = len(data)
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class SampleAPKCache:
    """Thread-safe per-sample APK cache.

    Ensures one APK parse per sample_id across all endpoints.
    Also caches the SHA-256 hash so it's computed once.
    """

    def __init__(self):
        self._cache: Dict[str, Tuple[APK, str]] = {}
        self._lock = threading.RLock()

    def get_or_parse(self, sample_id: str, apk_path: str) -> Tuple[APK, str]:
        """Return cached (APK, sha256) or parse and cache."""
        with self._lock:
            entry = self._cache.get(sample_id)
            if entry is not None:
                return entry

            start = time.perf_counter()
            apk = APK(apk_path)
            elapsed = time.perf_counter() - start
            logger.info(f"APK parse: {elapsed:.3f}s for sample={sample_id[:12]} ({Path(apk_path).stat().st_size / 1e6:.1f}MB)")

            sha256 = self._compute_sha256(apk_path)
            self._cache[sample_id] = (apk, sha256)
            return apk, sha256

    def invalidate(self, sample_id: str) -> None:
        """Remove cached entry, forcing re-parse on next request."""
        with self._lock:
            self._cache.pop(sample_id, None)

    @staticmethod
    def _compute_sha256(path: str) -> str:
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()


class APKDissector:
    """Fast APK structural dissection."""

    def __init__(self, apk_path: str, work_dir: str = None, cache: Optional[SampleAPKCache] = None):
        self.apk_path = Path(apk_path)
        self.work_dir = Path(work_dir) if work_dir else settings.WORK_DIR
        self._cache = cache or SampleAPKCache()
        self._apk: Optional[APK] = None
        self._sample_id_cache: Optional[str] = None

    def _get_apk(self) -> APK:
        sample_id = self._sample_id_from_apk()
        apk, _ = self._cache.get_or_parse(sample_id, str(self.apk_path))
        return apk

    def dissect(self) -> Dict[str, Any]:
        """Return all dissected APK data as a JSON-serializable dict."""
        return {
            "metadata": self.extract_metadata(),
            "manifest": self.extract_manifest(),
            "permissions": self.extract_permissions(),
            "components": self.extract_components(),
            "native_libs": self.extract_native_libs(),
            "resources": self.extract_resources_structure(),
            "dex_stats": self.extract_dex_stats(),
            "file_structure": self.extract_file_structure(),
        }

    def extract_metadata(self) -> Dict[str, Any]:
        """Extract basic APK metadata."""
        apk = self._get_apk()
        return {
            "apk_path": str(self.apk_path),
            "file_size_bytes": self.apk_path.stat().st_size,
            "package_name": apk.get_package(),
            "version_code": apk.get_androidversion_code(),
            "version_name": apk.get_androidversion_name(),
            "min_sdk_version": apk.get_min_sdk_version(),
            "target_sdk_version": apk.get_target_sdk_version(),
            "effective_target_sdk_version": apk.get_effective_target_sdk_version(),
            "max_sdk_version": apk.get_max_sdk_version(),
            "is_multidex": apk.is_multidex(),
        }

    def extract_manifest(self) -> Dict[str, Any]:
        """Return parsed AndroidManifest.xml fields."""
        apk = self._get_apk()
        manifest = apk.get_android_manifest_xml()
        app = manifest.find("application")
        app_attrs = {}
        if app is not None:
            for key, value in app.attrib.items():
                # Strip Android namespace for readability
                short_key = key.replace(ANDROID_NS, "")
                app_attrs[short_key] = value

        return {
            "package": apk.get_package(),
            "version_code": apk.get_androidversion_code(),
            "version_name": apk.get_androidversion_name(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "max_sdk": apk.get_max_sdk_version(),
            "application": app_attrs,
            "features": sorted(set(apk.get_features() or [])),
            "libraries": sorted(set(apk.get_libraries() or [])),
            "raw_manifest": etree.tostring(manifest, pretty_print=True, encoding='unicode') if manifest is not None else None,
        }

    def extract_permissions(self) -> List[Dict[str, Any]]:
        """Return declared permissions with risk levels."""
        apk = self._get_apk()
        declared = apk.get_declared_permissions() or []
        requested = apk.get_permissions() or []
        details = apk.get_details_permissions() or {}

        permissions = []
        seen = set()

        for perm in requested:
            if perm in seen:
                continue
            seen.add(perm)
            perm_details = details.get(perm, [])
            protection_level = self._classify_protection_level(perm, perm_details)
            permissions.append({
                "name": perm,
                "type": "uses_permission",
                "protection_level": protection_level,
                "label": perm_details[1] if len(perm_details) > 1 else None,
                "description": perm_details[2] if len(perm_details) > 2 else None,
                "is_aosp": perm.startswith("android.permission."),
            })

        for perm in declared:
            if perm in seen:
                continue
            seen.add(perm)
            perm_details = details.get(perm, [])
            protection_level = self._classify_protection_level(perm, perm_details)
            permissions.append({
                "name": perm,
                "type": "declared_permission",
                "protection_level": protection_level,
                "label": perm_details[1] if len(perm_details) > 1 else None,
                "description": perm_details[2] if len(perm_details) > 2 else None,
                "is_aosp": perm.startswith("android.permission."),
            })

        return permissions

    def _classify_protection_level(self, permission: str, details: List[Any]) -> str:
        """Classify a permission's risk level."""
        if details:
            level = details[0]
            if isinstance(level, str):
                level_lower = level.lower()
                # Compound levels like "signature|system|development"
                if "dangerous" in level_lower:
                    return "dangerous"
                if "signature" in level_lower:
                    return "signature"
                if "normal" in level_lower:
                    return "normal"
                return level_lower
        if permission in DANGEROUS_PERMISSIONS:
            return "dangerous"
        if permission in SIGNATURE_PERMISSIONS:
            return "signature"
        if permission.startswith("android.permission."):
            return "normal"
        return "unknown"

    def extract_components(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return activities, services, broadcast receivers, content providers."""
        apk = self._get_apk()
        manifest = apk.get_android_manifest_xml()
        components = {"activities": [], "services": [], "receivers": [], "providers": []}

        for tag, key in [
            ("activity", "activities"),
            ("service", "services"),
            ("receiver", "receivers"),
            ("provider", "providers"),
        ]:
            for elem in manifest.findall(f".//{tag}"):
                name = elem.get(f"{ANDROID_NS}name")
                if not name:
                    continue
                exported = elem.get(f"{ANDROID_NS}exported")
                # Default exported rules: activities/receivers/services with
                # intent filters are exported by default; providers are not.
                has_filters = elem.find("intent-filter") is not None
                if exported is None:
                    if tag == "provider":
                        exported_default = False
                    else:
                        exported_default = has_filters
                else:
                    exported_default = exported.lower() == "true"

                intent_filters = apk.get_intent_filters(tag, name)

                components[key].append({
                    "name": name,
                    "exported": exported_default,
                    "exported_declared": exported,
                    "intent_filters": intent_filters if intent_filters else [],
                    "attributes": {
                        k.replace(ANDROID_NS, ""): v
                        for k, v in elem.attrib.items()
                    },
                })

        return components

    def extract_native_libs(self) -> List[Dict[str, Any]]:
        """Return list of .so files with full ELF break down."""
        apk = self._get_apk()
        libs = []
        with zipfile.ZipFile(self.apk_path, "r") as zf:
            zip_info = {info.filename: info for info in zf.infolist()}
            content_cache = {}
            for file_name in apk.get_files():
                if not file_name.endswith(".so"):
                    continue
                parts = Path(file_name).parts
                arch = parts[1] if len(parts) >= 3 else "unknown"
                info = zip_info.get(file_name)
                entry = {
                    "path": file_name,
                    "arch": arch,
                    "name": Path(file_name).name,
                    "size": info.file_size if info else 0,
                    "crc32": f"{info.CRC & 0xFFFFFFFF:08x}" if info else None,
                }

                # Run full ELF break down
                try:
                    if file_name not in content_cache:
                        content_cache[file_name] = zf.read(file_name)
                    content = content_cache[file_name]
                    if content:
                        breaker = ELFBreaker(entry["name"], content)
                        analysis = breaker.analyze()
                        entry["elf_analysis"] = analysis

                        jni_count = len(analysis.get("jni_exports", []))
                        if jni_count:
                            entry["jni_exports_count"] = jni_count
                            entry["jni_exports"] = analysis["jni_exports"]

                        packing = analysis.get("packing", {})
                        if packing.get("level", "none") != "none":
                            entry["packing"] = packing

                        anti = analysis.get("anti_analysis", [])
                        if anti:
                            entry["anti_analysis"] = anti

                        risk = analysis.get("risk_score", {})
                        entry["risk"] = risk

                        suspicious_strs = analysis.get("suspicious_strings", [])
                        if suspicious_strs:
                            entry["suspicious_strings"] = suspicious_strs

                        deob_strs = analysis.get("deobfuscated_strings", [])
                        if deob_strs:
                            entry["deobfuscated_strings"] = deob_strs
                except Exception:
                    logger.debug("Failed to run ELF break down on %s", file_name)

                libs.append(entry)
        return libs

    def extract_resources_structure(self) -> Dict[str, Any]:
        """Return high-level resource tree."""
        apk = self._get_apk()
        counts: Dict[str, int] = {}
        resource_files = []
        for file_name in apk.get_files():
            if file_name.startswith("res/"):
                resource_files.append(file_name)
                parts = Path(file_name).parts
                if len(parts) >= 2:
                    category = parts[1]
                    counts[category] = counts.get(category, 0) + 1

        return {
            "total_resource_files": len(resource_files),
            "counts_by_type": counts,
            "sample_files": resource_files[:50],
        }

    def extract_dex_stats(self) -> Dict[str, Any]:
        """Parse DEX header for statistics."""
        apk = self._get_apk()
        stats = {
            "dex_count": 0,
            "total_classes": 0,
            "total_methods": 0,
            "total_strings": 0,
            "total_bytes": 0,
            "entropy": 0.0,
            "dex_files": [],
        }

        all_dex_bytes = []
        for idx, dex_data in enumerate(apk.get_all_dex()):
            all_dex_bytes.append(dex_data)
            try:
                dex = DEX(dex_data)
                classes = len(list(dex.get_classes()))
                methods = len(list(dex.get_methods()))
                strings = len(list(dex.get_strings()))
            except Exception:
                logger.debug("Failed to parse DEX at index %d, using zero stats", idx)
                classes = methods = strings = 0

            stats["dex_files"].append({
                "index": idx,
                "size": len(dex_data),
                "classes": classes,
                "methods": methods,
                "strings": strings,
                "entropy": round(_shannon_entropy(dex_data), 4),
            })
            stats["total_classes"] += classes
            stats["total_methods"] += methods
            stats["total_strings"] += strings

        stats["dex_count"] = len(all_dex_bytes)
        combined = b"".join(all_dex_bytes)
        stats["total_bytes"] = len(combined)
        stats["entropy"] = round(_shannon_entropy(combined), 4)
        return stats

    def extract_file_structure(self) -> Dict[str, Any]:
        """Return directory tree of APK contents."""
        apk = self._get_apk()
        structure: Dict[str, List[str]] = {}
        for file_name in apk.get_files():
            parts = Path(file_name).parts
            top = parts[0] if parts else "root"
            structure.setdefault(top, []).append(file_name)

        return {
            "top_level_directories": sorted(structure.keys()),
            "files_by_directory": {k: v[:100] for k, v in structure.items()},
            "total_files": sum(len(v) for v in structure.values()),
        }

    def list_decompiled_classes(self) -> List[str]:
        """List class names from DEX via Androguard."""
        return self._list_classes_from_androguard()

    def _list_classes_from_androguard(self) -> List[str]:
        """List class names from DEX via Androguard."""
        try:
            apk = self._get_apk()
            classes = []
            for dex_data in apk.get_all_dex():
                try:
                    dex = DEX(dex_data)
                    for cls in dex.get_classes():
                        class_name = cls.get_name()
                        if class_name.startswith("L") and class_name.endswith(";"):
                            class_name = class_name[1:-1].replace("/", ".")
                        classes.append(class_name)
                except Exception:
                    logger.debug("Skipping malformed DEX class entry in androguard")
                    continue
            return sorted(classes)
        except Exception:
            logger.debug("Androguard class listing failed, returning empty")
            return []

    def list_decompiled_class_objects(self, refresh: bool = False) -> List[Dict[str, Any]]:
        """Return class objects with method/network summaries for the dashboard.
        Cached in-memory (5min TTL) and on-disk so subsequent loads are instant.
        """
        sample_id = self._sample_id_from_apk()
        now = time.time()

        if refresh:
            _CLASS_OBJECTS_CACHE.pop(sample_id, None)

        # In-memory cache (avoids re-reading 841KB JSON from disk per request)
        cached = _CLASS_OBJECTS_CACHE.get(sample_id)
        if cached is not None and (now - cached[1]) < _CLASS_OBJECTS_TTL:
            return cached[0]

        cache_path = self.work_dir / sample_id / "dissection_classes_cache.json"

        # Return cached result if available
        if cache_path.exists():
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                _CLASS_OBJECTS_CACHE[sample_id] = (data, now)
                return data
            except Exception:
                logger.debug("Class cache corrupt, rebuilding")

        result = self._list_class_objects_from_androguard()

        # Atomic write cache with per-sample lock
        with _class_cache_locks_lock:
            if sample_id not in _class_cache_locks:
                _class_cache_locks[sample_id] = threading.Lock()
            lock = _class_cache_locks[sample_id]

        with lock:
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                tmp_path = cache_path.with_suffix(".tmp")
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(result, f)
                os.replace(tmp_path, cache_path)
            except Exception:
                logger.debug("Cache write failed (non-fatal)")

        _CLASS_OBJECTS_CACHE[sample_id] = (result, now)
        return result

    def _list_class_objects_from_androguard(self) -> List[Dict[str, Any]]:
        """Extract classes and methods from DEX bytecode using Androguard."""
        classes = []
        try:
            apk = self._get_apk()
            for dex_data in apk.get_all_dex():
                try:
                    dex = DEX(dex_data)
                    for cls in dex.get_classes():
                        raw_class_name = cls.get_name()
                        class_name = raw_class_name
                        if class_name.startswith("L") and class_name.endswith(";"):
                            class_name = class_name[1:-1].replace("/", ".")
                        
                        methods = []
                        for method in cls.get_methods():
                            method_name = method.get_name()
                            body_parts = []
                            try:
                                code = method.get_code()
                                if code:
                                    for ins in _iter_instructions(code):
                                        body_parts.append(f"{ins.get_name()} {ins.get_output()}")
                            except Exception:
                                logger.debug("Failed to extract method instructions in androguard")

                            body = "\n".join(body_parts) if body_parts else "[Bytecode unavailable]"
                            methods.append({
                                "name": method_name,
                                "body": body
                            })

                        classes.append({
                            "name": class_name,
                            "methods": methods,
                            "network_calls": [],
                            "permissions_used": []
                        })
                except Exception:
                    logger.debug("Skipping DEX class in androguard")
                    continue
        except Exception:
            logger.debug("Androguard class object extraction failed entirely")
        return sorted(classes, key=lambda x: x["name"])

    def read_class_source(self, class_name: str) -> Optional[str]:
        """Read class source as disassembled DEX instructions via Androguard."""
        return self._disassemble_class_from_androguard(class_name)

    def _disassemble_class_from_androguard(self, class_name: str) -> Optional[str]:
        """Disassemble a class from DEX using Androguard and return a text representation."""
        try:
            apk = self._get_apk()
            targets = [
                "L" + class_name.replace(".", "/") + ";",
                class_name,
                class_name.replace(".", "/"),
            ]
            for dex_data in apk.get_all_dex():
                try:
                    dex = DEX(dex_data)
                    for cls in dex.get_classes():
                        cls_raw = cls.get_name()
                        if cls_raw in targets:
                            output = [
                                f"// Disassembled DEX Class via Androguard",
                                f"class {class_name} {{",
                                ""
                            ]
                            for method in cls.get_methods():
                                access_flags = method.get_access_flags()
                                flags = []
                                if access_flags & 0x1: flags.append("public")
                                if access_flags & 0x2: flags.append("private")
                                if access_flags & 0x4: flags.append("protected")
                                if access_flags & 0x8: flags.append("static")
                                if access_flags & 0x10: flags.append("final")
                                if access_flags & 0x100: flags.append("native")
                                
                                flag_str = " ".join(flags) + " " if flags else ""
                                output.append(f"    {flag_str}{method.get_name()}{method.get_descriptor()} {{")
                                
                                code = method.get_code()
                                if code:
                                    for ins in _iter_instructions(code):
                                        output.append(f"        {ins.get_name():<15} {ins.get_output()}")
                                else:
                                    output.append("        // No code body (abstract/native/empty)")
                                output.append("    }")
                                output.append("")
                            output.append("}")
                            return "\n".join(output)
                except Exception:
                    logger.debug("Failed to disassemble DEX for class %s", class_name)
                    continue
        except Exception:
            logger.debug("Androguard disassemble failed for class %s", class_name)
        logger.warning("Androguard: class '%s' not found in DEX (listed but source unavailable)", class_name)
        return None

    def load_strings(self) -> Optional[Dict[str, Any]]:
        """Load extracted strings from Step 2 result."""
        sample_id = self._sample_id_from_apk()
        strings_path = self.work_dir / sample_id / "step2_strings.json"
        if not strings_path.exists():
            return None
        try:
            with open(strings_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            logger.debug("Failed to load strings JSON for sample %s", self._sample_id_from_apk())
            return None

    def _sample_id_from_apk(self) -> str:
        """Compute sample_id as SHA-256 of the APK, matching Step 1.
        Cached per instance to avoid re-hashing on every call.
        """
        if self._sample_id_cache is not None:
            return self._sample_id_cache
        import hashlib
        h = hashlib.sha256()
        with open(self.apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        self._sample_id_cache = h.hexdigest()
        return self._sample_id_cache


def get_class_methods_lite(class_objects: List[Dict[str, Any]], class_name: str) -> Optional[Dict[str, Any]]:
    """Return a single class with its methods (from cached class objects).
    Used for on-demand method body loading after the lightweight list is returned.
    """
    for cls in class_objects:
        if cls["name"] == class_name:
            return cls
    return None


def load_dissection(work_dir: str, sample_id: str) -> Optional[Dict[str, Any]]:
    """Load cached dissection.json for a sample if it exists (in-memory cached, 5min TTL)."""
    now = time.time()
    cached = _DISSECTION_CACHE.get(sample_id)
    if cached is not None and (now - cached[1]) < _DISSECTION_TTL:
        return cached[0]

    path = Path(work_dir) / sample_id / "dissection.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        _DISSECTION_CACHE[sample_id] = (data, now)
        return data
    except Exception:
        logger.debug("Failed to load dissection.json for %s", sample_id)
        return None


def dissect_apk(apk_path: str, work_dir: str = None) -> Dict[str, Any]:
    """Convenience function to dissect an APK."""
    return APKDissector(apk_path, work_dir).dissect()
