"""
Code analysis engine for DroidForensix.

Analyzes decompiled Java code to extract:
- Method-level risk assessment
- Suspicious patterns (reflection, service launching, payload dropping)
- String references and their usage context
- Attack flow reconstruction
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.dissection import APKDissector


_SUSPICIOUS_PATTERNS: Dict[str, Dict[str, Any]] = {
    "reflection_abuse": {
        "patterns": [
            r"\bsetAccessible\s*\(",
            r"\binvoke\s*\(",
            r"\bgetDeclaredField\s*\(",
            r"\bgetDeclaredMethod\s*\(",
            r"\bforName\s*\(",
        ],
        "risk": "CRITICAL",
        "label": "Reflection Abuse",
        "description": "Uses Java reflection to access hidden APIs or methods",
    },
    "service_dropping": {
        "patterns": [
            r"\bstartService\s*\(",
            r"\bsetClassName\s*\(",
        ],
        "risk": "CRITICAL",
        "label": "Service Dropping",
        "description": "Launches Android services dynamically",
    },
    "payload_drop": {
        "patterns": [
            r"\bgetAssets\s*\(",
            r"\bopenNonAsset\s*\(",
            r"\bFileOutputStream\s*\(",
            r"\binstallPackage\s*\(",
            r"\bPackageInstaller\s*\(",
        ],
        "risk": "CRITICAL",
        "label": "Payload Drop",
        "description": "Extracts or writes files possible malware payload deployment",
    },
    "anti_analysis": {
        "patterns": [
            r"\bequals\s*\([^)]*m30a",
            r"\bsignature",
            r"\bPackageManager.*GET_SIGNATURES",
            r"\bcheckSignature",
        ],
        "risk": "MEDIUM",
        "label": "Anti-Analysis",
        "description": "Signature or integrity check may be evading analysis",
    },
    "crypto": {
        "patterns": [
            r"\bCipher\s*\(",
            r"\bencrypt",
            r"\bdecrypt",
            r"\bSecretKeySpec\s*\(",
            r"\bKeyGenerator\s*\(",
            r"\bIvParameterSpec\s*\(",
        ],
        "risk": "MEDIUM",
        "label": "Cryptography",
        "description": "Cryptographic operations check for data encryption/decryption",
    },
    "network": {
        "patterns": [
            r"\bHttpURLConnection\s*\(",
            r"\bSocket\s*\(",
            r"\bURL\s*\(",
            r"\bopenConnection\s*\(",
            r"\bgetInputStream\s*\(",
            r"\bInetAddress\s*\(",
        ],
        "risk": "HIGH",
        "label": "Network Communication",
        "description": "Network call potential C2 communication channel",
    },
    "dynamic_loading": {
        "patterns": [
            r"\bDexClassLoader\s*\(",
            r"\bPathClassLoader\s*\(",
            r"\bloadClass\s*\(",
            r"\bdefineClass\s*\(",
        ],
        "risk": "CRITICAL",
        "label": "Dynamic Code Loading",
        "description": "Loads code at runtime strong indicator of malicious behavior",
    },
    "command_exec": {
        "patterns": [
            r"\bRuntime\.exec\s*\(",
            r"\.exec\s*\(",
            r"\bProcessBuilder\s*\(",
        ],
        "risk": "CRITICAL",
        "label": "Command Execution",
        "description": "Executes shell commands high-severity indicator",
    },
}

_STRING_CLASSIFICATION_RULES: List[tuple] = [
    ("payload_filename", re.compile(r"\.(apk|dex|jar|zip)$", re.IGNORECASE)),
    ("social_engineering", re.compile(r"[\u4e00-\u9fff]")),
    ("c2_domain", re.compile(r"^https?://", re.IGNORECASE)),
    ("ip_address", re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")),
    ("file_path", re.compile(r"^/(data|sdcard|system|storage)/")),
    ("signature_check", re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")),
]

_ENTRY_POINTS = {
    "onCreate", "onStart", "onResume", "onReceive",
    "onHandleIntent", "run", "onClick", "onActivityResult",
}

_METHOD_PATTERN = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|abstract|synchronized|native)\s+)+"
    r"(?:[\w\[\]<>?]+(?:\s*<[^>]+>\s*)?\s+)+"
    r"(\w+)\s*\([^)]*\)\s*\{",
    re.MULTILINE,
)

_CALL_PATTERN = re.compile(r"(?:this\.)?(\w+)\s*\(")

_CONTROL_NAMES = {"if", "for", "while", "switch", "catch", "synchronized", "try", "finally", "return"}


def _parse_method_bodies(source: str) -> List[Dict[str, Any]]:
    """Parse Java method declarations and bodies from source code."""
    methods = []
    for match in _METHOD_PATTERN.finditer(source):
        name = match.group(1)
        if name in _CONTROL_NAMES:
            continue
        body_start = match.end()
        brace_count = 1
        idx = body_start
        while idx < len(source) and brace_count > 0:
            if source[idx] == "{":
                brace_count += 1
            elif source[idx] == "}":
                brace_count -= 1
            idx += 1
        body = source[body_start:idx - 1]
        start_line = source[:match.start()].count("\n") + 1
        end_line = start_line + body.count("\n") + 1
        methods.append({
            "name": name,
            "body": body,
            "start_line": start_line,
            "end_line": end_line,
        })
    return methods


def _detect_techniques(body: str, start_line: int) -> tuple:
    """Detect suspicious techniques in a method body. Returns (techniques, suspicious_lines)."""
    techniques = []
    suspicious_lines = []
    for tech_name, tech_info in _SUSPICIOUS_PATTERNS.items():
        for pattern_str in tech_info["patterns"]:
            try:
                for line_match in re.finditer(pattern_str, body, re.IGNORECASE):
                    line_num = body[:line_match.start()].count("\n") + start_line
                    line_start = body.rfind("\n", 0, line_match.start()) + 1
                    line_end = body.find("\n", line_match.start())
                    if line_end == -1:
                        line_end = len(body)
                    code_line = body[line_start:line_end].strip()
                    if tech_name not in techniques:
                        techniques.append(tech_name)
                    suspicious_lines.append({
                        "line": line_num,
                        "pattern": tech_name,
                        "code": code_line,
                        "description": tech_info["description"],
                        "risk": tech_info["risk"],
                    })
            except re.error:
                continue
    return techniques, suspicious_lines


def _extract_calls(body: str, start_line: int) -> List[Dict[str, Any]]:
    """Extract method calls from a method body."""
    calls = []
    for call_match in _CALL_PATTERN.finditer(body):
        target = call_match.group(1)
        if target in _CONTROL_NAMES:
            continue
        line_num = body[:call_match.start()].count("\n") + start_line
        if not any(c["target"] == target for c in calls):
            calls.append({
                "target": target,
                "line": line_num,
                "action": f"Calls {target}()",
            })
    return calls


def _assess_risk(techniques: List[str]) -> str:
    """Assign overall risk level based on detected techniques."""
    critical_techs = {t for t, info in _SUSPICIOUS_PATTERNS.items() if info["risk"] == "CRITICAL"}
    high_techs = {t for t, info in _SUSPICIOUS_PATTERNS.items() if info["risk"] == "HIGH"}
    tech_set = set(techniques)
    if tech_set & critical_techs:
        return "CRITICAL"
    if tech_set & high_techs:
        return "HIGH"
    if tech_set:
        return "MEDIUM"
    return "LOW"


def _classify_string(string_value: str) -> str:
    """Classify a string by its usage type."""
    for label, pattern in _STRING_CLASSIFICATION_RULES:
        if pattern.search(string_value):
            return label
    if "." in string_value and string_value.count(".") >= 2:
        return "service_name"
    return "other"


def _method_at_line(source: str, line_number: int) -> str:
    """Determine which method a line belongs to."""
    methods = _parse_method_bodies(source)
    for m in methods:
        if m["start_line"] <= line_number <= m["end_line"]:
            return m["name"]
    return "unknown"


def _reconstruct_attack_flow(methods: List[Dict[str, Any]], source: str) -> List[Dict[str, Any]]:
    """Build attack chain from entry points through method calls to malicious actions."""
    flow = []
    step_num = 0

    method_map = {}
    for m in methods:
        entry_type = None
        if m["name"] in _ENTRY_POINTS:
            entry_type = "Entry point"
        elif m["risk_level"] == "CRITICAL":
            if "payload_drop" in m["techniques"]:
                entry_type = "Malware execution"
            elif "service_dropping" in m["techniques"]:
                entry_type = "Service launch"
            elif "dynamic_loading" in m["techniques"]:
                entry_type = "Dynamic load"
            elif "command_exec" in m["techniques"]:
                entry_type = "Command execution"
        elif m["risk_level"] == "HIGH":
            entry_type = "Suspicious operation"
        elif m["techniques"]:
            entry_type = "Decision logic"

        if entry_type:
            tech_descriptions = []
            for t in m["techniques"]:
                info = _SUSPICIOUS_PATTERNS.get(t)
                if info:
                    tech_descriptions.append(info["description"])
            step_num += 1
            description = f"{m['name']}() - {', '.join(tech_descriptions)}" if tech_descriptions else f"{m['name']}()"
            flow.append({
                "step": step_num,
                "method": m["name"],
                "line": m["start_line"],
                "action": f"{entry_type}: {m['name']}()",
                "description": description,
                "risk_level": m["risk_level"],
            })

        method_map[m["name"]] = m

    if not flow:
        return flow

    sorted_flow = sorted(flow, key=lambda f: (
        _ENTRY_POINT_ORDER.get(f["method"], 999),
        f["step"],
    ))
    for i, item in enumerate(sorted_flow, start=1):
        item["step"] = i
    return sorted_flow


_ENTRY_POINT_ORDER = {
    "onCreate": 0, "onStart": 1, "onResume": 2,
    "onReceive": 3, "onHandleIntent": 4, "run": 5,
    "onClick": 6, "onActivityResult": 7,
}


class CodeAnalyzer:
    """Analyzes decompiled Java code for suspicious patterns and attack flows."""

    def __init__(self, apk_path: str, work_dir: str, sample_id: str, cache=None):
        self.sample_id = sample_id
        self.work_dir = work_dir
        self.dissector = APKDissector(
            apk_path, work_dir=work_dir, cache=cache or None,
        )
        self._all_classes: Optional[List[Dict[str, Any]]] = None

    def analyze_class(self, class_name: str) -> Optional[Dict[str, Any]]:
        """Analyze a single decompiled class and return structured analysis."""
        source = self.dissector.read_class_source(class_name)
        if source is None:
            return None

        methods = self._extract_methods(source)
        string_refs = self._extract_string_refs(source)
        attack_flow = _reconstruct_attack_flow(methods, source)

        return {
            "class_name": class_name,
            "methods": methods,
            "string_references": string_refs,
            "attack_flow": attack_flow,
        }

    def get_string_references(self, string_value: str) -> Optional[Dict[str, Any]]:
        """Find all usages of a string value across all decompiled classes."""
        classes = self._get_all_classes()
        usages = []
        for cls in classes:
            source = self.dissector.read_class_source(cls["name"])
            if source is None:
                continue
            for i, line in enumerate(source.splitlines(), start=1):
                if string_value in line:
                    method = _method_at_line(source, i)
                    usage_type = _classify_string(string_value)
                    usages.append({
                        "class_name": cls["name"],
                        "method": method,
                        "line": i,
                        "usage": usage_type,
                        "context": line.strip(),
                    })
        if not usages:
            return None
        return {"string": string_value, "usages": usages}

    def _extract_methods(self, source: str) -> List[Dict[str, Any]]:
        """Parse methods from Java source and assess risk per method."""
        parsed = _parse_method_bodies(source)
        methods = []
        for m in parsed:
            techniques, suspicious_lines = _detect_techniques(m["body"], m["start_line"])
            calls = _extract_calls(m["body"], m["start_line"])
            risk_level = _assess_risk(techniques)
            methods.append({
                "name": m["name"],
                "start_line": m["start_line"],
                "end_line": m["end_line"],
                "risk_level": risk_level,
                "techniques": techniques,
                "calls": calls,
                "suspicious_lines": suspicious_lines,
            })
        return methods

    def _extract_string_refs(self, source: str) -> Dict[str, List[Dict[str, Any]]]:
        """Extract string constants and their usage locations from source."""
        string_pattern = re.compile(r'"((?:\\.|[^"\\])*)"')
        refs: Dict[str, List[Dict[str, Any]]] = {}
        for match in string_pattern.finditer(source):
            value = match.group(1)
            if len(value) < 3 or value.startswith("\\"):
                continue
            line_num = source[:match.start()].count("\n") + 1
            method = _method_at_line(source, line_num)
            usage_type = _classify_string(value)
            if value not in refs:
                refs[value] = []
            refs[value].append({
                "method": method,
                "line": line_num,
                "usage": usage_type,
            })
        return refs

    def _get_all_classes(self) -> List[Dict[str, Any]]:
        """Get and cache all decompiled class objects."""
        if self._all_classes is None:
            self._all_classes = self.dissector.list_decompiled_class_objects()
        return self._all_classes
