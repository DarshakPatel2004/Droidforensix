#!/usr/bin/env python3
"""
DroidForensix Androguard Static Analysis Module
Refactored for integration into 7-step pipeline.

Usage:
    analyzer = APKAnalyzer("path/to/apk")
    results = analyzer.run()
    
Returns:
    {
        'success': bool,
        'data': {
            'metadata': {...},
            'permissions': [...],
            'fcm_components': [...],
            'native_libs': [...],
            'risk_assessment': {...}
        }
    }
"""

import sys
import os
import zipfile
import re
import logging
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple

from backend.elf_analyzer import ELFBreaker

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    from androguard.core.analysis import analysis
except ImportError:
    print("ERROR: androguard not installed. Run: pip install androguard")
    sys.exit(1)

logger = logging.getLogger(__name__)


class APKAnalyzer:
    """
    Static analysis for Android APKs using androguard.
    Designed for DroidForensix pipeline integration.
    """
    
    # High-risk permission list
    HIGH_RISK_PERMS = [
        'REQUEST_INSTALL_PACKAGES',
        'QUERY_ALL_PACKAGES',
        'RECEIVE_BOOT_COMPLETED',
        'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS',
        'BIND_ACCESSIBILITY_SERVICE',
        'SYSTEM_ALERT_WINDOW',
        'WRITE_SETTINGS',
        'DEVICE_ADMIN',
        'READ_SMS', 'SEND_SMS',
        'READ_CONTACTS', 'READ_CALL_LOG',
        'RECORD_AUDIO', 'CAMERA',
        'ACCESS_FINE_LOCATION',
        'READ_EXTERNAL_STORAGE'
    ]
    
    # Firebase/FCM indicators
    FCM_INDICATORS = [
        'firebase', 'fcm', 'messaging', 'c2dm', 'cloud', 'gcm',
        'google.*messaging', 'messaging_event', 'cloudmessaging'
    ]
    
    # Suspicious string patterns
    SUSPICIOUS_PATTERNS = {
        'package_names': r'com\.[a-zA-Z0-9_\.]{5,}',
        'urls': r'https?://[^\s\"]+',
        'ip_addresses': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        'shell': r'sh\s+-c|/system/bin/sh|exec\(',
        'dex_loading': r'DexClassLoader|PathClassLoader|InMemoryClassLoader',
        'reflection': r'java/lang/reflect',
        'native': r'loadLibrary|System\.load|JNI',
        'command_control': r'c2|command|control|bot|payload',
    }
    
    def __init__(self, apk_path: str, deep_analysis: bool = True):
        """
        Initialize analyzer.
        
        Args:
            apk_path: Path to APK file
            deep_analysis: Enable bytecode deep analysis (slower but comprehensive)
        """
        self.apk_path = apk_path
        self.deep_analysis = deep_analysis
        self.apk: Optional[APK] = None
        self.dexes: List[DEX] = []
        self.dx: Optional[analysis.Analysis] = None
        
        self.results = {
            'metadata': {},
            'permissions': [],
            'fcm_components': [],
            'native_libs': [],
            'native_strings': [],
            'jni_methods': [],
            'obfuscated_classes': [],
            'bytecode_methods': [],
            'crypto_usage': [],
            'suspicious_strings': [],
            'network_indicators': [],
            'certificate_info': {},
            'risk_assessment': {},
            'error': None
        }
    
    def _set_error(self, message: str):
        """Log and set error"""
        logger.error(message)
        self.results['error'] = message
    
    def load_dex_files(self) -> bool:
        """Load and parse DEX files from APK."""
        try:
            self.apk = APK(self.apk_path)
            dex_data_list = self.apk.get_all_dex()
            
            if not dex_data_list:
                self._set_error("No DEX files found in APK")
                return False
            
            for dex_data in dex_data_list:
                d = DEX(dex_data)
                self.dexes.append(d)
            
            # Create analysis object
            self.dx = analysis.Analysis(self.dexes[0])
            for d in self.dexes[1:]:
                self.dx.add(d)
            
            logger.info(f"Loaded {len(self.dexes)} DEX file(s)")
            return True
            
        except Exception as e:
            self._set_error(f"DEX loading failed: {str(e)}")
            return False
    
    def extract_metadata(self) -> None:
        """Extract basic APK metadata."""
        try:
            self.results['metadata'] = {
                'package': self.apk.get_package(),
                'version_name': self.apk.get_androidversion_name(),
                'version_code': self.apk.get_androidversion_code(),
                'min_sdk': self.apk.get_min_sdk_version(),
                'target_sdk': self.apk.get_target_sdk_version(),
                'num_dex': len(self.dexes),
                'num_classes': sum(len(d.get_classes()) for d in self.dexes)
            }
        except Exception as e:
            logger.warning(f"Metadata extraction failed: {e}")
    
    def extract_all_strings(self) -> List[str]:
        """Extract all strings from DEX files."""
        strings = set()
        try:
            for d in self.dexes:
                for string in d.get_strings():
                    if string and len(string) > 1:
                        strings.add(string)
            logger.info(f"Extracted {len(strings)} unique strings")
            return sorted(list(strings))
        except Exception as e:
            logger.warning(f"String extraction failed: {e}")
            return []
    
    def analyze_permissions(self) -> None:
        """Analyze APK permissions and identify high-risk ones."""
        try:
            all_perms = self.apk.get_permissions()
            
            for perm in all_perms:
                is_high_risk = any(risk in perm for risk in self.HIGH_RISK_PERMS)
                self.results['permissions'].append({
                    'name': perm,
                    'high_risk': is_high_risk
                })
            
            logger.info(f"Found {len(all_perms)} permissions "
                       f"({sum(1 for p in self.results['permissions'] if p['high_risk'])} high-risk)")
        except Exception as e:
            logger.warning(f"Permission analysis failed: {e}")
    
    def find_fcm_components(self) -> None:
        """Identify Firebase/FCM messaging components."""
        try:
            manifest = self.apk.get_android_manifest_xml()
            if manifest is None:
                return
            
            for element_type in ['receiver', 'service']:
                for element in manifest.iter(element_type):
                    # Extract component name
                    name = element.get('{http://schemas.android.com/apk/res/android}name', '')
                    if not name:
                        name = element.get('android:name', '')
                    
                    # Check if FCM-related
                    is_fcm = any(x in name.lower() for x in self.FCM_INDICATORS)
                    
                    # Extract intent filters
                    intents = []
                    for intent_filter in element.findall('.//intent-filter'):
                        for action in intent_filter.findall('.//action'):
                            action_name = action.get('{http://schemas.android.com/apk/res/android}name', '')
                            if not action_name:
                                action_name = action.get('android:name', '')
                            intents.append(action_name)
                            if any(x in action_name.lower() for x in self.FCM_INDICATORS):
                                is_fcm = True
                    
                    # Check exported status
                    exported = element.get('{http://schemas.android.com/apk/res/android}exported', 'false')
                    if not exported:
                        exported = element.get('android:exported', 'false')
                    
                    if is_fcm or any(x in i.lower() for x in self.FCM_INDICATORS for i in intents):
                        self.results['fcm_components'].append({
                            'type': element_type,
                            'name': name,
                            'intents': intents,
                            'exported': exported.lower() == 'true'
                        })
            
            logger.info(f"Found {len(self.results['fcm_components'])} FCM components")
        except Exception as e:
            logger.warning(f"FCM analysis failed: {e}")
    
    def extract_native_libraries(self) -> None:
        """Extract and analyze native libraries (.so files) with full ELF break down."""
        all_native_strings = []
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                for name in z.namelist():
                    if name.endswith('.so'):
                        lib_name = os.path.basename(name)
                        parts = name.split('/')
                        arch = parts[1] if len(parts) > 1 else 'unknown'
                        
                        try:
                            with z.open(name) as f:
                                content = f.read()

                            breaker = ELFBreaker(lib_name, content)
                            analysis = breaker.analyze()

                            entry = {
                                'path': name,
                                'name': lib_name,
                                'architecture': arch,
                                'size_bytes': analysis.get('size_bytes', len(content)),
                                'elf_analysis': analysis,
                            }

                            suspicious_count = len(analysis.get('suspicious_strings', []))
                            if suspicious_count:
                                entry['suspicious_strings_count'] = suspicious_count

                            jni_count = len(analysis.get('jni_exports', []))
                            if jni_count:
                                entry['jni_exports_count'] = jni_count
                                entry['jni_exports'] = analysis['jni_exports']

                            packing = analysis.get('packing', {})
                            if packing.get('level', 'none') != 'none':
                                entry['packing'] = packing

                            anti = analysis.get('anti_analysis', [])
                            if anti:
                                entry['anti_analysis'] = anti

                            risk = analysis.get('risk_score', {})
                            entry['risk'] = risk

                            self.results['native_libs'].append(entry)

                            all_native_strings.extend(analysis.get('suspicious_strings', []))

                        except Exception as e:
                            logger.warning("Failed to analyze %s: %s", name, e)
                            self.results['native_libs'].append({
                                'path': name,
                                'name': lib_name,
                                'architecture': arch,
                                'error': str(e),
                            })

            self.results['native_strings'] = all_native_strings
            logger.info("Analyzed %d native libraries (%d suspicious strings)",
                        len(self.results['native_libs']), len(all_native_strings))
        except Exception as e:
            logger.warning("Native library extraction failed: %s", e)
            logger.debug(f"Native string extraction error: {e}")
    
    def analyze_bytecode_deep(self) -> None:
        """Perform deep bytecode analysis (optional, can be slow)."""
        if not self.deep_analysis:
            return
        
        try:
            for d in self.dexes:
                for cls in d.get_classes():
                    class_name = cls.get_name()
                    
                    # Find JNI methods (native methods)
                    for method in cls.get_methods():
                        if method.get_access_flags() & 0x0100:  # ACC_NATIVE
                            self.results['jni_methods'].append({
                                'class': class_name,
                                'method': method.get_name()
                            })
                    
                    # Analyze interesting methods
                    for method in cls.get_methods():
                        try:
                            if method.get_code():
                                method_info = {
                                    'class': class_name,
                                    'method': method.get_name(),
                                    'string_refs': [],
                                    'method_calls': [],
                                    'suspicious': []
                                }
                                
                                for ins in method.get_instructions():
                                    output = ins.get_output()
                                    
                                    # Detect native library loading
                                    if 'loadLibrary' in output:
                                        method_info['suspicious'].append('native_library_load')
                                    
                                    # Detect reflection
                                    if 'java/lang/reflect' in output:
                                        method_info['suspicious'].append('reflection')
                                    
                                    # Detect crypto
                                    if any(x in output for x in ['Cipher', 'MessageDigest', 'SecretKey']):
                                        method_info['suspicious'].append('crypto_usage')
                                    
                                    # Detect dynamic loading
                                    if 'ClassLoader' in output:
                                        method_info['suspicious'].append('dynamic_classloader')
                                
                                if method_info['suspicious']:
                                    self.results['bytecode_methods'].append(method_info)
                        except Exception:
                            continue
            
            logger.info(f"Analyzed {len(self.results['bytecode_methods'])} interesting methods")
        except Exception as e:
            logger.warning(f"Deep bytecode analysis failed: {e}")
    
    def analyze_obfuscation(self) -> None:
        """Detect obfuscated class names."""
        try:
            for d in self.dexes:
                for cls in d.get_classes():
                    class_name = cls.get_name()
                    simple_name = class_name.split('/')[-1].replace(';', '')
                    
                    # Short names (< 4 chars)
                    if len(simple_name) <= 4 and re.match(r'^[a-zA-Z0-9]+$', simple_name):
                        self.results['obfuscated_classes'].append({
                            'class': class_name,
                            'type': 'short_obfuscated'
                        })
                    # Dictionary words (suspicious for obfuscation)
                    elif len(simple_name) > 8 and re.match(r'^[a-zA-Z]+$', simple_name):
                        vowels = sum(1 for c in simple_name.lower() if c in 'aeiou')
                        if vowels >= 2:  # Real words have vowels
                            self.results['obfuscated_classes'].append({
                                'class': class_name,
                                'type': 'dictionary_word'
                            })
            
            logger.info(f"Found {len(self.results['obfuscated_classes'])} obfuscated classes")
        except Exception as e:
            logger.warning(f"Obfuscation analysis failed: {e}")
    
    def find_suspicious_strings(self, all_strings: List[str]) -> None:
        """Identify suspicious strings matching known patterns."""
        try:
            for string in all_strings:
                for category, pattern in self.SUSPICIOUS_PATTERNS.items():
                    if re.search(pattern, string, re.IGNORECASE):
                        self.results['suspicious_strings'].append({
                            'category': category,
                            'value': string
                        })
            
            # Deduplicate
            seen = set()
            unique = []
            for item in self.results['suspicious_strings']:
                key = (item['category'], item['value'])
                if key not in seen:
                    seen.add(key)
                    unique.append(item)
            self.results['suspicious_strings'] = unique
            
            logger.info(f"Found {len(unique)} suspicious string indicators")
        except Exception as e:
            logger.warning(f"Suspicious string analysis failed: {e}")
    
    def analyze_certificate(self) -> None:
        """Analyze APK signing certificate."""
        try:
            cert = self.apk.get_certificate(self.apk.get_signature_name())
            if cert:
                self.results['certificate_info'] = {
                    'issuer': str(cert.issuer),
                    'subject': str(cert.subject),
                    'serial': str(cert.serial_number),
                    'self_signed': str(cert.issuer) == str(cert.subject),
                    'valid_from': str(cert.not_valid_before),
                    'valid_until': str(cert.not_valid_after)
                }
                logger.info("Certificate analyzed")
        except Exception as e:
            logger.debug(f"Certificate analysis failed: {e}")
    
    def calculate_risk(self) -> None:
        """Calculate risk score based on findings."""
        risk_score = 0
        risk_factors = []
        
        high_risk_perms = sum(1 for p in self.results['permissions'] if p['high_risk'])
        if high_risk_perms:
            risk_score += high_risk_perms * 2
            risk_factors.append(f"High-risk permissions: {high_risk_perms}")
        
        if self.results['fcm_components']:
            risk_score += 3
            risk_factors.append("FCM C2 capability detected")
        
        if self.results['native_libs']:
            risk_score += 2
            risk_factors.append("Native code present")
        
        if self.results['obfuscated_classes']:
            risk_score += len(self.results['obfuscated_classes'])
            risk_factors.append(f"Obfuscated classes: {len(self.results['obfuscated_classes'])}")
        
        if self.results['jni_methods']:
            risk_score += 2
            risk_factors.append(f"JNI native methods: {len(self.results['jni_methods'])}")
        
        # Determine risk level
        if risk_score >= 15:
            risk_level = "CRITICAL"
        elif risk_score >= 10:
            risk_level = "HIGH"
        elif risk_score >= 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        self.results['risk_assessment'] = {
            'level': risk_level,
            'score': risk_score,
            'max_score': 25,
            'factors': risk_factors
        }
        
        logger.info(f"Risk: {risk_level} ({risk_score}/25)")
    
    def run(self) -> Dict[str, Any]:
        """
        Execute full analysis pipeline.
        
        Returns:
            {
                'success': bool,
                'data': {...results...} or 'error': str
            }
        """
        if not self.load_dex_files():
            return {
                'success': False,
                'error': self.results['error']
            }
        
        # Run all analysis steps
        self.extract_metadata()
        self.analyze_permissions()
        self.find_fcm_components()
        self.extract_native_libraries()
        self.analyze_obfuscation()
        
        # Extract strings for pattern matching
        all_strings = self.extract_all_strings()
        self.find_suspicious_strings(all_strings)
        
        # Deep analysis (optional, slower)
        if self.deep_analysis:
            self.analyze_bytecode_deep()
        
        self.analyze_certificate()
        self.calculate_risk()
        
        return {
            'success': True,
            'data': self.results
        }


def main():
    """CLI interface for testing."""
    if len(sys.argv) < 2:
        print("Usage: python androguard_analyzer.py <path_to_apk> [--no-deep]")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    deep = '--no-deep' not in sys.argv
    
    if not os.path.exists(apk_path):
        print(f"[-] File not found: {apk_path}")
        sys.exit(1)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)-8s | %(message)s'
    )
    
    print(f"[*] Analyzing: {apk_path}")
    analyzer = APKAnalyzer(apk_path, deep_analysis=deep)
    results = analyzer.run()
    
    if results['success']:
        print("\n[+] Analysis complete")
        print(f"Risk: {results['data']['risk_assessment']['level']}")
        print(f"Findings: {len(results['data']['suspicious_strings'])} suspicious strings")
    else:
        print(f"[-] Error: {results['error']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
