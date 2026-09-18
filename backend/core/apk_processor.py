#!/usr/bin/env python3
"""
DroidForensix APK Processor
Orchestrates the 7-step malware analysis pipeline.

Pipeline:
1. Static Analysis (Androguard) → metadata, permissions, FCM, native libs
2. String Extraction → suspicious strings, URLs, IPs
3. Entropy Analysis → packed/encoded detection
4. Encoding Detection → base64, hex, custom encodings
5. Payload Decoding → extract obfuscated payloads
6. C2 Extraction → domain/IP extraction from native libs + strings
7. Threat Chain Correlation → LLM-based severity + YARA rules + indicators

Usage:
    processor = APKProcessor("path/to/apk")
    results = processor.process()
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib
import json

logger = logging.getLogger(__name__)


@dataclass
class ProcessorConfig:
    """Configuration for APK processor"""
    cache_dir: Path = Path("./cache")
    deep_analysis: bool = True
    skip_frida: bool = True  # Dynamic analysis disabled by default
    timeout: int = 60  # seconds per step
    enable_yara: bool = True
    llm_model: str = "llama2:latest"


class APKProcessor:
    """Orchestrates the full analysis pipeline"""
    
    def __init__(
        self,
        apk_path: str,
        config: Optional[ProcessorConfig] = None
    ):
        self.apk_path = Path(apk_path)
        self.config = config or ProcessorConfig()
        self.apk_hash = self._compute_hash()
        self.results = {
            'metadata': {
                'file': str(self.apk_path),
                'hash': self.apk_hash,
                'timestamp': datetime.now().isoformat(),
                'pipeline_version': '2.0'
            },
            'steps': {}
        }
    
    def _compute_hash(self) -> str:
        """Compute SHA-256 hash of APK for caching"""
        sha256 = hashlib.sha256()
        with open(self.apk_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _get_cache_path(self, step_name: str) -> Path:
        """Get cache file path for a step"""
        cache_file = self.config.cache_dir / step_name / f"{self.apk_hash}.json"
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        return cache_file
    
    def _load_from_cache(self, step_name: str) -> Optional[Dict]:
        """Load step results from cache if available"""
        cache_file = self._get_cache_path(step_name)
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    logger.info(f"[{step_name}] Loading from cache")
                    return json.load(f)
            except Exception as e:
                logger.warning(f"[{step_name}] Cache load failed: {e}")
        return None
    
    def _save_to_cache(self, step_name: str, data: Dict) -> None:
        """Save step results to cache"""
        cache_file = self._get_cache_path(step_name)
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            logger.debug(f"[{step_name}] Saved to cache")
        except Exception as e:
            logger.warning(f"[{step_name}] Cache save failed: {e}")
    
    def step_1_androguard_analysis(self) -> Dict[str, Any]:
        """
        Step 1: Static Analysis (Androguard)
        
        Outputs:
        - APK metadata (permissions, version, SDK targets)
        - FCM components (C2 capability)
        - Native libraries (native code present)
        - JNI methods (native entry points)
        - Obfuscated classes
        - Suspicious strings
        """
        
        # Check cache
        cached = self._load_from_cache('androguard')
        if cached:
            return cached
        
        logger.info("[Step 1/7] Running Androguard static analysis...")
        
        try:
            from backend.core.androguard_analyzer import APKAnalyzer
            
            analyzer = APKAnalyzer(
                str(self.apk_path),
                deep_analysis=self.config.deep_analysis
            )
            result = analyzer.run()
            
            if not result['success']:
                return {'error': result['error'], 'success': False}
            
            step_result = {
                'success': True,
                'data': result['data']
            }
            
            self._save_to_cache('androguard', step_result)
            return step_result
            
        except ImportError:
            return {
                'success': False,
                'error': 'androguard not installed. Run: pip install androguard'
            }
        except Exception as e:
            logger.error(f"[Step 1] Failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def step_2_string_extraction(self, androguard_data: Dict) -> Dict[str, Any]:
        """
        Step 2: String Extraction & Analysis
        
        Inputs from Step 1:
        - All strings from DEX
        - Suspicious strings (already flagged)
        - Native library strings
        
        Outputs:
        - Deduplicated strings
        - Network indicators (URLs, IPs)
        - Package names
        - Firebase/C2 indicators
        """
        
        cached = self._load_from_cache('string_extraction')
        if cached:
            return cached
        
        logger.info("[Step 2/7] Extracting and analyzing strings...")
        
        try:
            strings_data = {
                'suspicious_strings': androguard_data['suspicious_strings'],
                'native_strings': androguard_data['native_strings'],
                'network_indicators': {
                    'urls': [],
                    'ipv4_addresses': []
                },
                'package_names': [],
                'c2_indicators': []
            }
            
            # Extract network indicators from suspicious strings
            import re
            for item in androguard_data['suspicious_strings']:
                value = item['value']
                
                if item['category'] == 'urls':
                    strings_data['network_indicators']['urls'].append(value)
                elif item['category'] == 'ip_addresses':
                    strings_data['network_indicators']['ipv4_addresses'].append(value)
                elif item['category'] == 'package_names':
                    strings_data['package_names'].append(value)
            
            # Extract C2 indicators from native strings
            for native_str in androguard_data['native_strings']:
                if native_str['type'] in ['c2_indicator', 'url']:
                    strings_data['c2_indicators'].append(native_str['value'])
            
            step_result = {
                'success': True,
                'data': strings_data
            }
            
            self._save_to_cache('string_extraction', step_result)
            return step_result
            
        except Exception as e:
            logger.error(f"[Step 2] Failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def step_3_entropy_analysis(self, androguard_data: Dict) -> Dict[str, Any]:
        """
        Step 3: Entropy Analysis
        
        Purpose: Detect packed/encoded/suspicious native code
        
        Inputs:
        - Native library paths
        - Binary content metadata
        
        Outputs:
        - Entropy scores per binary
        - Packed status
        - Encryption indicators
        """
        
        cached = self._load_from_cache('entropy_analysis')
        if cached:
            return cached
        
        logger.info("[Step 3/7] Performing entropy analysis...")
        
        try:
            import struct
            import zipfile
            
            entropy_data = {
                'native_libs': []
            }
            
            # Analyze native library entropy
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                for lib in androguard_data['native_libs']:
                    lib_path = lib['path']
                    try:
                        lib_content = z.read(lib_path)
                        entropy = self._calculate_entropy(lib_content)
                        
                        is_packed = entropy > 7.5  # High entropy suggests compression/encryption
                        
                        entropy_data['native_libs'].append({
                            'path': lib_path,
                            'name': lib['name'],
                            'size': len(lib_content),
                            'entropy': round(entropy, 2),
                            'packed': is_packed
                        })
                    except Exception as e:
                        logger.debug(f"Entropy calc failed for {lib_path}: {e}")
            
            step_result = {
                'success': True,
                'data': entropy_data
            }
            
            self._save_to_cache('entropy_analysis', step_result)
            return step_result
            
        except Exception as e:
            logger.error(f"[Step 3] Failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def step_4_encoding_detection(self, strings_data: Dict) -> Dict[str, Any]:
        """
        Step 4: Encoding Detection
        
        Purpose: Identify custom encodings and obfuscation
        
        Inputs:
        - Suspicious strings
        - Network indicators
        
        Outputs:
        - Base64 encoded strings
        - Hex encoded strings
        - Custom encoding patterns
        """
        
        cached = self._load_from_cache('encoding_detection')
        if cached:
            return cached
        
        logger.info("[Step 4/7] Detecting encoding schemes...")
        
        try:
            import base64
            
            encoding_data = {
                'base64_candidates': [],
                'hex_candidates': [],
                'custom_patterns': []
            }
            
            for item in strings_data['suspicious_strings']:
                value = item['value']
                
                # Check for base64
                if self._is_base64(value):
                    encoding_data['base64_candidates'].append({
                        'encoded': value,
                        'category': item['category']
                    })
                
                # Check for hex
                if self._is_hex(value):
                    encoding_data['hex_candidates'].append({
                        'encoded': value,
                        'category': item['category']
                    })
            
            step_result = {
                'success': True,
                'data': encoding_data
            }
            
            self._save_to_cache('encoding_detection', step_result)
            return step_result
            
        except Exception as e:
            logger.error(f"[Step 4] Failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def step_5_payload_decoding(self, encoding_data: Dict) -> Dict[str, Any]:
        """
        Step 5: Payload Decoding
        
        Purpose: Decode and extract obfuscated payloads
        
        Inputs:
        - Base64 candidates
        - Hex candidates
        
        Outputs:
        - Decoded payloads
        - Secondary URLs/IPs
        - Commands or configuration data
        """
        
        cached = self._load_from_cache('payload_decoding')
        if cached:
            return cached
        
        logger.info("[Step 5/7] Decoding payloads...")
        
        try:
            import base64
            
            payload_data = {
                'decoded_payloads': [],
                'secondary_indicators': []
            }
            
            # Attempt to decode base64 payloads
            for item in encoding_data['base64_candidates']:
                try:
                    decoded = base64.b64decode(item['encoded']).decode('utf-8', errors='ignore')
                    # Check if decoded output looks meaningful
                    if len(decoded) > 5 and any(c.isalnum() for c in decoded):
                        payload_data['decoded_payloads'].append({
                            'encoded': item['encoded'][:50],  # Truncate for display
                            'decoded': decoded[:100],
                            'type': 'base64'
                        })
                except Exception:
                    logger.debug("Failed to decode base64 payload: %s", item['encoded'][:30])
            
            step_result = {
                'success': True,
                'data': payload_data
            }
            
            self._save_to_cache('payload_decoding', step_result)
            return step_result
            
        except Exception as e:
            logger.error(f"[Step 5] Failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def step_6_c2_extraction(
        self,
        androguard_data: Dict,
        strings_data: Dict
    ) -> Dict[str, Any]:
        """
        Step 6: C2 Extraction
        
        Purpose: Extract command & control infrastructure
        
        Inputs:
        - Native library strings
        - Network indicators
        - FCM components
        
        Outputs:
        - C2 domains
        - C2 IPs
        - FCM C2 channels
        - API endpoints
        """
        
        cached = self._load_from_cache('c2_extraction')
        if cached:
            return cached
        
        logger.info("[Step 6/7] Extracting C2 infrastructure...")
        
        try:
            c2_data = {
                'c2_domains': [],
                'c2_ips': [],
                'fcm_channels': [],
                'api_endpoints': [],
                'confidence_score': 0
            }
            
            # Extract domains and IPs
            urls = strings_data['network_indicators']['urls']
            ips = strings_data['network_indicators']['ipv4_addresses']
            
            for url in urls:
                c2_data['c2_domains'].append({
                    'domain': url,
                    'source': 'string_extraction'
                })
            
            for ip in ips:
                c2_data['c2_ips'].append({
                    'ip': ip,
                    'source': 'string_extraction'
                })
            
            # FCM channels
            for component in androguard_data['fcm_components']:
                c2_data['fcm_channels'].append({
                    'component': component['name'],
                    'type': component['type'],
                    'exported': component['exported']
                })
            
            # Calculate confidence
            c2_data['confidence_score'] = min(
                (len(c2_data['c2_domains']) + len(c2_data['c2_ips']) + 
                 len(c2_data['fcm_channels'])) / 5.0,
                1.0
            )
            
            step_result = {
                'success': True,
                'data': c2_data
            }
            
            self._save_to_cache('c2_extraction', step_result)
            return step_result
            
        except Exception as e:
            logger.error(f"[Step 6] Failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def step_7_threat_chain(
        self,
        androguard_data: Dict,
        c2_data: Dict
    ) -> Dict[str, Any]:
        """
        Step 7: Threat Chain Correlation & LLM Scoring
        
        Purpose: Correlate all findings into threat narrative
        
        Inputs:
        - All previous step results
        
        Outputs:
        - Threat narrative (text summary)
        - Severity score (0-100)
        - YARA rules
        - STIX indicators
        - Recommended actions
        """
        
        cached = self._load_from_cache('threat_chain')
        if cached:
            return cached
        
        logger.info("[Step 7/7] Correlating threat chain...")
        
        try:
            threat_data = {
                'threat_narrative': '',
                'severity_score': 0,
                'yara_rules': [],
                'stix_indicators': [],
                'recommendations': []
            }
            
            # Build threat narrative
            narrative = []
            
            risk_level = androguard_data['risk_assessment']['level']
            narrative.append(f"Overall Risk Level: {risk_level}")
            
            if androguard_data['fcm_components']:
                narrative.append(
                    f"Found {len(androguard_data['fcm_components'])} FCM components "
                    "suggesting push-based command & control capability"
                )
            
            if androguard_data['native_libs']:
                narrative.append(
                    f"Contains {len(androguard_data['native_libs'])} native libraries "
                    "indicating platform-specific functionality"
                )
            
            if androguard_data['jni_methods']:
                narrative.append(
                    f"Detected {len(androguard_data['jni_methods'])} JNI entry points "
                    "for native method invocation"
                )
            
            if c2_data['c2_domains'] or c2_data['c2_ips']:
                narrative.append(
                    f"Extracted {len(c2_data['c2_domains']) + len(c2_data['c2_ips'])} "
                    "command & control indicators"
                )
            
            threat_data['threat_narrative'] = '\n'.join(narrative)
            
            # Calculate severity score (0-100)
            base_score = androguard_data['risk_assessment']['score']
            threat_data['severity_score'] = min(base_score * 4, 100)
            
            # Generate simple YARA rule
            if androguard_data['obfuscated_classes']:
                threat_data['yara_rules'].append({
                    'rule_name': 'Android_Obfuscated_Malware',
                    'description': f"Detects APKs with {len(androguard_data['obfuscated_classes'])} obfuscated classes",
                    'severity': 'high'
                })
            
            # Recommendations
            if androguard_data['fcm_components']:
                threat_data['recommendations'].append(
                    "Intercept Firebase Cloud Messaging using Frida during dynamic analysis"
                )
            if androguard_data['native_libs']:
                threat_data['recommendations'].append(
                    "Extract and reverse-engineer native libraries for C2 communication"
                )
            
            step_result = {
                'success': True,
                'data': threat_data
            }
            
            self._save_to_cache('threat_chain', step_result)
            return step_result
            
        except Exception as e:
            logger.error(f"[Step 7] Failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def process(self) -> Dict[str, Any]:
        """
        Execute full 7-step pipeline
        """
        
        logger.info(f"Starting APK analysis: {self.apk_path}")
        logger.info(f"APK Hash: {self.apk_hash}")
        
        # Step 1
        step1 = self.step_1_androguard_analysis()
        if not step1['success']:
            return {'success': False, 'error': step1['error']}
        self.results['steps']['androguard'] = step1['data']
        androguard_data = step1['data']
        
        # Step 2
        step2 = self.step_2_string_extraction(androguard_data)
        if not step2['success']:
            return {'success': False, 'error': step2['error']}
        self.results['steps']['string_extraction'] = step2['data']
        strings_data = step2['data']
        
        # Step 3
        step3 = self.step_3_entropy_analysis(androguard_data)
        if step3['success']:
            self.results['steps']['entropy_analysis'] = step3['data']
        
        # Step 4
        step4 = self.step_4_encoding_detection(strings_data)
        if step4['success']:
            self.results['steps']['encoding_detection'] = step4['data']
        encoding_data = step4['data'] if step4['success'] else {}
        
        # Step 5
        step5 = self.step_5_payload_decoding(encoding_data)
        if step5['success']:
            self.results['steps']['payload_decoding'] = step5['data']
        
        # Step 6
        step6 = self.step_6_c2_extraction(androguard_data, strings_data)
        if step6['success']:
            self.results['steps']['c2_extraction'] = step6['data']
        c2_data = step6['data'] if step6['success'] else {}
        
        # Step 7
        step7 = self.step_7_threat_chain(androguard_data, c2_data)
        if step7['success']:
            self.results['steps']['threat_chain'] = step7['data']
        
        logger.info("Pipeline execution complete")
        
        return {
            'success': True,
            'data': self.results
        }
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of binary data"""
        import math
        if not data:
            return 0
        entropy = 0
        for i in range(256):
            freq = data.count(bytes([i]))
            if freq:
                entropy -= (freq / len(data)) * math.log2(freq / len(data))
        return entropy
    
    @staticmethod
    def _is_base64(s: str) -> bool:
        """Check if string looks like base64"""
        import re
        if len(s) < 8:
            return False
        return bool(re.match(r'^[A-Za-z0-9+/]*={0,2}$', s))
    
    @staticmethod
    def _is_hex(s: str) -> bool:
        """Check if string looks like hex"""
        if len(s) < 8 or len(s) % 2 != 0:
            return False
        try:
            int(s, 16)
            return True
        except ValueError:
            return False


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python apk_processor.py <path_to_apk>")
        sys.exit(1)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)-8s | %(message)s'
    )
    
    processor = APKProcessor(sys.argv[1])
    results = processor.process()
    
    if results['success']:
        print("\n[+] Analysis complete")
        severity = results['data']['steps']['threat_chain']['severity_score']
        print(f"Severity Score: {severity}/100")
    else:
        print(f"[-] Error: {results['error']}")
        sys.exit(1)
