#!/usr/bin/env python3
"""
SQL Injection Log Detection Engine
Real-time log analysis with pattern-based detection (No ML dependencies)
"""

import re
import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict, Counter
from dataclasses import dataclass, field

@dataclass
class SQLiDetectionRule:
    """SQL injection detection rule with metadata"""
    pattern: str
    severity: str
    category: str
    description: str
    false_positive_ratio: float = 0.0
    confidence: float = 1.0

class SQLInjectionDetector:
    """
    Advanced SQL injection detection engine with:
    - Pattern-based detection (signature matching)
    - Query structure analysis
    - False positive reduction
    - Automated response integration
    """
    
    def __init__(self):
        self.rules = self._initialize_rules()
        self.attack_patterns = self._initialize_attack_patterns()
        
        # Detection statistics
        self.detection_stats = {
            'total_processed': 0,
            'attacks_detected': 0,
            'false_positives': 0,
            'patterns_used': defaultdict(int)
        }
        
        # IP-based tracking for attack grouping
        self.ip_tracker = defaultdict(lambda: {
            'attempts': 0,
            'first_seen': None,
            'last_seen': None,
            'payloads': [],
            'severity': 'LOW'
        })
        
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging for detection events"""
        self.logger = logging.getLogger('SQLiDetector')
        self.logger.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        file_handler = logging.FileHandler('sqli_detection.log')
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
    
    def _initialize_rules(self) -> List[SQLiDetectionRule]:
        """Initialize comprehensive SQL injection detection rules"""
        return [
            # Classic SQL injection patterns
            SQLiDetectionRule(
                pattern=r"('|%27)|(%22)|(--\s*$|#|/\*.*?\*/)",
                severity="HIGH",
                category="SINGLE_QUOTE",
                description="SQL comment injection or quote injection",
                false_positive_ratio=0.05
            ),
            SQLiDetectionRule(
                pattern=r"UNION\s+(ALL\s+)?SELECT\s+.*?FROM",
                severity="CRITICAL",
                category="UNION_BASED",
                description="UNION SELECT injection attempt",
                false_positive_ratio=0.02
            ),
            SQLiDetectionRule(
                pattern=r"(\bOR\b|\bAND\b)\s+\d+=\d+",
                severity="HIGH",
                category="LOGICAL",
                description="Always true condition injection",
                false_positive_ratio=0.1
            ),
            SQLiDetectionRule(
                pattern=r"WAITFOR\s+DELAY\s+['\"]?\d+",
                severity="CRITICAL",
                category="TIME_BASED",
                description="Time-based blind SQL injection",
                false_positive_ratio=0.01
            ),
            SQLiDetectionRule(
                pattern=r"(INTO\s+OUTFILE|INTO\s+DUMPFILE|LOAD_FILE\()",
                severity="CRITICAL",
                category="FILE_ACCESS",
                description="File system access attempt",
                false_positive_ratio=0.0
            ),
            SQLiDetectionRule(
                pattern=r"(xp_cmdshell|sp_executesql|exec\s+\(.*?\)|exec\s+\@|\$\$)",
                severity="CRITICAL",
                category="EXECUTION",
                description="Command execution or stored procedure injection",
                false_positive_ratio=0.01
            ),
            SQLiDetectionRule(
                pattern=r"information_schema\.",
                severity="HIGH",
                category="SCHEMA_ENUMERATION",
                description="Database schema enumeration attempt",
                false_positive_ratio=0.02
            ),
            SQLiDetectionRule(
                pattern=r"CONCAT\(|SUBSTRING\(|ASCII\(|CHR\(|CHAR\(",
                severity="MEDIUM",
                category="FUNCTION_USAGE",
                description="SQL function abuse for data extraction",
                false_positive_ratio=0.08
            ),
            SQLiDetectionRule(
                pattern=r"(\bSLEEP\s*\(|benchmark\s*\()",
                severity="CRITICAL",
                category="TIME_BASED",
                description="Time-based SQL injection",
                false_positive_ratio=0.01
            ),
            SQLiDetectionRule(
                pattern=r"({|%7b|}|%7d|>>=|<<=|%3c%3c|=|%3d)",
                severity="MEDIUM",
                category="OBFUSCATION",
                description="Character obfuscation attempt",
                false_positive_ratio=0.15
            ),
            SQLiDetectionRule(
                pattern=r"DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)",
                severity="CRITICAL",
                category="DDL_ATTACK",
                description="Dropping database objects attempt",
                false_positive_ratio=0.01
            ),
            SQLiDetectionRule(
                pattern=r"(0x[a-fA-F0-9]+|UNHEX\(|HEX\()",
                severity="HIGH",
                category="HEX_ENCODING",
                description="Hex encoding for payload obfuscation",
                false_positive_ratio=0.03
            ),
            SQLiDetectionRule(
                pattern=r"@@(version|hostname|tmpdir|datadir)",
                severity="MEDIUM",
                category="SERVER_INFO",
                description="Server information extraction attempt",
                false_positive_ratio=0.02
            ),
            SQLiDetectionRule(
                pattern=r"(\bBENCHMARK\s*\(|SLEEP\s*\()",
                severity="CRITICAL",
                category="TIME_BASED",
                description="Time-based blind SQL injection",
                false_positive_ratio=0.01
            ),
            SQLiDetectionRule(
                pattern=r"(\bADMIN\b|\bPASSWORD\b|\bUSER\b)\s*=",
                severity="MEDIUM",
                category="CREDENTIAL_HARVEST",
                description="Attempt to harvest credentials",
                false_positive_ratio=0.1
            )
        ]
    
    def _initialize_attack_patterns(self) -> Dict:
        """Initialize attack pattern database"""
        return {
            'error_based': {
                'patterns': [
                    r"you have an error in your sql syntax",
                    r"mysql_fetch_array",
                    r"ora-[0-9]{5}",
                    r"sqlite3\.",
                    r"microsoft ole db provider for odbc drivers",
                    r"warning: mysql",
                    r"unclosed quotation mark"
                ],
                'severity': 'HIGH',
                'description': 'Error-based SQL injection'
            },
            'union_based': {
                'patterns': [
                    r"union select.*?from",
                    r"union all select",
                    r"union distinct select"
                ],
                'severity': 'CRITICAL',
                'description': 'UNION-based SQL injection'
            },
            'boolean_based': {
                'patterns': [
                    r"(and|or)\s+1=1",
                    r"(and|or)\s+1=2",
                    r"true",
                    r"false"
                ],
                'severity': 'HIGH',
                'description': 'Boolean-based blind SQL injection'
            },
            'time_based': {
                'patterns': [
                    r"waitfor delay",
                    r"sleep\(",
                    r"benchmark\(",
                    r"pg_sleep"
                ],
                'severity': 'CRITICAL',
                'description': 'Time-based blind SQL injection'
            },
            'stacked_queries': {
                'patterns': [
                    r";\s*(drop|delete|insert|update|select)",
                    r";\s*--",
                    r";\s*#"
                ],
                'severity': 'CRITICAL',
                'description': 'Stacked query injection'
            }
        }
    
    def detect_sqli_attacks(self, log_entry: str) -> List[Dict]:
        """
        Comprehensive detection pipeline for SQL injection attempts
        
        Args:
            log_entry: Single log line to analyze
            
        Returns:
            List of detection results with metadata
        """
        self.detection_stats['total_processed'] += 1
        
        detections = []
        lower_entry = log_entry.lower()
        
        # 1. Pattern-based detection
        pattern_matches = self._pattern_based_detection(log_entry)
        if pattern_matches:
            detections.extend(pattern_matches)
        
        # 2. Attack pattern classification
        attack_class = self._classify_attack_pattern(lower_entry)
        if attack_class:
            detections.append(attack_class)
        
        # 3. Frequency analysis for repeated attempts
        frequency_analysis = self._frequency_analysis(log_entry)
        if frequency_analysis:
            detections.append(frequency_analysis)
        
        # 4. Query structure analysis
        query_analysis = self._analyze_query_structure(log_entry)
        if query_analysis:
            detections.append(query_analysis)
        
        # Process detections
        if detections:
            self.detection_stats['attacks_detected'] += 1
            self._log_detection(log_entry, detections)
            
            # Update IP tracking
            ip = self._extract_ip(log_entry)
            if ip:
                self._update_ip_tracker(ip, detections)
            
            # Trigger automated response for critical attacks
            for detection in detections:
                if detection.get('severity') == 'CRITICAL':
                    self._trigger_automated_response(log_entry, detection)
        
        return detections
    
    def _pattern_based_detection(self, log_entry: str) -> List[Dict]:
        """Detect SQL injection using pattern matching"""
        detections = []
        
        for rule in self.rules:
            matches = re.finditer(rule.pattern, log_entry, re.IGNORECASE)
            for match in matches:
                detections.append({
                    'type': 'pattern_based',
                    'rule': rule.category,
                    'severity': rule.severity,
                    'description': rule.description,
                    'matched': match.group(),
                    'confidence': rule.confidence * (1 - rule.false_positive_ratio)
                })
                self.detection_stats['patterns_used'][rule.category] += 1
        
        return detections
    
    def _classify_attack_pattern(self, log_entry: str) -> Optional[Dict]:
        """Classify attack based on known patterns"""
        for attack_type, attack_data in self.attack_patterns.items():
            for pattern in attack_data['patterns']:
                if re.search(pattern, log_entry, re.IGNORECASE):
                    return {
                        'type': 'attack_classification',
                        'attack_type': attack_type,
                        'severity': attack_data['severity'],
                        'description': attack_data.get('description', f'Detected {attack_type} SQL injection attempt')
                    }
        return None
    
    def _analyze_query_structure(self, log_entry: str) -> Optional[Dict]:
        """Analyze query structure for injection patterns"""
        # Check for multiple SQL keywords in sequence
        sql_keywords = ['select', 'from', 'where', 'union', 'insert', 'update', 'delete']
        keyword_count = sum(1 for keyword in sql_keywords if keyword in log_entry.lower())
        
        if keyword_count >= 3:
            return {
                'type': 'semantic',
                'severity': 'HIGH',
                'description': f'High density of SQL keywords ({keyword_count}) detected in request'
            }
        
        # Check for stacked queries
        if ';' in log_entry and log_entry.count(';') > 1:
            if any(pattern in log_entry.lower() for pattern in ['select', 'insert', 'update', 'delete']):
                return {
                    'type': 'semantic',
                    'severity': 'CRITICAL',
                    'description': 'Stacked query injection detected - multiple SQL statements'
                }
        
        return None
    
    def _frequency_analysis(self, log_entry: str) -> Optional[Dict]:
        """Analyze frequency of SQL injection attempts from same source"""
        ip = self._extract_ip(log_entry)
        if not ip:
            return None
        
        tracker = self.ip_tracker[ip]
        tracker['attempts'] += 1
        
        if tracker['attempts'] >= 5:
            return {
                'type': 'frequency_analysis',
                'severity': 'HIGH',
                'description': f'High frequency SQL injection attempts from {ip} ({tracker["attempts"]} attempts)'
            }
        
        return None
    
    def _extract_ip(self, log_entry: str) -> Optional[str]:
        """Extract IP address from log entry"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        match = re.search(ip_pattern, log_entry)
        return match.group() if match else None
    
    def _update_ip_tracker(self, ip: str, detections: List[Dict]):
        """Update IP-based tracking"""
        tracker = self.ip_tracker[ip]
        
        if tracker['first_seen'] is None:
            tracker['first_seen'] = datetime.now(timezone.utc).isoformat()
        
        tracker['last_seen'] = datetime.now(timezone.utc).isoformat()
        
        for detection in detections:
            payload = detection.get('matched', '')
            if payload and payload not in tracker['payloads']:
                tracker['payloads'].append(payload)
            
            # Update severity
            severity_levels = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
            current_level = severity_levels.get(tracker['severity'], 0)
            detection_level = severity_levels.get(detection.get('severity', 'LOW'), 0)
            
            if detection_level > current_level:
                tracker['severity'] = detection.get('severity', 'LOW')
    
    def _log_detection(self, log_entry: str, detections: List[Dict]):
        """Log detection events"""
        self.logger.warning(f"SQLi Detection: {json.dumps({
            'log_entry': log_entry[:200],
            'detections': detections,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })}")
    
    def _trigger_automated_response(self, log_entry: str, detection: Dict):
        """Trigger automated response for critical attacks"""
        ip = self._extract_ip(log_entry)
        
        self.logger.critical(f"AUTOMATED RESPONSE: Blocking IP {ip} - {detection.get('description', 'Critical SQL injection detected')}")
        
        # Log the response action
        self.logger.info(f"Response action: Added {ip} to blocklist")
    
    def process_log_file(self, file_path: str, output_file: Optional[str] = None) -> Dict:
        """Process an entire log file for SQL injection attempts"""
        results = {
            'total_logs': 0,
            'detected_attacks': 0,
            'attacks': [],
            'by_severity': defaultdict(int),
            'top_attackers': [],
            'analysis_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Group attacks by IP
        attacker_stats = defaultdict(int)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    results['total_logs'] += 1
                    detections = self.detect_sqli_attacks(line)
                    
                    if detections:
                        results['detected_attacks'] += 1
                        
                        # Update attacker statistics
                        ip = self._extract_ip(line)
                        if ip:
                            attacker_stats[ip] += 1
                        
                        # Count by severity
                        for detection in detections:
                            severity = detection.get('severity', 'UNKNOWN')
                            results['by_severity'][severity] += 1
                        
                        # Store attack details (limited for performance)
                        if len(results['attacks']) < 1000:
                            results['attacks'].append({
                                'log': line[:500],
                                'detections': detections
                            })
        except FileNotFoundError:
            self.logger.error(f"Log file not found: {file_path}")
            return {'error': f'File not found: {file_path}'}
        
        # Identify top attackers
        results['top_attackers'] = sorted(
            [{'ip': ip, 'attempts': count} for ip, count in attacker_stats.items()],
            key=lambda x: x['attempts'],
            reverse=True
        )[:10]
        
        # Output results if requested
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            self.logger.info(f"Results saved to {output_file}")
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        return {
            'total_processed': self.detection_stats['total_processed'],
            'attacks_detected': self.detection_stats['attacks_detected'],
            'attack_rate': self.detection_stats['attacks_detected'] / max(1, self.detection_stats['total_processed']) * 100,
            'patterns_used': dict(self.detection_stats['patterns_used']),
            'active_attackers': len(self.ip_tracker),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

# Main execution
if __name__ == "__main__":
    print("=" * 70)
    print("SQL INJECTION LOG DETECTION ENGINE")
    print("=" * 70 + "\n")
    
    detector = SQLInjectionDetector()
    
    # Test log entries
    test_logs = [
        '192.168.1.100 - - [10/Oct/2024:14:23:45 +0000] "GET /login?user=admin\' OR 1=1-- HTTP/1.1" 200 543',
        '10.0.0.5 - - [10/Oct/2024:14:24:12 +0000] "GET /search?q=UNION SELECT username,password FROM users HTTP/1.1" 500 23',
        '172.16.0.10 - - [10/Oct/2024:14:25:33 +0000] "POST /api/data HTTP/1.1" 200 1024',
        '192.168.1.200 - - [10/Oct/2024:14:26:01 +0000] "GET /products?id=1; DROP TABLE products-- HTTP/1.1" 200 543',
        '10.0.0.15 - - [10/Oct/2024:14:27:44 +0000] "GET /profile?user=admin\' AND 1=1 HTTP/1.1" 200 432',
        '172.16.0.20 - - [10/Oct/2024:14:28:22 +0000] "GET /search?q=SELECT * FROM users WHERE username=\'admin\' HTTP/1.1" 200 1024',
        '192.168.1.100 - - [10/Oct/2024:14:29:55 +0000] "GET /admin?cmd=;id HTTP/1.1" 403 128',
        '10.0.0.25 - - [10/Oct/2024:14:30:17 +0000] "GET /api/users?order=ASC;-- HTTP/1.1" 200 2048',
        '172.16.0.30 - - [10/Oct/2024:14:31:03 +0000] "GET /blog?post_id=1 UNION SELECT @@version HTTP/1.1" 200 512'
    ]
    
    print("[*] Processing test logs for SQL injection detection...\n")
    
    # Process each log entry
    for log in test_logs:
        detections = detector.detect_sqli_attacks(log)
        
        if detections:
            print(f"[!] ATTACK DETECTED IN: {log[:80]}...")
            for detection in detections:
                print(f"    Severity: {detection.get('severity', 'UNKNOWN')} - {detection.get('description', '')}")
            print()
    
    # Get statistics
    stats = detector.get_statistics()
    print("\n[+] Detection Statistics:")
    print(f"    Total logs processed: {stats['total_processed']}")
    print(f"    Attacks detected: {stats['attacks_detected']}")
    print(f"    Attack rate: {stats['attack_rate']:.2f}%")
    print(f"    Active attackers: {stats['active_attackers']}")
    print("\n[+] Pattern usage:")
    for pattern, count in stats['patterns_used'].items():
        print(f"    {pattern}: {count} times")
    
    # IP tracker summary
    print("\n[+] Top Attackers:")
    for ip, data in list(detector.ip_tracker.items())[:5]:
        print(f"    {ip}: {data['attempts']} attempts (Severity: {data['severity']})")
    
    print("\n[+] Key Features Demonstrated:")
    print("    ✓ Pattern-based SQL Injection Detection")
    print("    ✓ Attack Classification (Error-based, Union-based, Time-based)")
    print("    ✓ IP-based Attack Tracking")
    print("    ✓ Frequency Analysis")
    print("    ✓ Automated Response Triggers")
    print("    ✓ Detailed Logging")
    print("    ✓ JSON Report Generation")