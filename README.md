# 🔍 SQL Injection (SQLi) Log Detection Engine

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Security Level](https://img.shields.io/badge/security-SIEM%20Analytics-red.svg)](#)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-A03%3A2021--Injection-green.svg)](https://owasp.org/)

A SIEM-capable log analytics and SQL Injection (SQLi) threat detection engine written in Python. Parses web server access logs (Apache, Nginx, Flask), applies multi-pattern detection signatures, decodes URL-encoded payloads, calculates anomaly thresholds per source IP, and outputs structured alert reports.

---

## 📌 Executive Overview

SQL Injection remains one of the most critical threats to web application databases. Attackers frequently test payloads via query strings and POST forms, leaving signatures in web server log files.

This engine automates log threat hunting:
1. **Multi-Format Log Parsing**: Parses standard Combined Log Format (CLF), Nginx access logs, and JSON logs.
2. **Payload Decoding**: Normalizes hex, URL-encoded, and unicode payloads to reveal obfuscated injection strings.
3. **Comprehensive Pattern Rules**:
   - **Error-Based SQLi**: Identifies single quote escapes, syntax errors, `UNION SELECT`.
   - **Boolean / Blind SQLi**: Detects `OR 1=1`, `AND 1=1`, `HAVING 1=1`.
   - **Time-Based Blind SQLi**: Flags SQL sleeping functions (`SLEEP()`, `WAITFOR DELAY`, `pg_sleep()`).
   - **Stacked Queries**: Detects inline statement terminators (`; DROP TABLE`, `; UPDATE`).
4. **IP Anomaly Scoring**: Aggregates attack frequencies per client IP to flag automated vulnerability scanners (e.g. `sqlmap`).

---

## ✨ Advanced Features

- 📜 **Log Parsing Engine**: Flexible regex-based log parsing for web access logs.
- 🔓 **Deep Payload Unpacking**: Decodes URL-encoded payload layers.
- 🎯 **Advanced Heuristic Signature Rules**: Pre-configured signature sets targeting major database dialects (MySQL, PostgreSQL, MSSQL, SQLite, Oracle).
- 📊 **Attacker IP Profiling**: Groups suspicious transactions by source IP and generates risk scores.
- 📄 **JSON Alert Export**: Writes alerts to `sqli_alerts.json` for ingestion into SIEM platforms.

---

## 🏗️ Processing Workflow

```
 [ Web Access Logs (Apache / Nginx / Flask) ]
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    SQLInjectionDetector Engine                          │
├─────────────────────────────────────────────────────────────────────────┤
│  1. Parse Log Line Fields (IP, Timestamp, URI, Method)                  │
│  2. URL & Hex Decoding of Query Strings                                 │
│  3. Execute SQLi Heuristic Signature Rules                              │
│  4. Update Source IP Anomaly Counter                                    │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │
                 ┌─────────────────┴─────────────────┐
                 ▼                                   ▼
      [ Signature Matched ]                 [ Normal Request ]
                 │                                   │
                 ▼                                   ▼
        Generate SIEM Alert                  Ignore & Continue
        Write to `sqli_alerts.json`
```

---

## 📋 Prerequisites & Setup

- **Python 3.8+** (Standard library only; zero external third-party dependencies required).

---

## 🚀 Usage & Integration Guide

### 1. Direct Execution
```bash
python3 main.py
```

### 2. Programmatic Python Execution
```python
from main import SQLInjectionDetector

detector = SQLInjectionDetector()
log_line = '192.168.1.100 - - [22/Aug/2026:23:27:10 +0000] "GET /products.php?id=1%20UNION%20SELECT%201,username,password%20FROM%20users HTTP/1.1" 200 4523'

alert = detector.process_log_line(log_line)
if alert:
    print(f"🚨 SQLi Detected from IP: {alert['ip']} | Pattern: {alert['rule_matched']}")
```

---

## 📊 Sample Output Alert (`sqli_alerts.json`)

```json
{
  "timestamp": "2026-08-22T23:27:10Z",
  "ip": "192.168.1.100",
  "rule_matched": "Union-Based SQL Injection",
  "risk_score": 9,
  "payload": "1 UNION SELECT 1,username,password FROM users"
}
```

---

## 🛡️ OWASP Alignment & Threat Mitigation Matrix

| Threat Vector | Attack Description | Engine Countermeasure |
|---|---|---|
| **SQL Injection** | Attacker extracts database tables via query string parameters. | Decodes URL payloads and flags SQL keywords & comment tokens. |
| **Obfuscated Injection** | Attacker hex-encodes payload to bypass web firewalls. | Recursively decodes hex/URL strings before pattern matching. |
