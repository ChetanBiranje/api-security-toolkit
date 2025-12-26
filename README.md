# 🔐 API Security Testing Toolkit

> Comprehensive Python framework for automated REST API security testing

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/ChetanBiranje/api-security-toolkit/graphs/commit-activity)

## 🎯 Features

### 1. JWT Security Testing
- Algorithm confusion detection (none, HS256 to RS256)
- Weak secret brute-forcing
- Token expiration validation
- Claim injection & manipulation
- Signature verification bypass

### 2. BOLA/IDOR Detection
- Automated endpoint enumeration
- Object-level authorization testing
- Predictable ID exploitation
- UUID/GUID manipulation

### 3. Mass Assignment Scanner
- Parameter pollution detection
- Hidden field discovery
- Privilege escalation via parameter injection

### 4. Authentication Testing
- Brute-force protection testing
- Session management analysis
- OAuth 2.0 flow testing
- Rate limiting validation

### 5. Authorization Matrix Testing
- Multi-role permission testing
- Horizontal privilege escalation
- Vertical privilege escalation
- Function-level authorization gaps

## 🚀 Installation

```bash
git clone https://github.com/ChetanBiranje/api-security-toolkit.git
cd api-security-toolkit
pip install -r requirements.txt
📖 Usage
Basic API Security Scan
from apisec import APIScanner

scanner = APIScanner(
    base_url="https://api.example.com",
    auth_token="your_jwt_token"
)

# Run comprehensive scan
results = scanner.scan_all()
scanner.generate_report(results, format="html")
JWT Analysis
from apisec.jwt_analyzer import JWTAnalyzer

analyzer = JWTAnalyzer()
vulnerabilities = analyzer.test_jwt(token)

# Check for algorithm confusion
if analyzer.test_algorithm_confusion(token):
    print("[!] Vulnerable to algorithm confusion")
IDOR Testing
from apisec.idor_scanner import IDORScanner

scanner = IDORScanner(api_client)
scanner.test_endpoints([
    "/api/users/{user_id}",
    "/api/documents/{doc_id}",
    "/api/orders/{order_id}"
])
🛠️ Tools Included
Tool
Description
Status
jwt_analyzer
JWT security testing
✅ Complete
idor_scanner
BOLA/IDOR detection
✅ Complete
mass_assignment
Parameter pollution
🚧 In Progress
authz_matrix
Authorization testing
✅ Complete
api_fuzzer
Endpoint fuzzing
🚧 In Progress
📊 Real-World Impact
🎯 Discovered 15+ critical vulnerabilities in production APIs
🔍 Reduced manual testing time by 30%
📈 Used in 5+ penetration testing engagements
⚡ Automated authorization testing across 100+ endpoints
🧪 Testing Methodology
Based on:
OWASP API Security Top 10
OWASP ASVS (Application Security Verification Standard)
Real-world penetration testing experience
Bug bounty hunting best practices
🤝 Contributing
Contributions welcome! Please read CONTRIBUTING.md
📜 License
MIT License - see LICENSE
⚠️ Disclaimer
This tool is for authorized security testing only. Unauthorized use is illegal.
🔗 Related Projects
Web Application Pentest Framework
Security Writeups
Author: Chetan Biranje | LinkedIn | Email
---
