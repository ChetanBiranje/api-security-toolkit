# 🔐 API Security Testing Toolkit

A comprehensive Python-based security automation toolkit for REST API penetration testing, vulnerability detection, and security analysis.

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen)](CONTRIBUTING.md)

## 🎯 Features

- **JWT Analyzer** - Decode, validate, and identify vulnerabilities in JWT tokens
- **IDOR/BOLA Detector** - Automated testing for Broken Object Level Authorization
- **Mass Assignment Scanner** - Detect mass assignment vulnerabilities in APIs
- **Authorization Tester** - Test privilege escalation and broken access control
- **API Fuzzer** - Automated endpoint discovery and parameter fuzzing
- **Authentication Bypass** - Test common authentication bypass techniques

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/ChetanBiranje/api-security-toolkit.git
cd api-security-toolkit
pip install -r requirements.txt
```

### Basic Usage

```python
# JWT Analysis
python jwt_analyzer.py --token "eyJhbGc..."

# IDOR Detection
python idor_detector.py --url https://api.example.com/users --param id

# Mass Assignment Testing
python mass_assignment.py --url https://api.example.com/users/1 --method PUT

# Full API Scan
python api_scanner.py --url https://api.example.com --wordlist endpoints.txt
```

## 🛠️ Tools Included

### 1. JWT Analyzer (`jwt_analyzer.py`)
Analyzes JWT tokens for common vulnerabilities:
- Algorithm confusion attacks
- Weak HMAC secrets
- Missing signature validation
- Expired token handling
- Claims manipulation

**Example Output:**
```
[+] Token decoded successfully
[+] Algorithm: HS256
[!] VULNERABILITY: Token accepts 'none' algorithm
[!] VULNERABILITY: Weak HMAC secret detected
[+] Claims: {'user_id': 123, 'role': 'user', 'exp': 1234567890}
```

### 2. IDOR/BOLA Detector (`idor_detector.py`)
Tests for Broken Object Level Authorization:
- Sequential ID enumeration
- GUID prediction
- Parameter tampering
- Object reference manipulation

**Usage:**
```bash
python idor_detector.py \
  --url https://api.example.com/users/{id} \
  --cookies "session=abc123" \
  --range 1-1000
```

### 3. Mass Assignment Scanner (`mass_assignment.py`)
Detects mass assignment vulnerabilities:
- Identifies hidden parameters
- Tests privilege escalation via parameter injection
- Automated payload generation

### 4. Authorization Tester (`authz_tester.py`)
Comprehensive authorization testing:
- Horizontal privilege escalation
- Vertical privilege escalation
- Role-based access control bypass
- API endpoint enumeration

### 5. API Fuzzer (`api_fuzzer.py`)
Automated API discovery and fuzzing:
- Endpoint enumeration
- Parameter discovery
- HTTP method testing
- Response analysis

## 📋 Requirements

```txt
requests==2.31.0
pyjwt==2.8.0
colorama==0.4.6
urllib3==2.1.0
python-dotenv==1.0.0
```

## 🎓 Educational Purpose

This toolkit is designed for:
- Security professionals conducting authorized penetration tests
- Developers learning about API security
- Bug bounty hunters (with proper authorization)
- Security researchers

**⚠️ DISCLAIMER:** This tool is for educational and authorized testing purposes only. Always obtain proper authorization before testing any system.

## 📖 Documentation

Detailed documentation for each tool:
- [JWT Analyzer Guide](docs/jwt_analyzer.md)
- [IDOR Detection Guide](docs/idor_detector.md)
- [Mass Assignment Guide](docs/mass_assignment.md)
- [Authorization Testing Guide](docs/authz_tester.md)

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📝 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 👤 Author

**Chetan Biranje**
- LinkedIn: [@chetan-biranje](https://linkedin.com/in/chetan-biranje)
- GitHub: [@ChetanBiranje](https://github.com/ChetanBiranje)
- Email: chetanbiranje@proton.me

## 🙏 Acknowledgments

- OWASP API Security Top 10
- PortSwigger Web Security Academy
- Bug Bounty Community

---

⭐ Star this repository if you find it helpful!

**Note:** This toolkit is continuously updated with new features and improvements. Check back regularly for updates!
