# API Security Automation Toolkit

🔒 A comprehensive Python-based security testing framework for REST APIs that automates vulnerability discovery and security assessments.

## 🌟 Features

- **🔍 JWT Token Analysis**: Comprehensive JWT security testing including algorithm verification, expiration checks, and weak secret detection
- **🔑 Authentication Testing**: Brute force protection testing, default credential checks, and session fixation detection
- **🚪 Authorization Testing**: IDOR (Insecure Direct Object Reference) detection, privilege escalation testing
- **🎯 API Fuzzing**: Automated fuzzing with SQL injection, XSS, command injection, path traversal, and XXE payloads
- **📊 Automated Reporting**: Generate detailed security reports in JSON, HTML, and text formats
- **⚡ Rate Limit Testing**: Verify API rate limiting mechanisms

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Quick Install

```bash
# Clone the repository
git clone https://github.com/ChetanBiranje/api-security-toolkit
cd api-security-toolkit

# Install dependencies
pip install -r requirements.txt
```

## 🚀 Quick Start

### 1. JWT Token Analysis

```python
from api_toolkit import JWTAnalyzer

analyzer = JWTAnalyzer()
result = analyzer.check_jwt("your-jwt-token-here")

print(f"Valid: {result['valid']}")
print(f"Vulnerabilities: {result['vulnerabilities']}")
print(f"Recommendations: {result['recommendations']}")
```

### 2. Authentication Testing

```python
from api_toolkit import AuthenticationTester

auth_tester = AuthenticationTester(base_url="https://api.example.com")

# Test brute force protection
brute_force_result = auth_tester.test_brute_force_protection(
    endpoint="/auth/login",
    username="test@example.com",
    max_attempts=10
)

# Test for default credentials
default_creds_result = auth_tester.test_default_credentials(
    endpoint="/auth/login"
)
```

### 3. IDOR Testing

```python
from api_toolkit import AuthorizationTester

auth_z_tester = AuthorizationTester(base_url="https://api.example.com")

# Test for IDOR vulnerabilities
idor_result = auth_z_tester.test_idor(
    endpoint_template="/api/users/{id}",
    valid_token="your-auth-token",
    test_range=range(1, 100)
)

if idor_result['vulnerable']:
    print(f"⚠️ IDOR vulnerability found!")
    print(f"Accessible IDs: {idor_result['accessible_ids']}")
```

### 4. API Fuzzing

```python
from api_toolkit import APIFuzzer

fuzzer = APIFuzzer(base_url="https://api.example.com")

# Fuzz an endpoint
fuzz_results = fuzzer.fuzz_endpoint(
    endpoint="/api/search",
    method="POST",
    parameters=["query", "filter", "sort"]
)

print(f"Vulnerabilities found: {len(fuzz_results['vulnerabilities'])}")
```

### 5. Generate Security Report

```python
from api_toolkit import SecurityReporter

reporter = SecurityReporter()

# Add findings
reporter.add_finding(
    category="Authentication",
    severity="HIGH",
    title="Weak JWT Secret",
    description="JWT tokens are signed with a weak secret key",
    recommendation="Use strong, randomly generated secrets (256-bit minimum)"
)

# Generate report
html_report = reporter.generate_report(format='html')
with open('security_report.html', 'w') as f:
    f.write(html_report)
```

## 📚 Complete Usage Examples

### Full Security Assessment

```python
from api_toolkit import (
    JWTAnalyzer, 
    AuthenticationTester, 
    AuthorizationTester,
    APIFuzzer,
    SecurityReporter,
    RateLimitTester
)

# Initialize components
base_url = "https://api.example.com"
reporter = SecurityReporter()

# 1. Test JWT Security
jwt_analyzer = JWTAnalyzer()
token = "your-jwt-token"
jwt_result = jwt_analyzer.check_jwt(token)

for vuln in jwt_result.get('vulnerabilities', []):
    reporter.add_finding(
        category="JWT Security",
        severity=vuln['severity'],
        title=vuln['type'],
        description=vuln['description']
    )

# 2. Test Authentication
auth_tester = AuthenticationTester(base_url)
bf_result = auth_tester.test_brute_force_protection("/auth/login")

if not bf_result['protected']:
    reporter.add_finding(
        category="Authentication",
        severity="HIGH",
        title="No Brute Force Protection",
        description="API does not implement brute force protection",
        recommendation="Implement rate limiting and account lockout mechanisms"
    )

# 3. Test Authorization (IDOR)
authz_tester = AuthorizationTester(base_url)
idor_result = authz_tester.test_idor(
    endpoint_template="/api/users/{id}",
    valid_token=token
)

if idor_result['vulnerable']:
    reporter.add_finding(
        category="Authorization",
        severity="HIGH",
        title="IDOR Vulnerability",
        description=f"Can access {len(idor_result['accessible_ids'])} unauthorized resources",
        recommendation="Implement proper authorization checks"
    )

# 4. Fuzz API Endpoints
fuzzer = APIFuzzer(base_url)
fuzz_result = fuzzer.fuzz_endpoint("/api/search", method="POST")

for vuln in fuzz_result['vulnerabilities']:
    reporter.add_finding(
        category="Input Validation",
        severity="HIGH",
        title=f"{vuln['attack_type']} Vulnerability",
        description=f"Vulnerable parameter: {vuln['param']}",
        recommendation="Implement input validation and sanitization"
    )

# 5. Test Rate Limiting
rate_tester = RateLimitTester(base_url)
rate_result = rate_tester.test_rate_limit("/api/search")

if not rate_result['protected']:
    reporter.add_finding(
        category="Rate Limiting",
        severity="MEDIUM",
        title="No Rate Limiting",
        description="API does not implement rate limiting",
        recommendation="Implement rate limiting to prevent abuse"
    )

# Generate comprehensive report
report = reporter.generate_report(format='html')
with open('full_security_report.html', 'w') as f:
    f.write(report)

print("✅ Security assessment complete! Report saved to full_security_report.html")
```

## 🔧 Advanced Configuration

### Custom Fuzzing Payloads

```python
from api_toolkit import APIFuzzer

fuzzer = APIFuzzer(base_url="https://api.example.com")

# Add custom payloads
fuzzer.payloads['custom_injection'] = [
    "'; DROP TABLE users--",
    "admin' OR '1'='1",
    "../../../custom/path"
]

# Run fuzzing
results = fuzzer.fuzz_endpoint("/api/vulnerable")
```

### JWT Secret Brute Force with Custom Dictionary

```python
from api_toolkit import JWTAnalyzer

analyzer = JWTAnalyzer()

# Add custom weak secrets
analyzer.weak_secrets.extend([
    'myapp_secret',
    'production_key_2024',
    'custom_weak_password'
])

result = analyzer.check_jwt(token)
```

## 🧪 Testing

Run the test suite:

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=api_toolkit tests/

# Run specific test file
pytest tests/test_jwt_analyzer.py
```

## 📊 Sample Report Output

### Severity Breakdown
- **CRITICAL**: Issues requiring immediate attention (e.g., no signature JWT, weak secrets)
- **HIGH**: Serious vulnerabilities (e.g., IDOR, SQL injection, missing expiration)
- **MEDIUM**: Important security concerns (e.g., no rate limiting, long token validity)
- **LOW**: Minor issues and best practice violations
- **INFO**: Informational findings and recommendations

## 🛡️ Security Best Practices

1. **JWT Security**
   - Use asymmetric algorithms (RS256, ES256)
   - Implement short token expiration times
   - Never store sensitive data in JWT payload
   - Use strong, randomly generated secrets (256-bit minimum)

2. **Authentication**
   - Implement brute force protection
   - Use multi-factor authentication
   - Enforce strong password policies
   - Implement session timeout

3. **Authorization**
   - Always verify user permissions
   - Implement proper access controls
   - Use UUIDs instead of sequential IDs
   - Validate authorization on every request

4. **Input Validation**
   - Sanitize all user inputs
   - Use parameterized queries
   - Implement content type validation
   - Encode outputs properly

5. **Rate Limiting**
   - Implement per-user and per-IP rate limits
   - Use exponential backoff
   - Monitor and log rate limit violations

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Contribution Guidelines

- Write clear, descriptive commit messages
- Add tests for new features
- Update documentation as needed
- Follow PEP 8 style guidelines
- Ensure all tests pass before submitting PR

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before testing any system you do not own. Unauthorized access to computer systems is illegal.

## 🔗 Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc8725)
- [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist)

## 📧 Contact

Chetan Biranje - [@ChetanBiranje](https://github.com/ChetanBiranje)

Project Link: [https://github.com/ChetanBiranje/api-security-toolkit](https://github.com/ChetanBiranje/api-security-toolkit)

## 🙏 Acknowledgments

- OWASP for security testing methodologies
- JWT.io for JWT resources
- Security community for vulnerability research

---

**Made with ❤️ by Chetan Biranje**
