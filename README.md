# API Security Automation Toolkit

Comprehensive Python-based security testing framework for REST APIs.

## Features

- 🔍 JWT Token Analysis
- 🔑 Authentication Testing
- 🚪 Authorization & IDOR Detection
- 🎯 API Fuzzing
- 📊 Automated Reporting

## Installation
```bash
git clone https://github.com/ChetanBiranje/api-security-toolkit
cd api-security-toolkit
pip install -r requirements.txt
```

## Quick Start
```python
from api_toolkit import JWTAnalyzer

analyzer = JWTAnalyzer()
result = analyzer.check_jwt("your-token-here")
print(result)
```

## Usage

[Detailed examples]

## Contributing

Pull requests welcome!

## License

MIT
