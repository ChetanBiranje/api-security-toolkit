# API Security Automation Toolkit

Python framework for automated REST API security testing.

## Features
- JWT Analysis
- IDOR Detection  
- API Fuzzing
- Auth Testing

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```python
from api_toolkit import JWTAnalyzer
analyzer = JWTAnalyzer()
result = analyzer.check("token")
```

## License
MIT
