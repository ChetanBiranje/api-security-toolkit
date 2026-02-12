# Contributing to API Security Toolkit

First off, thank you for considering contributing to API Security Toolkit! It's people like you that make this tool better for the security community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

### Our Standards

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other contributors

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Basic understanding of API security concepts
- Familiarity with pytest for testing

### First Time Setup

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/api-security-toolkit.git
   cd api-security-toolkit
   ```

3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

5. Create a branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Python version, etc.)
- **Code samples** or error messages

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear title and description**
- **Use case** - why this enhancement would be useful
- **Possible implementation** if you have ideas
- **Alternative solutions** you've considered

### Adding New Features

Great features to contribute:

1. **New Security Tests**
   - OAuth vulnerabilities
   - API versioning security
   - CORS misconfiguration detection
   - XML External Entity (XXE) advanced tests

2. **Improved Reporting**
   - PDF report generation
   - CSV export for findings
   - Integration with security platforms

3. **Enhanced Detection**
   - Machine learning for anomaly detection
   - Better pattern matching for vulnerabilities
   - Custom payload libraries

4. **Documentation**
   - Tutorial videos
   - More code examples
   - Security best practices guide

## Development Setup

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=api_toolkit tests/

# Run specific test file
pytest tests/test_jwt_analyzer.py

# Run with verbose output
pytest -v tests/
```

### Code Style

We use Black for code formatting and Flake8 for linting:

```bash
# Format code
black api_toolkit.py

# Check linting
flake8 api_toolkit.py

# Fix imports
isort api_toolkit.py
```

## Coding Standards

### Python Style Guide

Follow PEP 8 guidelines:

- Use 4 spaces for indentation (not tabs)
- Maximum line length of 88 characters (Black default)
- Use descriptive variable names
- Add docstrings to all functions and classes

### Documentation

- Add docstrings to all public methods
- Include type hints where appropriate
- Update README.md for new features
- Add examples for complex functionality

Example:

```python
def check_jwt(self, token: str) -> Dict[str, Any]:
    """
    Comprehensive JWT security analysis
    
    Args:
        token: JWT token string to analyze
        
    Returns:
        Dictionary containing analysis results with keys:
        - valid: Boolean indicating if token is valid
        - decoded_header: Decoded JWT header
        - decoded_payload: Decoded JWT payload
        - vulnerabilities: List of found vulnerabilities
        - recommendations: List of security recommendations
        
    Example:
        >>> analyzer = JWTAnalyzer()
        >>> result = analyzer.check_jwt("eyJ...")
        >>> print(result['valid'])
        True
    """
```

### Testing

- Write tests for all new features
- Maintain or improve code coverage
- Use descriptive test names
- Test edge cases and error conditions

Example:

```python
class TestNewFeature:
    """Test suite for new feature"""
    
    def test_basic_functionality(self):
        """Test basic feature operation"""
        # Arrange
        feature = NewFeature()
        
        # Act
        result = feature.process()
        
        # Assert
        assert result is not None
        assert result['status'] == 'success'
    
    def test_error_handling(self):
        """Test feature handles errors correctly"""
        feature = NewFeature()
        
        with pytest.raises(ValueError):
            feature.process(invalid_input=True)
```

## Commit Guidelines

### Commit Messages

Use clear, descriptive commit messages:

```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Example:**

```
feat: Add OAuth 2.0 vulnerability scanner

Implement scanner to detect common OAuth 2.0 misconfigurations
including redirect URI validation issues and token leakage.

Closes #123
```

### Atomic Commits

- Make commits small and focused
- One logical change per commit
- Commit working code (tests should pass)

## Pull Request Process

### Before Submitting

1. **Update documentation** - Ensure README and docstrings are current
2. **Run tests** - All tests must pass
3. **Format code** - Run Black and Flake8
4. **Update CHANGELOG** - Add entry for your changes
5. **Rebase** - Ensure your branch is up to date with main

### Creating a Pull Request

1. Push your branch to GitHub
2. Create a pull request from your fork
3. Fill out the PR template completely
4. Link related issues
5. Request review from maintainers

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactoring

## Testing
Describe testing performed

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Code formatted with Black
- [ ] Docstrings added
- [ ] CHANGELOG updated
```

### Review Process

1. At least one maintainer must approve
2. All tests must pass
3. Code coverage should not decrease
4. Address all reviewer comments
5. Squash commits if requested

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in documentation

## Questions?

Feel free to:
- Open an issue for discussion
- Join our community chat
- Email the maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to API Security Toolkit!** 🔒
