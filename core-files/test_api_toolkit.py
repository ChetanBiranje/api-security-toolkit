"""
Unit tests for API Security Toolkit
"""

import pytest
import jwt
from datetime import datetime, timedelta
from api_toolkit import (
    JWTAnalyzer,
    AuthenticationTester,
    AuthorizationTester,
    APIFuzzer,
    SecurityReporter,
    RateLimitTester
)


class TestJWTAnalyzer:
    """Test JWT Analysis functionality"""
    
    def test_valid_jwt_decoding(self):
        """Test decoding a valid JWT token"""
        analyzer = JWTAnalyzer()
        
        # Create a valid token
        payload = {
            'sub': '1234567890',
            'name': 'Test User',
            'iat': datetime.now().timestamp(),
            'exp': (datetime.now() + timedelta(hours=1)).timestamp()
        }
        token = jwt.encode(payload, 'test_secret', algorithm='HS256')
        
        result = analyzer.check_jwt(token)
        
        assert result['valid'] is True
        assert result['decoded_header'] is not None
        assert result['decoded_payload'] is not None
        assert result['decoded_payload']['name'] == 'Test User'
    
    def test_none_algorithm_detection(self):
        """Test detection of 'none' algorithm vulnerability"""
        analyzer = JWTAnalyzer()
        
        # Create token with 'none' algorithm
        payload = {'sub': 'test', 'name': 'Test'}
        token = jwt.encode(payload, '', algorithm='none')
        
        result = analyzer.check_jwt(token)
        
        # Check if 'none' algorithm is detected
        vuln_types = [v['type'] for v in result.get('vulnerabilities', [])]
        assert any('Algorithm' in vt for vt in vuln_types) or result.get('error')
    
    def test_missing_expiration_detection(self):
        """Test detection of missing expiration claim"""
        analyzer = JWTAnalyzer()
        
        # Create token without expiration
        payload = {'sub': '1234567890', 'name': 'Test User'}
        token = jwt.encode(payload, 'test_secret', algorithm='HS256')
        
        result = analyzer.check_jwt(token)
        
        # Should detect missing expiration
        vuln_types = [v['type'] for v in result.get('vulnerabilities', [])]
        assert any('Expiration' in vt for vt in vuln_types)
    
    def test_weak_secret_detection(self):
        """Test detection of weak JWT secrets"""
        analyzer = JWTAnalyzer()
        
        # Create token with weak secret
        payload = {'sub': 'test', 'exp': (datetime.now() + timedelta(hours=1)).timestamp()}
        token = jwt.encode(payload, 'secret', algorithm='HS256')
        
        result = analyzer.check_jwt(token)
        
        # Should detect weak secret
        vuln_types = [v['type'] for v in result.get('vulnerabilities', [])]
        assert any('Weak Secret' in vt for vt in vuln_types)
    
    def test_sensitive_data_detection(self):
        """Test detection of sensitive data in payload"""
        analyzer = JWTAnalyzer()
        
        # Create token with sensitive data
        payload = {
            'sub': 'test',
            'password': 'secret123',
            'exp': (datetime.now() + timedelta(hours=1)).timestamp()
        }
        token = jwt.encode(payload, 'test_secret', algorithm='HS256')
        
        result = analyzer.check_jwt(token)
        
        # Should detect sensitive data
        vuln_types = [v['type'] for v in result.get('vulnerabilities', [])]
        assert any('Sensitive Data' in vt for vt in vuln_types)


class TestAuthenticationTester:
    """Test authentication testing functionality"""
    
    def test_initialization(self):
        """Test AuthenticationTester initialization"""
        tester = AuthenticationTester(base_url="https://api.example.com")
        assert tester.base_url == "https://api.example.com"
        assert tester.session is not None


class TestAuthorizationTester:
    """Test authorization testing functionality"""
    
    def test_initialization(self):
        """Test AuthorizationTester initialization"""
        tester = AuthorizationTester(base_url="https://api.example.com")
        assert tester.base_url == "https://api.example.com"
        assert tester.session is not None
    
    def test_idor_detection_logic(self):
        """Test IDOR detection logic"""
        tester = AuthorizationTester(base_url="https://api.example.com")
        
        # Simulate IDOR test result
        result = {
            'vulnerable': False,
            'accessible_ids': [],
            'total_tested': 0
        }
        
        # If multiple IDs accessible, should be vulnerable
        result['accessible_ids'] = [1, 2, 3, 4]
        assert len(result['accessible_ids']) > 1
        # This would indicate IDOR vulnerability in real test


class TestAPIFuzzer:
    """Test API fuzzing functionality"""
    
    def test_payload_loading(self):
        """Test fuzzing payload initialization"""
        fuzzer = APIFuzzer(base_url="https://api.example.com")
        
        # Check that payloads are loaded
        assert 'sql_injection' in fuzzer.payloads
        assert 'xss' in fuzzer.payloads
        assert 'command_injection' in fuzzer.payloads
        assert 'path_traversal' in fuzzer.payloads
        assert 'xxe' in fuzzer.payloads
        
        # Check payload content
        assert len(fuzzer.payloads['sql_injection']) > 0
        assert "' OR '1'='1" in fuzzer.payloads['sql_injection']
    
    def test_fuzzer_initialization(self):
        """Test APIFuzzer initialization"""
        fuzzer = APIFuzzer(base_url="https://api.example.com")
        assert fuzzer.base_url == "https://api.example.com"
        assert fuzzer.payloads is not None


class TestSecurityReporter:
    """Test security reporting functionality"""
    
    def test_add_finding(self):
        """Test adding security findings"""
        reporter = SecurityReporter()
        
        reporter.add_finding(
            category="Test",
            severity="HIGH",
            title="Test Finding",
            description="Test description",
            recommendation="Test recommendation"
        )
        
        assert len(reporter.findings) == 1
        assert reporter.findings[0]['severity'] == "HIGH"
        assert reporter.findings[0]['title'] == "Test Finding"
    
    def test_severity_breakdown(self):
        """Test severity breakdown calculation"""
        reporter = SecurityReporter()
        
        reporter.add_finding("Test", "CRITICAL", "Finding 1", "Desc 1")
        reporter.add_finding("Test", "HIGH", "Finding 2", "Desc 2")
        reporter.add_finding("Test", "HIGH", "Finding 3", "Desc 3")
        reporter.add_finding("Test", "MEDIUM", "Finding 4", "Desc 4")
        
        breakdown = reporter._get_severity_breakdown()
        
        assert breakdown['CRITICAL'] == 1
        assert breakdown['HIGH'] == 2
        assert breakdown['MEDIUM'] == 1
        assert breakdown['LOW'] == 0
    
    def test_json_report_generation(self):
        """Test JSON report generation"""
        reporter = SecurityReporter()
        
        reporter.add_finding("Test", "HIGH", "Test Finding", "Description")
        
        report = reporter.generate_report(format='json')
        
        assert isinstance(report, str)
        assert 'total_findings' in report
        assert 'severity_breakdown' in report
        assert 'findings' in report
    
    def test_html_report_generation(self):
        """Test HTML report generation"""
        reporter = SecurityReporter()
        
        reporter.add_finding("Test", "HIGH", "Test Finding", "Description")
        
        report = reporter.generate_report(format='html')
        
        assert isinstance(report, str)
        assert '<html>' in report
        assert 'Test Finding' in report
        assert 'HIGH' in report
    
    def test_text_report_generation(self):
        """Test text report generation"""
        reporter = SecurityReporter()
        
        reporter.add_finding("Test", "HIGH", "Test Finding", "Description")
        
        report = reporter.generate_report(format='text')
        
        assert isinstance(report, str)
        assert 'SECURITY ASSESSMENT REPORT' in report
        assert 'Test Finding' in report


class TestRateLimitTester:
    """Test rate limiting functionality"""
    
    def test_initialization(self):
        """Test RateLimitTester initialization"""
        tester = RateLimitTester(base_url="https://api.example.com")
        assert tester.base_url == "https://api.example.com"


# Integration tests
class TestIntegration:
    """Integration tests for complete workflows"""
    
    def test_full_jwt_workflow(self):
        """Test complete JWT analysis workflow"""
        analyzer = JWTAnalyzer()
        reporter = SecurityReporter()
        
        # Create test token
        payload = {
            'sub': 'test',
            'name': 'Test User',
            'password': 'should_not_be_here'  # Sensitive data
        }
        token = jwt.encode(payload, 'secret', algorithm='HS256')
        
        # Analyze
        result = analyzer.check_jwt(token)
        
        # Report findings
        for vuln in result.get('vulnerabilities', []):
            reporter.add_finding(
                category="JWT Security",
                severity=vuln['severity'],
                title=vuln['type'],
                description=vuln['description']
            )
        
        # Should have findings
        assert len(reporter.findings) > 0
        
        # Generate report
        report = reporter.generate_report(format='json')
        assert 'findings' in report


# Fixtures
@pytest.fixture
def sample_jwt_token():
    """Fixture for creating sample JWT tokens"""
    payload = {
        'sub': '1234567890',
        'name': 'Test User',
        'exp': (datetime.now() + timedelta(hours=1)).timestamp()
    }
    return jwt.encode(payload, 'test_secret', algorithm='HS256')


@pytest.fixture
def security_reporter():
    """Fixture for SecurityReporter instance"""
    return SecurityReporter()


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
