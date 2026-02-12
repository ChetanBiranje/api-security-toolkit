"""
Advanced API Security Testing Example
Real-world penetration testing scenario
"""

from api_toolkit import (
    JWTAnalyzer,
    AuthenticationTester,
    AuthorizationTester,
    APIFuzzer,
    SecurityReporter
)
import json


class ComprehensiveSecurityAudit:
    """
    Perform comprehensive security audit on a REST API
    """
    
    def __init__(self, base_url: str, api_token: str = None):
        self.base_url = base_url
        self.api_token = api_token
        self.reporter = SecurityReporter()
        
        # Initialize all testers
        self.jwt_analyzer = JWTAnalyzer()
        self.auth_tester = AuthenticationTester(base_url)
        self.authz_tester = AuthorizationTester(base_url)
        self.fuzzer = APIFuzzer(base_url)
    
    def run_full_audit(self):
        """Execute complete security audit"""
        print("="*70)
        print("COMPREHENSIVE API SECURITY AUDIT")
        print("="*70)
        print(f"\nTarget: {self.base_url}")
        print(f"Started: {self.reporter.findings[0]['timestamp'] if self.reporter.findings else 'Now'}\n")
        
        # 1. JWT Security Assessment
        self._test_jwt_security()
        
        # 2. Authentication Testing
        self._test_authentication()
        
        # 3. Authorization Testing
        self._test_authorization()
        
        # 4. Input Validation (Fuzzing)
        self._test_input_validation()
        
        # 5. Generate comprehensive report
        self._generate_final_report()
    
    def _test_jwt_security(self):
        """Test JWT token security"""
        print("\n[1/4] JWT Security Assessment")
        print("-" * 70)
        
        if not self.api_token:
            print("⚠️  No JWT token provided - skipping JWT tests")
            return
        
        result = self.jwt_analyzer.check_jwt(self.api_token)
        
        if result['valid']:
            print("✓ JWT token is valid and decodable")
            
            # Report vulnerabilities
            for vuln in result.get('vulnerabilities', []):
                self.reporter.add_finding(
                    category="JWT Security",
                    severity=vuln['severity'],
                    title=vuln['type'],
                    description=vuln['description']
                )
                print(f"  [{vuln['severity']}] {vuln['type']}")
            
            # Report recommendations
            for rec in result.get('recommendations', []):
                self.reporter.add_finding(
                    category="JWT Security",
                    severity="INFO",
                    title="JWT Best Practice",
                    description=rec
                )
        else:
            print("❌ JWT token validation failed")
            if result.get('error'):
                print(f"   Error: {result['error']}")
    
    def _test_authentication(self):
        """Test authentication mechanisms"""
        print("\n[2/4] Authentication Security Testing")
        print("-" * 70)
        
        # Test 1: Brute Force Protection
        print("\n  Testing brute force protection...")
        bf_result = self.auth_tester.test_brute_force_protection(
            endpoint="/api/auth/login",
            max_attempts=15
        )
        
        if not bf_result['protected']:
            self.reporter.add_finding(
                category="Authentication",
                severity="HIGH",
                title="Missing Brute Force Protection",
                description=f"Completed {bf_result['attempts']} login attempts without rate limiting or lockout",
                recommendation="Implement progressive delays, rate limiting, and account lockout mechanisms"
            )
            print("  ❌ No brute force protection detected")
        else:
            print("  ✓ Brute force protection is active")
            if bf_result.get('rate_limited_at'):
                print(f"    Rate limited at attempt #{bf_result['rate_limited_at']}")
        
        # Test 2: Default Credentials
        print("\n  Testing for default credentials...")
        default_result = self.auth_tester.test_default_credentials(
            endpoint="/api/auth/login"
        )
        
        if default_result['vulnerable']:
            self.reporter.add_finding(
                category="Authentication",
                severity="CRITICAL",
                title="Default Credentials Active",
                description=f"Working credentials found: {default_result['working_credentials']}",
                recommendation="Immediately disable or change all default credentials"
            )
            print("  ❌ Default credentials are active!")
        else:
            print("  ✓ No default credentials accepted")
        
        # Test 3: Session Fixation
        print("\n  Testing for session fixation...")
        session_result = self.auth_tester.test_session_fixation(
            login_endpoint="/api/auth/login"
        )
        
        if session_result['vulnerable']:
            self.reporter.add_finding(
                category="Authentication",
                severity="HIGH",
                title="Session Fixation Vulnerability",
                description="Session token does not change after authentication",
                recommendation="Regenerate session tokens upon successful authentication"
            )
            print("  ❌ Session fixation vulnerability detected")
        else:
            print("  ✓ Session tokens properly regenerated")
    
    def _test_authorization(self):
        """Test authorization and access controls"""
        print("\n[3/4] Authorization Security Testing")
        print("-" * 70)
        
        if not self.api_token:
            print("⚠️  No token provided - skipping authorization tests")
            return
        
        # Test 1: IDOR (Insecure Direct Object Reference)
        print("\n  Testing for IDOR vulnerabilities...")
        idor_result = self.authz_tester.test_idor(
            endpoint_template="/api/users/{id}",
            valid_token=self.api_token,
            test_range=range(1, 50)
        )
        
        if idor_result['vulnerable']:
            self.reporter.add_finding(
                category="Authorization",
                severity="HIGH",
                title="IDOR Vulnerability Detected",
                description=f"Accessed {len(idor_result['accessible_ids'])} user records out of {idor_result['total_tested']} tested",
                recommendation="Implement proper authorization checks and consider using UUIDs instead of sequential IDs"
            )
            print(f"  ❌ IDOR found - {len(idor_result['accessible_ids'])} unauthorized resources accessible")
        else:
            print("  ✓ No IDOR vulnerabilities detected")
        
        # Test 2: Privilege Escalation
        print("\n  Testing for privilege escalation...")
        priv_esc_result = self.authz_tester.test_privilege_escalation(
            low_priv_token=self.api_token,
            admin_endpoint="/api/admin"
        )
        
        if priv_esc_result['vulnerable']:
            self.reporter.add_finding(
                category="Authorization",
                severity="CRITICAL",
                title="Vertical Privilege Escalation",
                description=f"Low-privilege user accessed: {', '.join(priv_esc_result['accessible_endpoints'])}",
                recommendation="Implement role-based access control (RBAC) with proper validation"
            )
            print("  ❌ Privilege escalation possible")
        else:
            print("  ✓ Proper access controls in place")
    
    def _test_input_validation(self):
        """Test input validation through fuzzing"""
        print("\n[4/4] Input Validation Testing (Fuzzing)")
        print("-" * 70)
        
        # Define critical endpoints to fuzz
        endpoints_to_test = [
            ("/api/search", "POST", ["query", "filter"]),
            ("/api/users", "GET", ["id", "name", "email"]),
            ("/api/products", "POST", ["name", "description", "price"]),
        ]
        
        total_vulns = 0
        
        for endpoint, method, params in endpoints_to_test:
            print(f"\n  Fuzzing {method} {endpoint}...")
            
            fuzz_result = self.fuzzer.fuzz_endpoint(
                endpoint=endpoint,
                method=method,
                parameters=params
            )
            
            # Report vulnerabilities
            for vuln in fuzz_result['vulnerabilities']:
                total_vulns += 1
                self.reporter.add_finding(
                    category="Input Validation",
                    severity="HIGH",
                    title=f"{vuln['attack_type']} Vulnerability",
                    description=f"Parameter '{vuln['param']}' vulnerable to {vuln['attack_type']}",
                    recommendation="Implement input validation, sanitization, and output encoding"
                )
                print(f"    ❌ {vuln['attack_type']} found in '{vuln['param']}'")
            
            # Report suspicious responses
            suspicious_count = len(fuzz_result['suspicious_responses'])
            if suspicious_count > 0:
                print(f"    ⚠️  {suspicious_count} suspicious responses detected")
        
        if total_vulns == 0:
            print("\n  ✓ No injection vulnerabilities detected")
        else:
            print(f"\n  ❌ Total vulnerabilities found: {total_vulns}")
    
    def _generate_final_report(self):
        """Generate and save final security report"""
        print("\n" + "="*70)
        print("GENERATING FINAL REPORT")
        print("="*70)
        
        # Get severity breakdown
        breakdown = self.reporter._get_severity_breakdown()
        
        print("\nSeverity Breakdown:")
        for severity, count in breakdown.items():
            if count > 0:
                print(f"  {severity}: {count}")
        
        print(f"\nTotal Findings: {len(self.reporter.findings)}")
        
        # Generate reports in all formats
        formats = ['json', 'html', 'text']
        for fmt in formats:
            report = self.reporter.generate_report(format=fmt)
            filename = f"/home/claude/security_audit_report.{fmt if fmt != 'text' else 'txt'}"
            
            with open(filename, 'w') as f:
                f.write(report)
            
            print(f"  ✓ {fmt.upper()} report: {filename}")
        
        print("\n" + "="*70)
        print("AUDIT COMPLETE")
        print("="*70)
        
        # Provide recommendations
        critical_count = breakdown.get('CRITICAL', 0)
        high_count = breakdown.get('HIGH', 0)
        
        if critical_count > 0:
            print(f"\n⚠️  CRITICAL: {critical_count} critical issues require immediate attention!")
        
        if high_count > 0:
            print(f"⚠️  WARNING: {high_count} high-severity issues found")
        
        if critical_count == 0 and high_count == 0:
            print("\n✓ No critical or high-severity issues detected")
        
        print("\nNext Steps:")
        print("  1. Review detailed reports")
        print("  2. Prioritize fixes based on severity")
        print("  3. Implement recommended security controls")
        print("  4. Re-test after remediation")


def main():
    """
    Example: Run comprehensive security audit
    """
    print("\nAPI SECURITY TOOLKIT - ADVANCED EXAMPLE")
    print("Real-world penetration testing scenario\n")
    
    # Configuration
    TARGET_API = "https://jsonplaceholder.typicode.com"
    
    # Sample JWT token (in real scenario, obtain through login)
    SAMPLE_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    # Initialize and run audit
    audit = ComprehensiveSecurityAudit(
        base_url=TARGET_API,
        api_token=SAMPLE_TOKEN
    )
    
    try:
        audit.run_full_audit()
    except KeyboardInterrupt:
        print("\n\n⚠️  Audit interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during audit: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
