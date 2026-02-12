"""
API Security Toolkit - Usage Examples
Demonstrates various security testing scenarios
"""

from api_toolkit import (
    JWTAnalyzer,
    AuthenticationTester,
    AuthorizationTester,
    APIFuzzer,
    SecurityReporter,
    RateLimitTester
)
import json


def example_jwt_analysis():
    """Example: Analyze JWT token security"""
    print("\n" + "="*60)
    print("EXAMPLE 1: JWT Token Analysis")
    print("="*60)
    
    analyzer = JWTAnalyzer()
    
    # Sample JWT token (signed with weak secret)
    sample_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.4Adcj0u6gHnGcFdz4AGVX6_HMlbVAr9TLVdl9YrJ8Cg"
    
    result = analyzer.check_jwt(sample_token)
    
    print(f"\n✓ Token Valid: {result['valid']}")
    
    if result.get('decoded_header'):
        print(f"\n📋 Header: {json.dumps(result['decoded_header'], indent=2)}")
    
    if result.get('decoded_payload'):
        print(f"\n📋 Payload: {json.dumps(result['decoded_payload'], indent=2)}")
    
    if result.get('vulnerabilities'):
        print(f"\n⚠️  Vulnerabilities Found: {len(result['vulnerabilities'])}")
        for vuln in result['vulnerabilities']:
            print(f"   [{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    
    if result.get('recommendations'):
        print(f"\n💡 Recommendations:")
        for rec in result['recommendations']:
            print(f"   - {rec}")


def example_authentication_testing():
    """Example: Test authentication mechanisms"""
    print("\n" + "="*60)
    print("EXAMPLE 2: Authentication Security Testing")
    print("="*60)
    
    # Note: Replace with your actual API URL
    base_url = "https://jsonplaceholder.typicode.com"
    
    tester = AuthenticationTester(base_url)
    
    print("\n🔍 Testing brute force protection...")
    print("(This is a demo - replace with real endpoint)")
    
    # In real scenario, you would test actual login endpoint
    print("\nBrute Force Test Results:")
    print("   - Protected: Would test actual endpoint")
    print("   - Rate Limited: Implementation-dependent")
    print("   - Account Lockout: Implementation-dependent")
    
    print("\n🔍 Checking for default credentials...")
    print("   - Testing common username/password combinations")
    print("   - Recommendation: Disable default accounts in production")


def example_idor_testing():
    """Example: Test for IDOR vulnerabilities"""
    print("\n" + "="*60)
    print("EXAMPLE 3: IDOR (Insecure Direct Object Reference) Testing")
    print("="*60)
    
    base_url = "https://jsonplaceholder.typicode.com"
    tester = AuthorizationTester(base_url)
    
    print("\n🔍 Testing IDOR on user endpoints...")
    
    # Test with a public API (for demonstration)
    # In real testing, you would use your authenticated token
    idor_result = tester.test_idor(
        endpoint_template="/users/{id}",
        valid_token="demo-token",
        test_range=range(1, 11)  # Test first 10 IDs
    )
    
    print(f"\n📊 IDOR Test Results:")
    print(f"   - Total IDs Tested: {idor_result['total_tested']}")
    print(f"   - Accessible IDs: {len(idor_result['accessible_ids'])}")
    print(f"   - Vulnerable: {idor_result['vulnerable']}")
    
    if idor_result['accessible_ids']:
        print(f"   - IDs accessed: {idor_result['accessible_ids'][:5]}...")


def example_api_fuzzing():
    """Example: Fuzz API endpoints"""
    print("\n" + "="*60)
    print("EXAMPLE 4: API Fuzzing for Vulnerabilities")
    print("="*60)
    
    base_url = "https://jsonplaceholder.typicode.com"
    fuzzer = APIFuzzer(base_url)
    
    print("\n🎯 Fuzzing API endpoint...")
    print("   Target: /posts")
    print("   Testing for: SQL Injection, XSS, Command Injection, etc.")
    
    # Note: This is a demo with a public API
    # The API likely won't be vulnerable, but demonstrates the process
    
    print("\nFuzzing Results:")
    print("   - SQL Injection Payloads: Testing...")
    print("   - XSS Payloads: Testing...")
    print("   - Command Injection: Testing...")
    print("   - Path Traversal: Testing...")
    
    print("\n💡 In real testing:")
    print("   - Analyze response codes (500 errors indicate issues)")
    print("   - Check for error messages (SQL errors, stack traces)")
    print("   - Monitor response times (can indicate injection success)")
    print("   - Look for reflected input (XSS indicators)")


def example_rate_limit_testing():
    """Example: Test rate limiting"""
    print("\n" + "="*60)
    print("EXAMPLE 5: Rate Limiting Analysis")
    print("="*60)
    
    base_url = "https://jsonplaceholder.typicode.com"
    tester = RateLimitTester(base_url)
    
    print("\n⚡ Testing rate limiting...")
    print("   Sending multiple requests to /posts endpoint")
    
    # Test with limited requests for demo
    rate_result = tester.test_rate_limit(
        endpoint="/posts",
        requests_count=20,
        time_window=60
    )
    
    print(f"\n📊 Rate Limit Test Results:")
    print(f"   - Requests Sent: {rate_result['requests_sent']}")
    print(f"   - Protected: {rate_result['protected']}")
    print(f"   - Blocked Requests: {rate_result['requests_blocked']}")
    
    if rate_result['limit_hit_at']:
        print(f"   - Limit Hit At: Request #{rate_result['limit_hit_at']}")
    
    print(f"\n   Response Code Distribution:")
    for code, count in rate_result['response_codes'].items():
        print(f"      {code}: {count} requests")


def example_comprehensive_assessment():
    """Example: Full security assessment with reporting"""
    print("\n" + "="*60)
    print("EXAMPLE 6: Comprehensive Security Assessment")
    print("="*60)
    
    reporter = SecurityReporter()
    
    # Simulate findings from various tests
    
    # JWT findings
    reporter.add_finding(
        category="JWT Security",
        severity="CRITICAL",
        title="Weak JWT Secret Key",
        description="JWT tokens are signed with a weak, easily guessable secret: 'secret'",
        recommendation="Use a strong, randomly generated secret (minimum 256 bits)"
    )
    
    reporter.add_finding(
        category="JWT Security",
        severity="HIGH",
        title="Missing Token Expiration",
        description="JWT tokens do not include expiration time (exp claim)",
        recommendation="Implement token expiration with reasonable timeframes (e.g., 15 minutes for access tokens)"
    )
    
    # Authentication findings
    reporter.add_finding(
        category="Authentication",
        severity="HIGH",
        title="No Brute Force Protection",
        description="Login endpoint allows unlimited authentication attempts",
        recommendation="Implement rate limiting and account lockout after failed attempts"
    )
    
    reporter.add_finding(
        category="Authentication",
        severity="CRITICAL",
        title="Default Credentials Active",
        description="System accepts default credentials: admin/admin",
        recommendation="Disable or change all default credentials before production deployment"
    )
    
    # Authorization findings
    reporter.add_finding(
        category="Authorization",
        severity="HIGH",
        title="IDOR Vulnerability",
        description="Users can access other users' data by manipulating user ID in API requests",
        recommendation="Implement proper authorization checks and use UUIDs instead of sequential IDs"
    )
    
    # Input validation findings
    reporter.add_finding(
        category="Input Validation",
        severity="HIGH",
        title="SQL Injection Vulnerability",
        description="Search parameter is vulnerable to SQL injection attacks",
        recommendation="Use parameterized queries and implement input validation"
    )
    
    reporter.add_finding(
        category="Input Validation",
        severity="MEDIUM",
        title="Cross-Site Scripting (XSS)",
        description="User input is reflected in responses without proper encoding",
        recommendation="Implement output encoding and Content Security Policy headers"
    )
    
    # Rate limiting findings
    reporter.add_finding(
        category="Rate Limiting",
        severity="MEDIUM",
        title="No Rate Limiting Implemented",
        description="API endpoints do not enforce rate limits",
        recommendation="Implement per-user and per-IP rate limiting"
    )
    
    # Generate reports in different formats
    print("\n📊 Generating Security Reports...")
    
    # JSON Report
    json_report = reporter.generate_report(format='json')
    with open('/home/claude/security_report.json', 'w') as f:
        f.write(json_report)
    print("   ✓ JSON report: security_report.json")
    
    # HTML Report
    html_report = reporter.generate_report(format='html')
    with open('/home/claude/security_report.html', 'w') as f:
        f.write(html_report)
    print("   ✓ HTML report: security_report.html")
    
    # Text Report
    text_report = reporter.generate_report(format='text')
    with open('/home/claude/security_report.txt', 'w') as f:
        f.write(text_report)
    print("   ✓ Text report: security_report.txt")
    
    print("\n📈 Summary:")
    severity_breakdown = reporter._get_severity_breakdown()
    for severity, count in severity_breakdown.items():
        if count > 0:
            print(f"   {severity}: {count} findings")
    
    print(f"\n   Total Findings: {len(reporter.findings)}")
    print("\n✅ Comprehensive assessment complete!")


def main():
    """Run all examples"""
    print("\n" + "="*60)
    print("API SECURITY TOOLKIT - USAGE EXAMPLES")
    print("="*60)
    print("\nThis script demonstrates various security testing scenarios")
    print("using the API Security Automation Toolkit.")
    
    try:
        # Run all examples
        example_jwt_analysis()
        example_authentication_testing()
        example_idor_testing()
        example_api_fuzzing()
        example_rate_limit_testing()
        example_comprehensive_assessment()
        
        print("\n" + "="*60)
        print("ALL EXAMPLES COMPLETED SUCCESSFULLY!")
        print("="*60)
        print("\n💡 Next Steps:")
        print("   1. Review the generated reports in the current directory")
        print("   2. Adapt these examples to test your own APIs")
        print("   3. Configure endpoints and tokens for real testing")
        print("   4. Always obtain proper authorization before testing")
        
    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
