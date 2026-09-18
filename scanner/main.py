import requests
from datetime import datetime
from urllib.parse import urlparse
from scanner import findings
from scanner.checks.cookies import check_cookie_security
from scanner.checks.redirect import check_redirect
from scanner.checks.headers import (
    check_security_header,
    check_frame_options,
    check_csp,
    check_content_type_options,
    check_information_disclosure,
    check_sensitive_headers
)
from scanner.checks.methods import check_http_methods
from scanner.checks.tls import check_tls_version




def check_server_header(server):
    if server:
        print("server information is disclosed")
        print("[INFO] server header is exposed")
        findings.add_finding(
            "Server Header Information Disclosure",
            "Low",
            server,
            "Consider removing or obfuscating the server header to reduce information disclosure"
        )

scanner_name = "WEB VAPT SCANNER"
pass_count = 0

print(scanner_name)
print("Automated Security Assessment")
print("starting...")

target = input("Enter the target URL: ").strip()
scan_time = datetime.now()
if not target.startswith(("http://", "https://")):
    target = "https://" + target

parsed_url = urlparse(target)
if not parsed_url.hostname:
    print("[ERROR] Invalid URL")
    exit()

if target.startswith("https://"):
    print("[PASS] Target uses HTTPS")
else:
    print("[WARN] Target does not use HTTPS")
    findings.add_finding(
       "Target is not using HTTPS",
       "High",
        target,
       "Use HTTPS to protect data transmitted between the client and server"
    )



try:
    response = requests.get(target, timeout=5)
except requests.exceptions.Timeout:
    print("Request timed out")
    exit()
except Exception as error:
    print(error)
    exit()

check_redirect(response, target)
check_http_methods(target)
check_information_disclosure(response.headers)
check_sensitive_headers(response.headers)
check_tls_version(target)

print(f"HTTP Status: {response.status_code}")


if 200 <= response.status_code < 300:
    print("[INFO] Successful response")

elif 300 <= response.status_code < 400:
    print("[INFO] Redirect response")

elif 400 <= response.status_code < 500:
    print("[WARN] Client error response")

elif 500 <= response.status_code < 600:
    print("[WARN] Server error response")
if 100 <= response.status_code <= 599:
    print("Target is reachable")
else:
    print("Target is not reachable")




server =response.headers.get("server")
check_server_header(server)
print(server)

pass_count += check_content_type_options(response.headers)

check_security_header(
    response.headers,
    "Strict-Transport-Security",
    "High",
    "Configure the Strict-Transport-Security header to enforce secure connections"
)

check_frame_options(response.headers)

check_security_header(
    response.headers,
    "Content-Security-Policy",
    "Medium",
    "Configure the Content-Security-Policy header to mitigate XSS and other code injection attacks"
)
check_security_header(
    response.headers,
    "Referrer-Policy",
    "Medium",
    "Configure the Referrer-Policy header to control the referrer information sent with requests"
)
check_security_header(
    response.headers,
    "Permissions-Policy",
    "Medium",
    "Configure the Permissions-Policy header to control access to browser features"
)
pass_count += check_cookie_security(response.cookies)
    
print(f"Total passed checks: {pass_count}")
print(f"risk score: {findings.risk_score}")
if findings.risk_score >= 10:
    risk_level = "CRITICAL"
elif findings.risk_score >= 7:
    risk_level = "HIGH"
elif findings.risk_score >= 4:
    risk_level = "MEDIUM"
elif findings.risk_score >= 1:
    risk_level = "LOW"
else:
    risk_level = "SAFE"
print(f"Risk Level: {risk_level}")
print("Severity Summary:")
print(f"Critical: {findings.critical_count}")
print(f"High: {findings.high_count}")
print(f"Medium: {findings.medium_count}")
print(f"Low: {findings.low_count}")

print("=" * 50)
print("SCAN SUMMARY")
print("=" * 50)
print(f"Target: {target}")
print(f"Final URL: {response.url}")
print(f"Total Findings: {len(findings.findings)}")
print(f"Scan Time: {scan_time}")

print("Findings:")
for finding in findings.findings:
    print("-" * 50)
    print(f"Finding: {finding['name']}")
    print(f"Severity: {finding['severity']}")
    print(f"Evidence: {finding['evidence']}")
    print(f"Recommendation: {finding['recommendation']}")