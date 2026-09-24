# SQLi-tester

A lightweight, automated SQL Injection vulnerability scanner written in Python. Built to detect error-based and anomaly-based SQLi in GET parameters.

---

## Features

- **15 built-in SQLi payloads** (quotes, OR 1=1, UNION, ORDER BY, comment bypass)
- **17 SQL error signatures** (MySQL, PostgreSQL, Oracle, SQLite, MSSQL)
- **Baseline comparison** — detects response length and status code anomalies
- **Color-coded terminal output** — instant visual feedback
- **Rate limiting** — 0.5s delay between requests to avoid crashing targets
- **Zero external dependencies** beyond `requests`

---
Usage

python3 sqli_tester.py <URL> <PARAMETER>
Examples

# Test DVWA SQLi page (security set to Low)
python3 sqli_tester.py "http://localhost:8080/vulnerabilities/sqli" "id"

# Test a search parameter
python3 sqli_tester.py "http://demo.testfire.net/search" "query"

# Test a product ID parameter
python3 sqli_tester.py "http://target.com/product" "id"
