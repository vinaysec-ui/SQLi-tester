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
