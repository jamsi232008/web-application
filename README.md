# Web Application Security & OWASP Top 10

**Cybersecurity Internship, Codomax: Module 3**

| | |
|---|---|
| **Intern** | Jamsira Farvin S |
| **Institution** | Chennai Institute of Technology, B.Tech AI & Data Science |
| **Module** | Web application security, OWASP Top 10, secure coding and the Secure Web Application Lab |
| **Standard used** | OWASP Top 10:2025 |

> **Ethical use notice:** `lab/app/vulnerable_app.py` is intentionally insecure and exists only for learning. It binds to `127.0.0.1`. Never deploy it, expose it to a network, or test any system you do not own or have written permission to test.

## Objectives

1. Understand how web applications work: HTTP request/response lifecycle, cookies, sessions, authentication and authorization.
2. Master the OWASP Top 10 vulnerabilities (injection, broken access control, authentication failures, XSS and more).
3. Learn secure coding practices and run a Secure Web Application Lab (Identify → Test → Fix → Document) in a safe sandbox.
4. Submit the OWASP analysis, vulnerability report, remediation recommendations and a demo walkthrough.

## Repository structure

```
web-app-security-owasp/
├── README.md
├── notes/
│   ├── 01-web-fundamentals.md        <- HTTP lifecycle, cookies, sessions, AuthN/AuthZ
│   ├── 02-owasp-top-10-2025.md       <- OWASP analysis (all 10 categories)
│   └── 03-secure-coding.md           <- secure coding practices with code examples
├── lab/
│   ├── secure-web-lab.md             <- Identify -> Test -> Fix -> Document guide
│   └── app/
│       ├── vulnerable_app.py         <- intentionally insecure training app (port 5000)
│       ├── secure_app.py             <- remediated version (port 5001)
│       └── requirements.txt
├── reports/
│   ├── vulnerability-report.md       <- 8 findings with evidence and severity
│   └── remediation-recommendations.md
├── demo/
│   └── demo-walkthrough.md           <- script for the demo recording
└── screenshots/                      <- evidence images
```

## Deliverables

| Required deliverable | Location |
|---|---|
| OWASP analysis | [`notes/02-owasp-top-10-2025.md`](notes/02-owasp-top-10-2025.md) |
| Vulnerability report | [`reports/vulnerability-report.md`](reports/vulnerability-report.md) |
| Remediation recommendations | [`reports/remediation-recommendations.md`](reports/remediation-recommendations.md) |
| Demo walkthrough | [`demo/demo-walkthrough.md`](demo/demo-walkthrough.md) |
| Secure lab | [`lab/secure-web-lab.md`](lab/secure-web-lab.md) and [`lab/app/`](lab/app/) |

## Results at a glance

| ID | Finding | OWASP 2025 | Severity |
|---|---|---|---|
| V-01 | SQL injection in login | A05 Injection | Critical |
| V-02 | Reflected XSS in search | A05 Injection | Medium |
| V-03 | IDOR on notes | A01 Broken Access Control | High |
| V-04 | Plaintext passwords | A04 Cryptographic Failures | High |
| V-05 | Weak authentication and sessions | A07 Authentication Failures | Medium |
| V-06 | Hard-coded secret key | A02 Misconfiguration / A04 | High |
| V-07 | Debug mode and missing headers | A02 Security Misconfiguration | Medium |
| V-08 | Verbose errors, no security logging | A10 Exceptional Conditions / A09 Logging | Medium |

All eight were fixed in `secure_app.py` and verified by re-testing.

## Quick start

```bash
cd lab/app
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

python3 vulnerable_app.py          # terminal 1 -> http://127.0.0.1:5000
APP_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") python3 secure_app.py   # terminal 2 -> http://127.0.0.1:5001
```

Test accounts: `alice / alice123`, `bob / bob123`. Then follow [`lab/secure-web-lab.md`](lab/secure-web-lab.md).

## Tools used

Python 3 and Flask, SQLite, curl, Burp Suite Community, OWASP ZAP, browser developer tools.

## References

- OWASP Top 10:2025: https://owasp.org/Top10/2025/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- Flask security documentation: https://flask.palletsprojects.com/en/stable/web-security/
