# Secure Web Application Lab: Identify → Test → Fix → Document

## 1. Goal

Practise the full lifecycle of finding and fixing web vulnerabilities inside a safe sandbox:

1. **Identify:** review the code and the running app to spot weaknesses and map them to the OWASP Top 10:2025.
2. **Test:** confirm each weakness with a minimal, harmless proof.
3. **Fix:** apply secure coding changes.
4. **Document:** record evidence, impact and remediation, then re-test.

## 2. Safety rules

- The training app binds to `127.0.0.1` only; it is reachable from your own computer and nowhere else.
- Run it inside a VM (for example your Kali VM from Module 1) or a Python virtual environment, never on a shared or public machine.
- Do not deploy `vulnerable_app.py` or expose port 5000 to any network.
- Test only the apps in this lab. Never test websites you do not own or have written permission to test.

## 3. Lab environment

| Item | Details |
|---|---|
| OS | Kali Linux VM (or any Linux/macOS/Windows with Python 3.9+) |
| Targets | `lab/app/vulnerable_app.py` (port 5000) and `lab/app/secure_app.py` (port 5001) |
| Tools | Browser, `curl`, Burp Suite Community, OWASP ZAP |
| Optional extra target | OWASP Juice Shop: `docker run -d -p 127.0.0.1:3000:3000 bkimminich/juice-shop` |

### Setup

```bash
cd lab/app
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Terminal 1 - vulnerable version
python3 vulnerable_app.py          # http://127.0.0.1:5000  (alice/alice123, bob/bob123)

# Terminal 2 - secure version
APP_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") python3 secure_app.py   # http://127.0.0.1:5001
```

## 4. Phase 1: Identify

Read `vulnerable_app.py` and list suspicious patterns. Expected result:

| # | Code observation | Suspected weakness | OWASP 2025 |
|---|---|---|---|
| 1 | SQL built with an f-string in `/login` | SQL injection | A05 |
| 2 | `/search` returns `q` inside HTML unescaped | Reflected XSS | A05 |
| 3 | `/note/<id>` has no owner check | IDOR | A01 |
| 4 | Passwords stored and compared in plain text | Cryptographic failure | A04 |
| 5 | No rate limit; no logout; session not cleared; cookie lacks `Secure` and `SameSite` | Authentication/session weakness | A07 |
| 6 | `app.secret_key = "dev"` | Hard-coded weak secret | A02/A04 |
| 7 | `debug=True`, no security headers | Misconfiguration | A02 |
| 8 | Raw exceptions reach the user, no security logging | Exceptional conditions, logging | A10/A09 |

Also run a **ZAP baseline/automated scan** against `http://127.0.0.1:5000` and add any extra alerts (missing headers, cookie flags) to your list.

## 5. Phase 2: Test (against the lab app only)

Run each test and take a screenshot into `../screenshots/`.

### T1: SQL injection (V-01)
```bash
# Valid login for reference
curl -i -d "username=alice&password=alice123" http://127.0.0.1:5000/login
# Wrong password but the password check is commented out by the input
curl -i -d "username=alice' --&password=wrong" http://127.0.0.1:5000/login
```
**Expected:** both return `302` (login success). The second should have been rejected.

### T2: Reflected XSS (V-02)
```bash
curl "http://127.0.0.1:5000/search?q=<b>test</b>"
```
Open the same URL in the browser. **Expected:** the tag is rendered as HTML instead of shown as text, proving input is not encoded. (A `<script>` payload behaves the same way; use a harmless `alert(1)` only in your own browser.)

### T3: IDOR (V-03)
```bash
curl -c jar.txt -d "username=alice&password=alice123" http://127.0.0.1:5000/login
curl -b jar.txt http://127.0.0.1:5000/note/1     # Alice's own note
curl -b jar.txt http://127.0.0.1:5000/note/2     # Bob's note - should be forbidden
```
**Expected:** Alice can read Bob's note.

### T4: Plaintext passwords (V-04)
```bash
sqlite3 vulnerable.db "SELECT username, password FROM users;"
```
**Expected:** passwords are readable.

### T5: Session and cookie weaknesses (V-05, V-06)
```bash
curl -si -d "username=alice&password=alice123" http://127.0.0.1:5000/login | grep -i set-cookie
```
**Expected:** `HttpOnly` is present (Flask's default) but `Secure` and `SameSite` are missing. Try 20 wrong passwords for one user: no lockout or delay.

### T6: Misconfiguration and error leakage (V-07, V-08)
```bash
curl -sI http://127.0.0.1:5000/ | grep -iE "content-security|x-frame|x-content"   # nothing returned
curl -s -d "username='&password=x" http://127.0.0.1:5000/login | head -n 20       # stack trace / debugger page
```
**Expected:** no security headers; a `500` page that exposes the traceback and the SQL error.

## 6. Phase 3: Fix

`secure_app.py` contains the fixes. Compare the two files (`diff -u vulnerable_app.py secure_app.py`) and map each change to its finding:

| Finding | Fix applied |
|---|---|
| V-01 SQL injection | Parameterised query plus username allow-list validation |
| V-02 XSS | Output encoding with `escape()`; CSP header |
| V-03 IDOR | Query includes `owner_id = session user`; 404 on mismatch |
| V-04 Plaintext passwords | `generate_password_hash` / `check_password_hash` |
| V-05 Authentication/session | Failed-attempt lockout, `session.clear()` at login, logout route, `SameSite=Lax`, `Secure` when HTTPS, 30-minute lifetime |
| V-06 Weak secret | Secret key from environment or random bytes |
| V-07 Misconfiguration | `debug=False`, security headers added |
| V-08 Errors and logging | Generic error handler, server-side log of logins, denials and failures |

## 7. Re-test (verification)

Repeat T1 to T6 against `http://127.0.0.1:5001`. Expected results:

| Test | Vulnerable (5000) | Secure (5001) |
|---|---|---|
| T1 SQLi bypass | 302 login success | 401 "Invalid username or password" |
| T2 XSS | `<script>` returned raw | Returned as `&lt;script&gt;` (inert text) |
| T3 IDOR on Bob's note | Note contents returned | 404; own note still 200 |
| T4 Passwords | Plain text | Salted hashes only |
| T5 Cookie / brute force | No `SameSite`; unlimited attempts | `SameSite=Lax`; lockout after 5 failures (correct password also refused while locked) |
| T6 Headers / errors | No headers; 500 with traceback | CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Cache-Control` present; malformed input returns a generic 401 |

Finally run the same ZAP scan against port 5001 and compare alert counts.

## 8. Document

For every finding record: ID, OWASP category, location, evidence (command and output or screenshot), severity, impact, remediation and re-test result. The completed write-up is in:

- [`../reports/vulnerability-report.md`](../reports/vulnerability-report.md)
- [`../reports/remediation-recommendations.md`](../reports/remediation-recommendations.md)
- [`../demo/demo-walkthrough.md`](../demo/demo-walkthrough.md)

## 9. Clean-up

```bash
pkill -f vulnerable_app.py; pkill -f secure_app.py
rm -f lab/app/*.db lab/app/*.log
deactivate
```
