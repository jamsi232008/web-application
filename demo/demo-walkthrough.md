# Demo Walkthrough

A step-by-step script for demonstrating the Secure Web Application Lab (about 8 to 10 minutes). Use it for a screen recording or a live demo. Upload the recording to YouTube (unlisted) or Google Drive and add the link at the bottom of this file.

## Before you start

- Two terminals open in `lab/app/` with the virtual environment active.
- Vulnerable app running on port 5000, secure app on port 5001 (see `lab/secure-web-lab.md`).
- Browser with two tabs, plus a terminal for `curl`, and optionally Burp/ZAP running.
- Screen recording tool ready (OBS, Zoom or the built-in recorder).

## Script

### 1. Introduction (30 seconds)
- "I'm Jamsira Farvin, cybersecurity intern at Codomax. This demo shows the Identify, Test, Fix, Document cycle for web application security using the OWASP Top 10:2025."
- State the safety rule: both apps run only on `127.0.0.1` inside my own lab.

### 2. Show the application and the HTTP lifecycle (1 minute)
- Open `http://127.0.0.1:5000`, log in as `alice`.
- In browser developer tools (Network tab) show the `POST /login` request, the `302` response and the `Set-Cookie` header.
- Point out: cookie, session, authentication versus authorization.

### 3. Identify (1 minute)
- Open `vulnerable_app.py` and highlight the f-string SQL query, the unescaped search output, the missing owner check, plaintext passwords, `debug=True`.
- Show the table of suspected weaknesses mapped to OWASP categories (A05, A01, A04, A07, A02, A10).

### 4. Test (3 minutes)
Run each test on port 5000 and show the result.

1. **SQL injection (A05):** `curl -i -d "username=alice' --&password=wrong" http://127.0.0.1:5000/login` → `302` login success without the password.
2. **XSS (A05):** open `http://127.0.0.1:5000/search?q=<b>test</b>` → text renders as bold HTML; explain that a script tag would execute.
3. **IDOR (A01):** log in as Alice, open `/note/2` → Bob's private note is shown.
4. **Plaintext passwords (A04):** `sqlite3 vulnerable.db "SELECT username, password FROM users;"`.
5. **Errors and headers (A02, A10):** `curl -s -d "username='&password=x" http://127.0.0.1:5000/login | head` shows the traceback; `curl -sI` shows no security headers.
6. (Optional) Run a ZAP automated scan and show the Alerts list.

### 5. Fix (1.5 minutes)
- Run `diff -u vulnerable_app.py secure_app.py` or show the two files side by side.
- Walk through each change: parameterised query, `escape()`, ownership check, password hashing, lockout and session handling, headers, `debug=False`, generic error handler and logging.

### 6. Re-test (1.5 minutes)
Repeat the same tests against `http://127.0.0.1:5001` and show the changed results:

- SQLi attempt returns `401`.
- XSS output is `&lt;b&gt;test&lt;/b&gt;`.
- Alice requesting `/note/2` gets `404`; `/note/1` works.
- Security headers appear in `curl -sI`.
- Seven wrong logins for one user lock the account; show the warnings in `secure_app.log`.

### 7. Document and conclude (30 seconds)
- Show `reports/vulnerability-report.md` and `reports/remediation-recommendations.md`.
- Summarise: 8 findings, all fixed and verified; key lessons are never trust input, enforce authorization on the server for every object, store passwords properly, and fail securely with good logging.
- Mention the GitHub repository and thank the viewer.

## Talking points to remember

| Topic | One-liner |
|---|---|
| Why parameterised queries | They keep data separate from code, so input cannot change the query |
| Why output encoding | It turns untrusted text into harmless text in the browser |
| Why server-side authorization | The client can be modified, so every request must be checked on the server |
| Why generic errors | Details help attackers; keep them in server logs |
| Why re-test | A fix is only proven when the original attack no longer works |

## Recording links

- Demo video: `<paste your video link here>`
- Repository: `<paste your GitHub link here>`
