# Remediation Recommendations

Recommendations for the Notes training application, prioritised by risk. Each item gives the action, a code reference and how to verify it. The same guidance applies to real web applications.

## 1. Priority order

| Priority | Finding | Action | Effort |
|---|---|---|---|
| P1 (immediate) | V-01 SQL injection | Parameterise every query | Low |
| P1 | V-03 IDOR | Enforce ownership on every object access | Low |
| P1 | V-04 Plaintext passwords | Hash with a slow salted algorithm; force reset | Medium |
| P1 | V-06 Hard-coded secret | Move to environment/secret manager; rotate | Low |
| P2 (this sprint) | V-05 Authentication and sessions | Rate limiting, session hygiene, cookie flags, MFA | Medium |
| P2 | V-02 XSS | Output encoding and CSP | Low |
| P3 (next release) | V-07 Misconfiguration | Disable debug, add headers, hardened deployment | Low |
| P3 | V-08 Errors and logging | Generic errors, central logging and alerts | Medium |

## 2. Detailed recommendations

### R1: Parameterise all database queries (V-01)
```python
# Before
cur.execute(f"SELECT * FROM users WHERE username = '{u}' AND password = '{p}'")
# After
cur.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (u,))
```
- Validate usernames against an allow-list pattern.
- Run the application with a database account that has only the needed privileges.
- **Verify:** injection input returns a normal failure; add a unit test with `' --`.

### R2: Enforce object-level authorisation (V-03)
```python
cur.execute("SELECT body FROM notes WHERE id = ? AND owner_id = ?", (note_id, session["user_id"]))
```
- Apply the same rule to read, update and delete routes and to any API.
- Prefer deny by default; centralise authorisation in one helper or decorator.
- **Verify:** automated tests with two users confirming user A cannot access user B's IDs.

### R3: Store passwords securely (V-04)
- Use Argon2id, bcrypt or scrypt (`generate_password_hash` in Werkzeug for this lab).
- Migrate existing users: hash at next login, or force a password reset.
- Enforce a minimum length of 12 characters and screen against breached passwords.
- **Verify:** inspect the database, no plain-text values remain.

### R4: Protect secrets (V-06)
- Load `SECRET_KEY` from an environment variable or secrets manager; generate with `secrets.token_hex(32)`.
- Rotate the key if it was ever committed; add `.env` to `.gitignore`; enable secret scanning on the repository.
- **Verify:** `git grep -n "secret_key"` shows no literal values.

### R5: Harden authentication and sessions (V-05)
- Rate limit and lock out repeated failures (for production use Flask-Limiter or a WAF, and track by user and IP).
- Clear the session at login (`session.clear()`) and at logout; set an idle and absolute lifetime.
- Cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict`).
- Return identical error messages for unknown user and wrong password.
- Add multi-factor authentication for sensitive accounts and CSRF tokens on state-changing forms.
- **Verify:** repeated failures trigger lockout; `Set-Cookie` shows all flags over HTTPS.

### R6: Encode output and add CSP (V-02)
```python
return f"<h1>Results for {escape(q)}</h1>"
```
- Use auto-escaping templates (Jinja2 `render_template`) rather than building HTML strings.
- Add `Content-Security-Policy: default-src 'self'` and avoid inline scripts.
- In JavaScript use `textContent`, not `innerHTML`, for untrusted data.
- **Verify:** payload displays as text; ZAP finds no reflected XSS.

### R7: Harden configuration (V-07)
- `debug=False` in all non-development environments; run behind a production WSGI server (Gunicorn/uWSGI) and a reverse proxy with TLS.
- Add headers: CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Strict-Transport-Security` (over HTTPS), `Cache-Control: no-store` for authenticated pages.
- Remove unused routes, packages and default accounts.
- **Verify:** `curl -I` shows all headers; ZAP baseline scan reports no missing-header alerts.

### R8: Handle errors safely and log security events (V-08)
- Central error handler returns a generic message; full details go to server logs only.
- Fail closed: any exception in a permission check results in denial.
- Log login success/failure, lockouts, access denials and validation failures with time, user and source IP, never passwords or tokens.
- Ship logs to a central system and alert on bursts of failures.
- **Verify:** trigger malformed input and failed logins, confirm generic responses and matching log entries.

## 3. Supporting practices

| Area | Recommendation |
|---|---|
| Dependencies (A03) | Pin versions, run `pip-audit`, keep an SBOM, update regularly |
| Secure SDLC | Threat model features, code review with a security checklist, SAST (Bandit), DAST (ZAP) in CI |
| Testing | Include negative-path and abuse-case unit tests |
| Transport | HTTPS everywhere, HSTS, TLS 1.2 or newer |
| Training | Regular secure coding training for the team |
| Response | Documented incident response and vulnerability disclosure process |

## 4. Verification checklist

- [ ] Injection payload no longer bypasses login
- [ ] User A cannot read user B's notes
- [ ] Password column contains only hashes
- [ ] No secrets in the repository
- [ ] Lockout works; cookie flags set; session cleared at logout
- [ ] Search input is encoded; CSP present
- [ ] Debug off; all security headers present
- [ ] Errors are generic; security events appear in logs
- [ ] ZAP re-scan of the fixed app shows fewer alerts than the vulnerable app
