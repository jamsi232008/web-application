# 3. Secure Coding Practices

Secure coding means preventing vulnerabilities while writing the code, rather than finding them afterwards. The examples use Python (Flask and SQLite), but each principle applies to any language.

## 3.1 Core principles

| Principle | Meaning |
|---|---|
| Never trust input | Treat all data from users, headers, cookies, files and APIs as hostile |
| Validate input, encode output | Allow-list inputs; encode for the output context |
| Least privilege | Give users, processes and database accounts only what they need |
| Deny by default | Access is refused unless explicitly granted |
| Fail securely | On error, close access and reveal nothing sensitive |
| Defence in depth | Several independent layers so one failure is not fatal |
| Keep it simple | Complexity hides bugs; reuse vetted libraries rather than inventing crypto |
| Secure defaults | The safe option is the default option |
| Minimise attack surface | Remove unused features, routes, dependencies and ports |

## 3.2 Input validation

```python
import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")

def valid_username(value: str) -> bool:
    return bool(USERNAME_RE.fullmatch(value or ""))
```

- Prefer **allow-lists** (what is permitted) over block-lists (what is forbidden).
- Check type, length, range and format; reject rather than "fix" bad input.
- Validate on the server even if the client also validates.
- Validation reduces risk but does not replace parameterised queries or output encoding.

## 3.3 Preventing SQL injection

**Vulnerable:** the query is built by joining strings.

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cur.execute(query)
```

**Fixed:** parameters are passed separately, so input can never change the query structure.

```python
cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
```

Also: use an ORM carefully (raw queries still need parameters), give the database user only the permissions it needs, and do not display database errors to users.

## 3.4 Preventing Cross-Site Scripting

**Vulnerable:** user input is placed straight into HTML.

```python
return f"<h1>Results for {query}</h1>"
```

**Fixed:** escape on output (templates with auto-escaping do this by default).

```python
from markupsafe import escape
return f"<h1>Results for {escape(query)}</h1>"
```

Additional layers: a Content-Security-Policy that blocks inline scripts, `HttpOnly` cookies, and avoiding `innerHTML` with untrusted data in JavaScript (use `textContent`).

## 3.5 Secure password handling

**Vulnerable:** passwords stored as plain text, or with a fast unsalted hash.

```python
cur.execute("INSERT INTO users VALUES (?, ?)", (username, password))
```

**Fixed:** a slow, salted, purpose-built hash.

```python
from werkzeug.security import generate_password_hash, check_password_hash

hash_ = generate_password_hash(password)          # salted (scrypt/pbkdf2 depending on version)
ok = check_password_hash(stored_hash, submitted)  # constant-time comparison
```

Production systems typically use Argon2id or bcrypt through a maintained library.

## 3.6 Access control (preventing IDOR)

**Vulnerable:** any logged-in user can read any note by changing the ID.

```python
note = cur.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
```

**Fixed:** the query is tied to the authenticated user.

```python
note = cur.execute(
    "SELECT * FROM notes WHERE id = ? AND owner_id = ?", (note_id, session["user_id"])
).fetchone()
if note is None:
    abort(404)
```

Return 404 (or 403) for objects the user does not own, and apply the same check on every route and API method.

## 3.7 Session and cookie hardening (Flask)

```python
app.config.update(
    SECRET_KEY=os.environ["APP_SECRET_KEY"],   # long random value, never hard-coded
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,                # requires HTTPS
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,           # 30 minutes
)
```

- Call `session.clear()` before setting the user at login to avoid fixation.
- On logout, `session.clear()`.
- Use CSRF tokens (for example Flask-WTF) on state-changing forms.

## 3.8 Security headers

```python
@app.after_request
def add_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Cache-Control"] = "no-store"
    return resp
```

## 3.9 Error handling and logging

```python
import logging
logging.basicConfig(filename="app.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

@app.errorhandler(Exception)
def handle_error(e):
    app.logger.exception("Unhandled error")      # details stay on the server
    return "Something went wrong.", 500           # generic message to the user
```

- Turn debug mode off in production (`debug=False`).
- Log logins (success and failure), access denials and validation failures; never log passwords or tokens.
- Fail closed: if a permission check raises an error, deny.

## 3.10 Dependencies and secrets

- Pin versions in `requirements.txt` and scan them: `pip-audit` or `safety check`.
- Keep secrets in environment variables or a secrets manager, never in the repository. Add `.env` to `.gitignore` and use secret scanning (for example GitHub secret scanning or `gitleaks`).
- Remove unused packages and update regularly.

## 3.11 Secure development lifecycle

| Phase | Security activity |
|---|---|
| Requirements | Define security and privacy requirements, abuse cases |
| Design | Threat modelling (STRIDE), secure architecture review |
| Implementation | Secure coding standards, peer review, linters (Bandit for Python) |
| Testing | Unit tests for negative cases, SAST, DAST (ZAP), dependency scanning |
| Deployment | Hardened configuration, secrets management, TLS |
| Operations | Logging, monitoring, patching, incident response |

## 3.12 Secure coding checklist

- [ ] All queries are parameterised
- [ ] All output is encoded for its context
- [ ] Passwords stored with Argon2id/bcrypt/scrypt
- [ ] Authorization enforced on the server for every object and route
- [ ] Session cookies are `HttpOnly`, `Secure`, `SameSite`; sessions regenerate at login
- [ ] Security headers set
- [ ] Debug off, generic error messages, detailed server-side logs
- [ ] Rate limiting on login and other sensitive endpoints
- [ ] Dependencies pinned and scanned; secrets outside the code
- [ ] Negative-path tests written
