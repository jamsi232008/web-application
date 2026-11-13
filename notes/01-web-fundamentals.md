# 1. How Web Applications Work

## 1.1 Architecture

A web application is split between a **client** (browser, mobile app) and a **server** side made of a web server, application logic and a data store.

| Tier | Role | Typical technology | Security concern |
|---|---|---|---|
| Client | Renders UI, runs JavaScript | HTML, CSS, JS, React | XSS, insecure storage, trusting client-side checks |
| Web server / reverse proxy | Terminates TLS, serves static files, routes requests | Nginx, Apache | Misconfiguration, verbose headers |
| Application server | Business logic, authentication, sessions | Flask, Django, Node/Express, Spring | Injection, broken access control |
| Database | Persistent data | MySQL, PostgreSQL, MongoDB, SQLite | SQL injection, excessive privileges |
| External services / APIs | Payments, email, identity | REST, GraphQL | SSRF, supply chain, leaked keys |

**Golden rule:** the client is controlled by the user (and attacker). Every check that matters must be repeated on the server.

## 1.2 HTTP request/response lifecycle

1. **DNS lookup:** the browser resolves the hostname to an IP address.
2. **TCP connection:** three-way handshake to port 80 or 443.
3. **TLS handshake (HTTPS):** server certificate verified, session keys agreed.
4. **HTTP request:** browser sends method, path, headers and optional body.
5. **Server processing:** routing, authentication, authorization, business logic, database queries.
6. **HTTP response:** status code, headers and body.
7. **Rendering:** browser parses HTML, loads CSS, JS and images (more requests), executes scripts.

### Anatomy of a request

```
POST /login HTTP/1.1
Host: shop.example.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123
Content-Length: 31

username=alice&password=secret1
```

### Anatomy of a response

```
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session=9f8e...; HttpOnly; Secure; SameSite=Lax; Path=/
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### HTTP methods

| Method | Purpose | Safe | Idempotent |
|---|---|---|---|
| GET | Retrieve a resource | Yes | Yes |
| POST | Submit data, create | No | No |
| PUT | Replace a resource | No | Yes |
| PATCH | Partially update | No | No |
| DELETE | Remove | No | Yes |
| OPTIONS / HEAD | Capabilities / headers only | Yes | Yes |

State-changing actions must never be done with GET (links and images can trigger them, which enables CSRF).

### Status codes

| Class | Examples | Meaning |
|---|---|---|
| 2xx | 200 OK, 201 Created | Success |
| 3xx | 301, 302, 304 | Redirection |
| 4xx | 400, 401 Unauthorized, 403 Forbidden, 404, 429 Too Many Requests | Client error |
| 5xx | 500, 502, 503 | Server error (never expose stack traces) |

### Important security headers

| Header | Purpose |
|---|---|
| `Content-Security-Policy` | Restricts where scripts, styles and frames may load from (mitigates XSS) |
| `Strict-Transport-Security` | Forces HTTPS in the browser |
| `X-Content-Type-Options: nosniff` | Stops MIME-type sniffing |
| `X-Frame-Options` / CSP `frame-ancestors` | Prevents clickjacking |
| `Referrer-Policy` | Limits URL leakage |
| `Permissions-Policy` | Restricts browser features |
| `Cache-Control: no-store` | Keeps sensitive pages out of caches |

## 1.3 Statelessness, cookies and sessions

HTTP is **stateless**: each request is independent. Applications add state using cookies and sessions.

### Cookies

A cookie is a small piece of data the server asks the browser to store and send back with later requests to the same site.

| Attribute | Effect | Why it matters |
|---|---|---|
| `HttpOnly` | JavaScript cannot read the cookie | Limits session theft via XSS |
| `Secure` | Sent only over HTTPS | Prevents sniffing on plain HTTP |
| `SameSite=Lax/Strict` | Limits cross-site sending | Reduces CSRF |
| `Path`, `Domain` | Scope of the cookie | Avoid over-broad scope |
| `Max-Age` / `Expires` | Lifetime | Short lifetimes limit exposure |

### Sessions

1. User logs in; the server creates a **session** (server-side record) with a long, random, unpredictable **session ID**.
2. The ID is sent to the browser in a cookie.
3. Each request carries the cookie; the server looks up the session to identify the user.
4. On logout or timeout the server destroys the session.

**Session security checklist**
- Generate IDs with a cryptographically secure random generator (at least 128 bits).
- Issue a **new** session ID after login (prevents session fixation).
- Invalidate sessions on logout and after inactivity; expire absolute lifetime.
- Never put session IDs in URLs.
- Bind high-risk actions to re-authentication.

### Token-based alternatives

| Mechanism | Description | Cautions |
|---|---|---|
| Server-side session ID | Opaque ID, data stored on server | Needs shared store when scaling |
| JWT | Signed token holding claims | Validate signature and algorithm, set short expiry, plan revocation |
| OAuth 2.0 / OpenID Connect | Delegated authorization / identity | Validate redirect URIs, use PKCE, check `state` |

## 1.4 Authentication vs authorization

| | Authentication (AuthN) | Authorization (AuthZ) |
|---|---|---|
| Question | Who are you? | What are you allowed to do? |
| Evidence | Password, MFA code, biometric, key | Roles, permissions, ownership |
| Failure looks like | Credential stuffing, weak reset flow | Viewing another user's data (IDOR), privilege escalation |
| When checked | At login, and on sensitive actions | On **every** request to a protected resource |

### Authentication best practices
- Store passwords only as salted hashes using Argon2id, bcrypt or scrypt.
- Enforce length (12 or more characters) and check against breached-password lists.
- Offer MFA; rate-limit and lock out repeated failures.
- Use generic error messages ("Invalid username or password").
- Secure password reset: single-use, short-lived tokens delivered out of band.

### Authorization best practices
- Deny by default; grant the least privilege required.
- Enforce checks on the server for every request, including APIs.
- Check **object-level** ownership (does this user own record 42?), not just the role.
- Centralise access control logic rather than scattering ad hoc checks.
- Log access control failures.

### Models
RBAC (roles), ABAC (attributes), ACLs (per-object lists), and ownership checks are combined in real applications.

## 1.5 Same-origin policy, CORS and CSRF

- **Same-Origin Policy:** scripts from one origin (scheme + host + port) cannot read responses from another.
- **CORS:** a controlled relaxation using headers such as `Access-Control-Allow-Origin`. Never reflect arbitrary origins or combine `*` with credentials.
- **CSRF:** a malicious site causes the victim's browser to send an authenticated request. Defend with `SameSite` cookies, anti-CSRF tokens and checking `Origin`/`Referer`.

## 1.6 Input, output and trust boundaries

Every place where data crosses from an untrusted source (form fields, URL parameters, headers, cookies, uploaded files, third-party APIs) into the application is a trust boundary. The two controls used there:

- **Validate input** (allow-lists for type, length, format and range).
- **Encode output** for the context in which it is used (HTML, attribute, JavaScript, URL, SQL parameter).

## 1.7 Summary

| Concept | One-line takeaway |
|---|---|
| HTTP | Stateless request/response; everything the client sends can be forged |
| Cookies | Use `HttpOnly`, `Secure`, `SameSite` |
| Sessions | Random IDs, regenerate on login, expire and destroy properly |
| AuthN vs AuthZ | Prove identity once, check permission on every request |
| Trust boundaries | Validate input, encode output, never trust the client |
