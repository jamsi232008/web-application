"""
secure_app.py  --  the remediated version of vulnerable_app.py.

Every fix is tagged with the finding it addresses (see reports/).
Run locally:  APP_SECRET_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))") python3 secure_app.py
"""
import os
import re
import time
import sqlite3
import logging
from flask import Flask, request, session, redirect, g, abort
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("APP_SECRET_KEY") or os.urandom(32),   # V-06: no hard-coded secret
    SESSION_COOKIE_HTTPONLY=True,                                     # V-05
    SESSION_COOKIE_SAMESITE="Lax",                                    # V-05
    SESSION_COOKIE_SECURE=os.environ.get("APP_HTTPS") == "1",         # V-05 (needs HTTPS)
    PERMANENT_SESSION_LIFETIME=1800,                                  # V-05
)
DB = "secure.db"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
FAILED = {}                       # username -> (count, first_failure_time) ; demo-grade rate limit
MAX_FAILS, WINDOW = 5, 300

logging.basicConfig(filename="secure_app.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")      # V-08


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB)
    db.executescript("""
        DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS notes;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT);
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT);
    """)
    db.execute("INSERT INTO users VALUES (1,'alice',?)", (generate_password_hash("alice123"),))  # V-04
    db.execute("INSERT INTO users VALUES (2,'bob',?)", (generate_password_hash("bob123"),))
    db.execute("INSERT INTO notes VALUES (1,1,'Alice private note: project codename ORION')")
    db.execute("INSERT INTO notes VALUES (2,2,'Bob private note: bank PIN reminder 4821')")
    db.commit()
    db.close()


@app.after_request
def security_headers(resp):                                              # V-07
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(Exception)
def handle_error(exc):                                                   # V-08: generic errors
    if hasattr(exc, "code") and isinstance(exc.code, int) and exc.code < 500:
        return exc.get_response()
    app.logger.exception("Unhandled error")
    return "Something went wrong.", 500


@app.route("/")
def index():
    who = escape(session.get("username", "nobody"))
    return f"<h1>Notes (secure)</h1><p>Logged in as: {who}</p>" \
           "<a href='/login'>Login</a> | <a href='/search?q=test'>Search</a>"


def locked_out(username):
    count, first = FAILED.get(username, (0, 0))
    if count >= MAX_FAILS and time.time() - first < WINDOW:
        return True
    if time.time() - first >= WINDOW:
        FAILED.pop(username, None)
    return False


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return ("<form method='post'>User <input name='username'> "
                "Pass <input name='password' type='password'> "
                "<button>Login</button></form>")
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    if not USERNAME_RE.fullmatch(u) or locked_out(u):                    # V-01 / V-05 validation + throttling
        app.logger.warning("Rejected login attempt for %r from %s", u[:30], request.remote_addr)
        return "Invalid username or password", 401
    row = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?", (u,)   # V-01 parameterised
    ).fetchone()
    if row and check_password_hash(row["password_hash"], p):
        session.clear()                                                  # V-05 new session on login
        session["user_id"], session["username"] = row["id"], row["username"]
        app.logger.info("Login success: %s", u)
        return redirect("/")
    count, first = FAILED.get(u, (0, time.time()))
    FAILED[u] = (count + 1, first)
    app.logger.warning("Login failure: %s", u)
    return "Invalid username or password", 401                           # generic message


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h1>Results for {escape(q)}</h1><p>No results.</p>"        # V-02 output encoding


@app.route("/note/<int:note_id>")
def note(note_id):
    if "user_id" not in session:
        return redirect("/login")
    row = get_db().execute(
        "SELECT body FROM notes WHERE id = ? AND owner_id = ?",          # V-03 ownership check
        (note_id, session["user_id"]),
    ).fetchone()
    if row is None:
        app.logger.warning("Access denied: user %s -> note %s", session["user_id"], note_id)
        abort(404)
    return escape(row["body"])


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001, debug=False)                    # V-07 debug off
