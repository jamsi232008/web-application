"""
vulnerable_app.py  --  INTENTIONALLY INSECURE training application.

For the Secure Web Application Lab only. It binds to 127.0.0.1 so it is reachable
only from your own machine. NEVER deploy it, expose it to a network, or reuse
its patterns. The secure version is secure_app.py.

Deliberate weaknesses (OWASP Top 10:2025):
  A05 Injection ........ SQL injection in /login, reflected XSS in /search
  A01 Access Control ... IDOR in /note/<id>
  A04 Crypto Failures .. plaintext passwords
  A07 Auth Failures .... no rate limiting, session cookie without Secure/SameSite,
                         session not cleared/renewed at login, no logout route
  A02 Misconfiguration . debug mode on, no security headers
  A10 Exceptional Cond.. verbose error output
"""
import sqlite3
from flask import Flask, request, session, redirect, g

app = Flask(__name__)
app.secret_key = "dev"          # weak, hard-coded secret (A02/A04)
DB = "vulnerable.db"


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
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT);
        INSERT INTO users VALUES (1,'alice','alice123'),(2,'bob','bob123');
        INSERT INTO notes VALUES (1,1,'Alice private note: project codename ORION'),
                                 (2,2,'Bob private note: bank PIN reminder 4821');
    """)
    db.commit()
    db.close()


@app.route("/")
def index():
    who = session.get("username")
    return f"<h1>Notes (vulnerable)</h1><p>Logged in as: {who}</p>" \
           "<a href='/login'>Login</a> | <a href='/search?q=test'>Search</a>"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return ("<form method='post'>User <input name='username'> "
                "Pass <input name='password' type='password'> "
                "<button>Login</button></form>")
    u, p = request.form["username"], request.form["password"]
    # A05: SQL built with string formatting -> SQL injection
    query = f"SELECT * FROM users WHERE username = '{u}' AND password = '{p}'"
    row = get_db().execute(query).fetchone()
    if row:
        session["user_id"], session["username"] = row["id"], row["username"]
        return redirect("/")
    return "Invalid credentials", 401


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # A05: reflected XSS - input echoed without encoding
    return f"<h1>Results for {q}</h1><p>No results.</p>"


@app.route("/note/<int:note_id>")
def note(note_id):
    if "user_id" not in session:
        return redirect("/login")
    # A01: no ownership check -> IDOR
    row = get_db().execute("SELECT * FROM notes WHERE id = " + str(note_id)).fetchone()
    return row["body"] if row else ("Not found", 404)


if __name__ == "__main__":
    init_db()
    # A02: debug mode exposes the Werkzeug debugger and stack traces (A10)
    app.run(host="127.0.0.1", port=5000, debug=True)
