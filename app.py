"""
CS Department Employee Portal — Intentionally Vulnerable Flask + SQLite App
Vulnerabilities: SQL Injection, Stored XSS, IDOR, Broken Auth, No Input Validation
FOR EDUCATIONAL / SECURITY TRAINING PURPOSES ONLY
"""

import sqlite3, os, json
from flask import Flask, request, jsonify, render_template, g, session

app = Flask(__name__)
app.secret_key = "supersecretkey123"   # VULN: hardcoded weak secret
DB_PATH = "employees.db"

# ──────────────────────────────────────────────
#  DATABASE HELPERS
# ──────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    if os.path.exists(DB_PATH):
        return
    db = sqlite3.connect(DB_PATH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL        -- VULN: plaintext password
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            emp_id         TEXT,
            name           TEXT,
            department     TEXT,
            worker_type    TEXT,
            specialization TEXT,
            email          TEXT,
            password       TEXT,          -- VULN: plaintext
            notes          TEXT,
            registered_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            author     TEXT,
            message    TEXT,
            posted_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            filename  TEXT,
            locked    INTEGER DEFAULT 0
        )
    """)
    # Seed users
    db.executemany("INSERT INTO users (username,password) VALUES (?,?)", [
        ("admin",   "admin123"),
        ("karim",   "karim2024"),
        ("fatima",  "fatima99"),
    ])
    # Seed employees
    db.executemany("""INSERT INTO employees
        (emp_id,name,department,worker_type,specialization,email,password,notes) VALUES
        (?,?,?,?,?,?,?,?)""", [
        ("EMP-001","Dr. Karim Bensalem","Computer Science","Professor","Cybersecurity","k.bensalem@cs.univ.dz","admin123","Department head."),
        ("EMP-002","Mme. Fatima Ouali","AI & Data Science","Associate Professor","Machine Learning","f.ouali@cs.univ.dz","fatima2024","Runs the AI lab."),
        ("EMP-003","M. Yacine Meziane","Networks & Security","Lecturer","Network Protocols","y.meziane@cs.univ.dz","yacine99","Teaches Cisco courses."),
        ("EMP-004","Sarah Hamdi","Software Engineering","PhD Researcher","Formal Verification","s.hamdi@cs.univ.dz","sarah!phd","PhD year 2."),
        ("EMP-005","M. Amine Tlemcani","Systems & Architecture","Lab Technician","Hardware & Embedded","a.tlemcani@cs.univ.dz","labo2025","Manages server room."),
    ])
    # Seed comments
    db.executemany("INSERT INTO comments (author,message) VALUES (?,?)", [
        ("Admin",  "Welcome to the CS Department portal."),
        ("HR",     "Reminder: submit timesheets before end of month."),
    ])
    # Seed files
    for f in ["employees_backup.csv","payroll_Q2_2025.xlsx","network_topology.pdf",
              "admin_passwords.txt","student_records_2025.db","server_config.json"]:
        db.execute("INSERT INTO files (filename) VALUES (?)", (f,))
    db.commit()
    db.close()

# ──────────────────────────────────────────────
#  FRONTEND
# ──────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

# ──────────────────────────────────────────────
#  AUTH — INTENTIONALLY VULNERABLE (SQLi)
# ──────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username", "")
    password  = data.get("password",  "")

    db = get_db()
    # ⚠ VULNERABILITY: Raw string interpolation → SQL Injection
    # e.g. username = admin' -- bypasses password check entirely
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        row = db.execute(query).fetchone()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "query": query}), 400

    if row:
        session["user"] = username
        return jsonify({"ok": True, "user": username, "query": query})
    else:
        return jsonify({"ok": False, "query": query})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})

# ──────────────────────────────────────────────
#  EMPLOYEES
# ──────────────────────────────────────────────
@app.route("/api/employees", methods=["GET"])
def get_employees():
    # VULN: no auth check — anyone can call this
    db = get_db()
    rows = db.execute("SELECT * FROM employees ORDER BY id DESC").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/employees/<int:eid>", methods=["GET"])
def get_employee(eid):
    # VULN: IDOR — direct integer ID, no ownership check
    db = get_db()
    row = db.execute("SELECT * FROM employees WHERE id=?", (eid,)).fetchone()
    if row:
        return jsonify(dict(row))
    return jsonify({"error": "Not found"}), 404

@app.route("/api/employees", methods=["POST"])
def add_employee():
    # VULN: no input validation, no sanitization
    d = request.json
    db = get_db()
    db.execute("""INSERT INTO employees
        (emp_id,name,department,worker_type,specialization,email,password,notes)
        VALUES (?,?,?,?,?,?,?,?)""",
        (d.get("emp_id",""), d.get("name",""), d.get("department",""),
         d.get("worker_type",""), d.get("specialization",""),
         d.get("email",""), d.get("password",""), d.get("notes","")))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/employees/<int:eid>", methods=["DELETE"])
def delete_employee(eid):
    # VULN: no auth check, no audit log
    db = get_db()
    db.execute("DELETE FROM employees WHERE id=?", (eid,))
    db.commit()
    return jsonify({"ok": True})

# ──────────────────────────────────────────────
#  SEARCH — REAL SQL INJECTION
# ──────────────────────────────────────────────
@app.route("/api/search", methods=["GET"])
def search():
    term = request.args.get("q", "")
    db = get_db()
    # ⚠ VULNERABILITY: Raw string interpolation in real SQLite query
    # Try: ' OR '1'='1  or  ' UNION SELECT id,username,password,password,password,password,password,password,password,registered_at FROM users--
    query = f"SELECT * FROM employees WHERE name LIKE '%{term}%' OR department LIKE '%{term}%' OR emp_id LIKE '%{term}%'"
    try:
        rows = db.execute(query).fetchall()
        return jsonify({"results": [dict(r) for r in rows], "query": query, "injected": False})
    except Exception as e:
        return jsonify({"results": [], "query": query, "error": str(e), "injected": True}), 400

# ──────────────────────────────────────────────
#  COMMENTS — STORED XSS
# ──────────────────────────────────────────────
@app.route("/api/comments", methods=["GET"])
def get_comments():
    db = get_db()
    rows = db.execute("SELECT * FROM comments ORDER BY id DESC").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/comments", methods=["POST"])
def add_comment():
    # VULN: stored as-is, rendered with innerHTML on frontend
    d = request.json
    db = get_db()
    db.execute("INSERT INTO comments (author,message) VALUES (?,?)",
               (d.get("author","Anonymous"), d.get("message","")))
    db.commit()
    return jsonify({"ok": True})

# ──────────────────────────────────────────────
#  FILES — RANSOMWARE SIMULATION
# ──────────────────────────────────────────────
@app.route("/api/files", methods=["GET"])
def get_files():
    db = get_db()
    rows = db.execute("SELECT * FROM files").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/files", methods=["POST"])
def add_file():
    d = request.json
    db = get_db()
    db.execute("INSERT INTO files (filename) VALUES (?)", (d.get("filename","unnamed"),))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/files/encrypt", methods=["POST"])
def encrypt_files():
    # Simulate ransomware — rename all files to .locked
    db = get_db()
    import base64
    rows = db.execute("SELECT * FROM files WHERE locked=0").fetchall()
    for r in rows:
        enc_name = base64.b64encode(r["filename"].encode()).decode()[:16] + ".locked"
        db.execute("UPDATE files SET filename=?, locked=1 WHERE id=?", (enc_name, r["id"]))
    db.commit()
    return jsonify({"ok": True, "affected": len(rows)})

@app.route("/api/files/decrypt", methods=["POST"])
def decrypt_files():
    db = get_db()
    import base64
    rows = db.execute("SELECT * FROM files WHERE locked=1").fetchall()
    for r in rows:
        try:
            padded = r["filename"].replace(".locked","")
            padded += "=" * (4 - len(padded) % 4)
            original = base64.b64decode(padded).decode()
        except:
            original = "recovered_" + r["filename"]
        db.execute("UPDATE files SET filename=?, locked=0 WHERE id=?", (original, r["id"]))
    db.commit()
    return jsonify({"ok": True})

# ──────────────────────────────────────────────
#  STATS
# ──────────────────────────────────────────────
@app.route("/api/stats", methods=["GET"])
def stats():
    db = get_db()
    emp_count  = db.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
    dept_count = db.execute("SELECT COUNT(DISTINCT department) FROM employees").fetchone()[0]
    com_count  = db.execute("SELECT COUNT(*) FROM comments").fetchone()[0]
    file_count = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    return jsonify({"employees": emp_count, "departments": dept_count,
                    "comments": com_count, "files": file_count})

# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5050, debug=True)
