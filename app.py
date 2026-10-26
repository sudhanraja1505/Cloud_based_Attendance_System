"""Cloud-Based Student Attendance System - Flask + SQLite backend.
Run:  python -m pip install -r requirements.txt  then  python app.py
Cloud: use PostgreSQL (RDS) instead of SQLite; run behind gunicorn (Linux) or waitress (Windows)."""
import csv, io, os, secrets, sqlite3, time
from datetime import datetime, timedelta, timezone
from functools import wraps
import jwt
from flask import Flask, request, jsonify, g, Response
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
SECRET = os.environ.get("SECRET_KEY", "change-me-in-production")
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "attendance.db"))
MIN_PERCENT = 75  # shown as a warning threshold

app = Flask(__name__, static_folder="static", static_url_path="")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('student','teacher')));
CREATE TABLE IF NOT EXISTS courses(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
  join_code TEXT UNIQUE NOT NULL, teacher_id INTEGER NOT NULL REFERENCES users(id));
CREATE TABLE IF NOT EXISTS enrollments(
  course_id INTEGER NOT NULL REFERENCES courses(id), student_id INTEGER NOT NULL REFERENCES users(id),
  PRIMARY KEY(course_id, student_id));
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, course_id INTEGER NOT NULL REFERENCES courses(id),
  code TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attendance(
  session_id INTEGER NOT NULL REFERENCES sessions(id), student_id INTEGER NOT NULL REFERENCES users(id),
  status TEXT NOT NULL CHECK(status IN ('present','absent')), marked_at TEXT NOT NULL,
  method TEXT NOT NULL, PRIMARY KEY(session_id, student_id));
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

with sqlite3.connect(DB_PATH) as c:
    c.executescript(SCHEMA)

def now(): return datetime.now(timezone.utc)
def iso(t): return t.isoformat(timespec="seconds")

def make_token(u):
    return jwt.encode({"sub": str(u["id"]), "role": u["role"], "name": u["name"],
                       "exp": now() + timedelta(hours=12)}, SECRET, algorithm="HS256")

def auth(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            try:
                p = jwt.decode(request.headers.get("Authorization", "").removeprefix("Bearer "), SECRET, algorithms=["HS256"])
            except jwt.PyJWTError:
                return jsonify(error="Please sign in again."), 401
            if roles and p["role"] not in roles:
                return jsonify(error="You don't have access to this."), 403
            g.user = {"id": int(p["sub"]), "role": p["role"], "name": p["name"]}
            return fn(*a, **kw)
        return wrapper
    return deco

# ---- accounts
@app.post("/api/register")
def register():
    d = request.get_json(force=True)
    if not all(d.get(k) for k in ("name", "email", "password", "role")) or d["role"] not in ("student", "teacher"):
        return jsonify(error="Fill in name, email, password and role."), 400
    if len(d["password"]) < 6:
        return jsonify(error="Password must be at least 6 characters."), 400
    try:
        cur = db().execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)",
                           (d["name"].strip(), d["email"].lower().strip(), generate_password_hash(d["password"]), d["role"]))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="That email is already registered."), 409
    u = {"id": cur.lastrowid, "role": d["role"], "name": d["name"].strip()}
    return jsonify(token=make_token(u), role=u["role"], name=u["name"])

@app.post("/api/login")
def login():
    d = request.get_json(force=True)
    u = db().execute("SELECT * FROM users WHERE email=?", (d.get("email", "").lower().strip(),)).fetchone()
    if not u or not check_password_hash(u["password"], d.get("password", "")):
        return jsonify(error="Email or password is incorrect."), 401
    return jsonify(token=make_token(u), role=u["role"], name=u["name"])

# ---- courses
@app.get("/api/courses")
@auth()
def courses():
    uid = g.user["id"]
    if g.user["role"] == "teacher":
        rows = db().execute("""SELECT c.*, (SELECT COUNT(*) FROM enrollments e WHERE e.course_id=c.id) AS students,
            (SELECT COUNT(*) FROM sessions s WHERE s.course_id=c.id) AS sessions
            FROM courses c WHERE teacher_id=? ORDER BY c.name""", (uid,))
    else:
        rows = db().execute("""SELECT c.id, c.name, u.name AS teacher,
            (SELECT COUNT(*) FROM sessions s WHERE s.course_id=c.id) AS sessions,
            (SELECT COUNT(*) FROM attendance a JOIN sessions s ON s.id=a.session_id
               WHERE s.course_id=c.id AND a.student_id=? AND a.status='present') AS present
            FROM enrollments e JOIN courses c ON c.id=e.course_id JOIN users u ON u.id=c.teacher_id
            WHERE e.student_id=? ORDER BY c.name""", (uid, uid))
    return jsonify(courses=[dict(r) for r in rows], min_percent=MIN_PERCENT)

@app.post("/api/courses")
@auth("teacher")
def create_course():
    name = (request.get_json(force=True).get("name") or "").strip()
    if not name: return jsonify(error="Enter a class name."), 400
    for _ in range(5):
        try:
            db().execute("INSERT INTO courses(name,join_code,teacher_id) VALUES(?,?,?)",
                         (name, secrets.token_hex(3).upper(), g.user["id"]))
            db().commit(); return jsonify(ok=True), 201
        except sqlite3.IntegrityError:
            continue
    return jsonify(error="Could not create the class. Try again."), 500

@app.post("/api/courses/join")
@auth("student")
def join():
    code = (request.get_json(force=True).get("code") or "").strip().upper()
    c = db().execute("SELECT id, name FROM courses WHERE join_code=?", (code,)).fetchone()
    if not c: return jsonify(error="No class found with that join code."), 404
    db().execute("INSERT OR IGNORE INTO enrollments(course_id,student_id) VALUES(?,?)", (c["id"], g.user["id"]))
    db().commit()
    return jsonify(ok=True, name=c["name"])

def own_course(cid):
    return db().execute("SELECT * FROM courses WHERE id=? AND teacher_id=?", (cid, g.user["id"])).fetchone()

# ---- sessions and marking
@app.post("/api/courses/<int:cid>/sessions")
@auth("teacher")
def start_session(cid):
    if not own_course(cid): return jsonify(error="Class not found."), 404
    try: minutes = max(1, min(120, int(request.get_json(force=True).get("minutes") or 10)))
    except (TypeError, ValueError): return jsonify(error="Minutes must be a number."), 400
    code, t = f"{secrets.randbelow(10**6):06d}", now()
    cur = db().execute("INSERT INTO sessions(course_id,code,created_at,expires_at) VALUES(?,?,?,?)",
                       (cid, code, iso(t), iso(t + timedelta(minutes=minutes))))
    db().commit()
    return jsonify(id=cur.lastrowid, code=code, expires_at=iso(t + timedelta(minutes=minutes))), 201

@app.get("/api/courses/<int:cid>/sessions")
@auth("teacher")
def list_sessions(cid):
    if not own_course(cid): return jsonify(error="Class not found."), 404
    rows = db().execute("""SELECT s.id, s.created_at, s.expires_at,
        (SELECT COUNT(*) FROM attendance a WHERE a.session_id=s.id AND a.status='present') AS present
        FROM sessions s WHERE s.course_id=? ORDER BY s.id DESC""", (cid,))
    return jsonify([dict(r) for r in rows])

@app.get("/api/sessions/<int:sid>")
@auth("teacher")
def roster(sid):
    s = db().execute("""SELECT s.* FROM sessions s JOIN courses c ON c.id=s.course_id
                        WHERE s.id=? AND c.teacher_id=?""", (sid, g.user["id"])).fetchone()
    if not s: return jsonify(error="Session not found."), 404
    rows = db().execute("""SELECT u.id, u.name, u.email, COALESCE(a.status='present', 0) AS present
        FROM enrollments e JOIN users u ON u.id=e.student_id
        LEFT JOIN attendance a ON a.session_id=? AND a.student_id=u.id
        WHERE e.course_id=? ORDER BY u.name""", (sid, s["course_id"]))
    return jsonify(session=dict(s), students=[dict(r) | {"present": bool(r["present"])} for r in rows])

@app.post("/api/sessions/<int:sid>/mark")
@auth("teacher")
def teacher_mark(sid):
    d = request.get_json(force=True)
    s = db().execute("""SELECT s.course_id FROM sessions s JOIN courses c ON c.id=s.course_id
                        WHERE s.id=? AND c.teacher_id=?""", (sid, g.user["id"])).fetchone()
    enrolled = s and db().execute("SELECT 1 FROM enrollments WHERE course_id=? AND student_id=?",
                                  (s["course_id"], d.get("student_id"))).fetchone()
    if not enrolled: return jsonify(error="Student not found in this class."), 404
    db().execute("""INSERT INTO attendance(session_id,student_id,status,marked_at,method) VALUES(?,?,?,?,'teacher')
        ON CONFLICT(session_id,student_id) DO UPDATE SET status=excluded.status, marked_at=excluded.marked_at, method='teacher'""",
        (sid, d["student_id"], "present" if d.get("present") else "absent", iso(now())))
    db().commit()
    return jsonify(ok=True)

_attempts = {}  # student_id -> recent attempt timestamps (limits code guessing; use Redis when scaling out)

@app.post("/api/attendance/mark")
@auth("student")
def student_mark():
    uid, t = g.user["id"], time.time()
    recent = [x for x in _attempts.get(uid, []) if t - x < 60]
    if len(recent) >= 8:
        return jsonify(error="Too many attempts. Wait a minute and try again."), 429
    _attempts[uid] = recent + [t]
    code = str(request.get_json(force=True).get("code") or "").strip()
    s = db().execute("""SELECT s.id, c.name FROM sessions s JOIN courses c ON c.id=s.course_id
        JOIN enrollments e ON e.course_id=s.course_id AND e.student_id=?
        WHERE s.code=? AND s.expires_at>? ORDER BY s.id DESC""", (uid, code, iso(now()))).fetchone()
    if not s: return jsonify(error="That code is wrong, expired, or not for one of your classes."), 400
    old = db().execute("SELECT status FROM attendance WHERE session_id=? AND student_id=?", (s["id"], uid)).fetchone()
    if old and old["status"] == "present":
        return jsonify(ok=True, name=s["name"], message="You were already marked present.")
    db().execute("""INSERT INTO attendance(session_id,student_id,status,marked_at,method) VALUES(?,?,'present',?,'code')
        ON CONFLICT(session_id,student_id) DO UPDATE SET status='present', marked_at=excluded.marked_at, method='code'""",
        (s["id"], uid, iso(now())))
    db().commit()
    return jsonify(ok=True, name=s["name"], message="You're marked present.")

# ---- reports
def report_rows(cid):
    total = db().execute("SELECT COUNT(*) FROM sessions WHERE course_id=?", (cid,)).fetchone()[0]
    rows = db().execute("""SELECT u.name, u.email,
        (SELECT COUNT(*) FROM attendance a JOIN sessions s ON s.id=a.session_id
           WHERE s.course_id=? AND a.student_id=u.id AND a.status='present') AS present
        FROM enrollments e JOIN users u ON u.id=e.student_id WHERE e.course_id=? ORDER BY u.name""", (cid, cid)).fetchall()
    return total, [dict(r) | {"percent": round(r["present"] * 100 / total, 1) if total else 0.0} for r in rows]

@app.get("/api/courses/<int:cid>/report")
@auth("teacher")
def report(cid):
    if not own_course(cid): return jsonify(error="Class not found."), 404
    total, rows = report_rows(cid)
    return jsonify(total=total, students=rows, min_percent=MIN_PERCENT)

def safe_cell(v):  # stop spreadsheet formula injection from names
    v = str(v); return "'" + v if v[:1] in "=+-@" else v

@app.get("/api/courses/<int:cid>/report.csv")
@auth("teacher")
def report_csv(cid):
    c = own_course(cid)
    if not c: return jsonify(error="Class not found."), 404
    total, rows = report_rows(cid)
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["Name", "Email", "Sessions attended", "Total sessions", "Attendance %"])
    for r in rows: w.writerow([safe_cell(r["name"]), safe_cell(r["email"]), r["present"], total, r["percent"]])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="attendance-{cid}.csv"'})

@app.get("/")
def index(): return app.send_static_file("index.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
