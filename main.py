from flask import Flask, request, jsonify
import sqlite3
import hashlib
from datetime import datetime

app = Flask(__name__)
DB = "users.db"

def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            pw_hash TEXT NOT NULL,
            expire_at TEXT NOT NULL
        )
        """)
        conn.commit()

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    user_id = data.get("id")
    user_pw = data.get("pw")

    if not user_id or not user_pw:
        return jsonify({"ok": False, "reason": "missing"})

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT pw_hash, expire_at FROM users WHERE id=?", (user_id,))
        row = c.fetchone()

    if not row:
        return jsonify({"ok": False, "reason": "no_user"})

    pw_hash, expire_at = row

    if hash_pw(user_pw) != pw_hash:
        return jsonify({"ok": False, "reason": "wrong_pw"})

    today = datetime.now().date()
    expire_date = datetime.strptime(expire_at, "%Y-%m-%d").date()

    if today > expire_date:
        return jsonify({"ok": False, "reason": "expired", "expire_at": expire_at})

    return jsonify({"ok": True, "expire_at": expire_at})

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
