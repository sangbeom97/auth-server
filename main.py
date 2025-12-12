from flask import Flask, request, jsonify
import sqlite3
import hashlib
from datetime import datetime
import os

app = Flask(__name__)
DB = "users.db"

# ✅ Render 환경변수로 넣어야 함 (코드에 하드코딩 금지)
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")

def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            pw_hash TEXT NOT NULL,
            approved INTEGER NOT NULL DEFAULT 0,
            expire_at TEXT
        )
        """)
        conn.commit()

@app.get("/")
def health():
    return "OK"

@app.post("/register")
def register():
    data = request.json or {}
    user_id = (data.get("id") or "").strip()
    user_pw = (data.get("pw") or "").strip()

    if not user_id or not user_pw:
        return jsonify({"ok": False, "reason": "missing"}), 400

    # 간단한 최소 검증(원하면 강화 가능)
    if len(user_id) < 3:
        return jsonify({"ok": False, "reason": "id_too_short"}), 400
    if len(user_pw) < 4:
        return jsonify({"ok": False, "reason": "pw_too_short"}), 400

    try:
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE id=?", (user_id,))
            if c.fetchone():
                return jsonify({"ok": False, "reason": "id_exists"}), 409

            c.execute(
                "INSERT INTO users (id, pw_hash, approved, expire_at) VALUES (?, ?, 0, NULL)",
                (user_id, hash_pw(user_pw))
            )
            conn.commit()

        return jsonify({"ok": True, "approved": False})
    except Exception as e:
        return jsonify({"ok": False, "reason": "server_error", "error": str(e)}), 500

@app.post("/login")
def login():
    data = request.json or {}
    user_id = (data.get("id") or "").strip()
    user_pw = (data.get("pw") or "").strip()

    if not user_id or not user_pw:
        return jsonify({"ok": False, "reason": "missing"}), 400

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT pw_hash, approved, expire_at FROM users WHERE id=?", (user_id,))
        row = c.fetchone()

    if not row:
        return jsonify({"ok": False, "reason": "no_user"})

    pw_hash, approved, expire_at = row

    if hash_pw(user_pw) != pw_hash:
        return jsonify({"ok": False, "reason": "wrong_pw"})

    if int(approved) != 1:
        return jsonify({"ok": False, "reason": "not_approved"})

    if not expire_at:
        return jsonify({"ok": False, "reason": "no_expire_set"})

    today = datetime.now().date()
    try:
        expire_date = datetime.strptime(expire_at, "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"ok": False, "reason": "bad_expire_format"})

    if today > expire_date:
        return jsonify({"ok": False, "reason": "expired", "expire_at": expire_at})

    return jsonify({"ok": True, "expire_at": expire_at})

@app.post("/admin/approve")
def admin_approve():
    data = request.json or {}
    admin_key = (data.get("admin_key") or "").strip()
    user_id = (data.get("id") or "").strip()
    expire_at = (data.get("expire_at") or "").strip()
    approved = data.get("approved", 1)  # 1 승인, 0 차단

    if not ADMIN_KEY:
        return jsonify({"ok": False, "reason": "admin_key_not_configured"}), 500

    if admin_key != ADMIN_KEY:
        return jsonify({"ok": False, "reason": "unauthorized"}), 403

    if not user_id:
        return jsonify({"ok": False, "reason": "missing_id"}), 400

    # 승인일 때만 만료일 필수
    if int(approved) == 1:
        if not expire_at:
            return jsonify({"ok": False, "reason": "missing_expire_at"}), 400
        try:
            datetime.strptime(expire_at, "%Y-%m-%d")
        except ValueError:
            return jsonify({"ok": False, "reason": "bad_expire_format"}), 400
    else:
        expire_at = None  # 차단 시 만료일 제거(선택)

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE id=?", (user_id,))
        if not c.fetchone():
            return jsonify({"ok": False, "reason": "no_user"}), 404

        c.execute(
            "UPDATE users SET approved=?, expire_at=? WHERE id=?",
            (int(approved), expire_at, user_id)
        )
        conn.commit()

    return jsonify({"ok": True, "id": user_id, "approved": int(approved), "expire_at": expire_at})

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))  # ✅ Render 포트
    app.run(host="0.0.0.0", port=port)
