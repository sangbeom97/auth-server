import os
import sqlite3
from datetime import datetime, date
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "auth.db")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")  # Render Environment Variables에 넣는 키
PORT = int(os.environ.get("PORT", "10000"))


# -----------------------------
# DB
# -----------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            pw_hash TEXT NOT NULL,
            approved INTEGER NOT NULL DEFAULT 0,
            expire_at TEXT
        )
    """)
    conn.commit()
    conn.close()


init_db()


# -----------------------------
# Utils
# -----------------------------
def today_date():
    return datetime.now().date()


def parse_ymd(s: str):
    # YYYY-MM-DD
    return datetime.strptime(s, "%Y-%m-%d").date()


def admin_auth_ok(req) -> bool:
    """
    관리자 키는 아래 두 방식 모두 허용:
    1) Header: X-ADMIN-KEY: <value>
    2) JSON body: {"admin_key": "<value>"}
    """
    if not ADMIN_KEY:
        return False

    got_header = (req.headers.get("X-ADMIN-KEY") or "").strip()
    got_json = ""
    j = req.get_json(silent=True) or {}
    if isinstance(j, dict):
        got_json = (j.get("admin_key") or "").strip()

    return (got_header == ADMIN_KEY) or (got_json == ADMIN_KEY)


# -----------------------------
# Routes
# -----------------------------
@app.get("/")
def home():
    # Render 헬스체크용
    return jsonify({"ok": True, "service": "auth-server"})


@app.post("/register")
def register():
    """
    사용자 회원가입 (누구나 가능)
    - 기본: approved=0 (관리자 승인 전)
    """
    data = request.get_json(silent=True) or {}
    user_id = (data.get("id") or "").strip()
    user_pw = (data.get("pw") or "")

    if not user_id or not user_pw:
        return jsonify({"ok": False, "reason": "missing_id_or_pw"}), 400

    pw_hash = generate_password_hash(user_pw)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    exists = cur.fetchone()

    if exists:
        conn.close()
        return jsonify({"ok": False, "reason": "user_exists"}), 409

    cur.execute(
        "INSERT INTO users (id, pw_hash, approved, expire_at) VALUES (?, ?, 0, NULL)",
        (user_id, pw_hash),
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "id": user_id, "approved": False})


@app.post("/login")
def login():
    """
    클라이언트(EXE)가 주기적으로 호출할 API
    응답:
      - ok=true  => 사용 가능(승인/만료 통과)
      - ok=false => no_user / wrong_pw / not_approved / expired
    """
    data = request.get_json(silent=True) or {}
    user_id = (data.get("id") or "").strip()
    user_pw = (data.get("pw") or "")

    if not user_id or not user_pw:
        return jsonify({"ok": False, "reason": "missing_id_or_pw"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, pw_hash, approved, expire_at FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"ok": False, "reason": "no_user"}), 200

    if not check_password_hash(row["pw_hash"], user_pw):
        return jsonify({"ok": False, "reason": "wrong_pw"}), 200

    if int(row["approved"]) != 1:
        return jsonify({"ok": False, "reason": "not_approved"}), 200

    expire_at = row["expire_at"]
    if not expire_at:
        # 승인 되었는데 만료일이 없으면(관리자 설정 실수) 막아두는 게 안전
        return jsonify({"ok": False, "reason": "no_expire_set"}), 200

    try:
        exp = parse_ymd(expire_at)
    except Exception:
        return jsonify({"ok": False, "reason": "bad_expire_format", "expire_at": expire_at}), 200

    if today_date() > exp:
        return jsonify({"ok": False, "reason": "expired", "expire_at": expire_at}), 200

    return jsonify({"ok": True, "expire_at": expire_at}), 200


@app.post("/admin/approve")
def admin_approve():
    """
    관리자 승인/기간 설정
    입력(JSON):
      - id: 대상 사용자 id
      - approved: 1 또는 0
      - expire_at: "YYYY-MM-DD"  (approved=1일 때 필수 추천)
    관리자키:
      - Header: X-ADMIN-KEY
      - 또는 JSON: admin_key
    """
    if not ADMIN_KEY:
        return jsonify({"ok": False, "reason": "admin_key_not_configured"}), 500

    if not admin_auth_ok(request):
        return jsonify({"ok": False, "reason": "unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    user_id = (data.get("id") or "").strip()
    approved = data.get("approved")
    expire_at = (data.get("expire_at") or "").strip()

    if not user_id:
        return jsonify({"ok": False, "reason": "missing_id"}), 400

    if approved is None:
        return jsonify({"ok": False, "reason": "missing_approved"}), 400

    approved_int = 1 if str(approved) in ["1", "true", "True"] else 0

    if approved_int == 1:
        if not expire_at:
            return jsonify({"ok": False, "reason": "missing_expire_at"}), 400
        try:
            _ = parse_ymd(expire_at)
        except Exception:
            return jsonify({"ok": False, "reason": "bad_expire_format"}), 400
    else:
        # 승인 해제 시 만료일도 비워둘지 유지할지는 취향인데, 여기선 유지
        # expire_at를 지우고 싶으면 expire_at=None 처리로 바꾸면 됨
        pass

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "reason": "no_user"}), 404

    cur.execute(
        "UPDATE users SET approved = ?, expire_at = ? WHERE id = ?",
        (approved_int, expire_at if expire_at else None, user_id),
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "id": user_id, "approved": bool(approved_int), "expire_at": expire_at or None})


# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":
    # Render는 PORT 환경변수를 제공함
    app.run(host="0.0.0.0", port=PORT, debug=False)
