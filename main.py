import os
from datetime import datetime, date

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

app = Flask(__name__)

ADMIN_KEY = (os.environ.get("ADMIN_KEY") or "").strip()
DATABASE_URL = (os.environ.get("DATABASE_URL") or "").strip()
PORT = int(os.environ.get("PORT", "10000"))

# ---------- DB helpers ----------
def _normalize_db_url(db_url: str) -> str:
    """
    Supabase direct URL은 SSL이 필수인 경우가 많아서 sslmode=require를 보장.
    """
    if not db_url:
        return db_url
    u = urlparse(db_url)
    qs = parse_qs(u.query)
    if "sslmode" not in qs:
        qs["sslmode"] = ["require"]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((u.scheme, u.netloc, u.path, u.params, new_query, u.fragment))


def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not configured")
    return psycopg2.connect(_normalize_db_url(DATABASE_URL), cursor_factory=RealDictCursor)


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id          TEXT PRIMARY KEY,
                    pw_hash     TEXT NOT NULL,
                    approved    BOOLEAN NOT NULL DEFAULT FALSE,
                    expire_at   DATE,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                """
            )
        conn.commit()


def today_date() -> date:
    return datetime.now().date()


def parse_ymd(s: str) -> date:
    return datetime.strptime(s, "%Y-%m-%d").date()


def admin_auth_ok(req) -> bool:
    """
    관리자 키 허용 방식:
    1) Header: X-ADMIN-KEY: <value>
    2) JSON body: {"admin_key": "<value>"}
    """
    if not ADMIN_KEY:
        return False

    got_header = (req.headers.get("X-ADMIN-KEY") or "").strip()
    j = req.get_json(silent=True) or {}
    got_json = ""
    if isinstance(j, dict):
        got_json = (j.get("admin_key") or "").strip()

    return (got_header == ADMIN_KEY) or (got_json == ADMIN_KEY)


# ---------- routes ----------
@app.get("/")
def health():
    return jsonify({"ok": True, "service": "auth-server"}), 200


@app.get("/__routes")
def __routes():
    return "\n".join(sorted([f"{list(r.methods)} {r.rule}" for r in app.url_map.iter_rules()])), 200


@app.post("/register")
def register():
    init_db()
    data = request.get_json(silent=True) or {}
    user_id = (data.get("id") or "").strip()
    pw = (data.get("pw") or "").strip()

    if not user_id or not pw:
        return jsonify({"ok": False, "reason": "missing_id_or_pw"}), 400

    pw_hash = generate_password_hash(pw)

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if row:
                    return jsonify({"ok": False, "reason": "already_exists"}), 200

                cur.execute(
                    "INSERT INTO users (id, pw_hash, approved) VALUES (%s, %s, %s)",
                    (user_id, pw_hash, False),
                )
            conn.commit()
    except Exception as e:
        return jsonify({"ok": False, "reason": "db_error", "detail": str(e)}), 500

    return jsonify({"ok": True, "id": user_id, "approved": False}), 200


@app.post("/login")
def login():
    init_db()
    data = request.get_json(silent=True) or {}
    user_id = (data.get("id") or "").strip()
    pw = (data.get("pw") or "").strip()

    if not user_id or not pw:
        return jsonify({"ok": False, "reason": "missing_id_or_pw"}), 400

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, pw_hash, approved, expire_at FROM users WHERE id=%s",
                    (user_id,),
                )
                row = cur.fetchone()
    except Exception as e:
        return jsonify({"ok": False, "reason": "db_error", "detail": str(e)}), 500

    if not row:
        return jsonify({"ok": False, "reason": "no_user"}), 200

    if not check_password_hash(row["pw_hash"], pw):
        return jsonify({"ok": False, "reason": "wrong_pw"}), 200

    # 승인 체크
    if not row["approved"]:
        return jsonify({"ok": False, "reason": "not_approved"}), 200

    # 만료 체크
    expire_at = row.get("expire_at")
    if expire_at:
        if today_date() > expire_at:
            return jsonify({"ok": False, "reason": "expired", "expire_at": str(expire_at)}), 200

    return jsonify({"ok": True, "expire_at": (str(expire_at) if expire_at else "")}), 200


@app.post("/admin/approve")
def admin_approve():
    init_db()

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

    # approved: 1/0, true/false 모두 허용
    approved_bool = bool(int(approved)) if isinstance(approved, (int, str)) and str(approved).isdigit() else bool(approved)

    exp_date = None
    if expire_at:
        try:
            exp_date = parse_ymd(expire_at)
        except Exception:
            return jsonify({"ok": False, "reason": "bad_expire_format", "expire_at": expire_at}), 400

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 존재 체크
                cur.execute("SELECT id FROM users WHERE id=%s", (user_id,))
                if not cur.fetchone():
                    return jsonify({"ok": False, "reason": "no_user"}), 404

                cur.execute(
                    "UPDATE users SET approved=%s, expire_at=%s WHERE id=%s",
                    (approved_bool, exp_date, user_id),
                )
            conn.commit()
    except Exception as e:
        return jsonify({"ok": False, "reason": "db_error", "detail": str(e)}), 500

    return jsonify({"ok": True, "id": user_id, "approved": approved_bool, "expire_at": expire_at}), 200


if __name__ == "__main__":
    # 로컬 실행용
    app.run(host="0.0.0.0", port=PORT, debug=False)
