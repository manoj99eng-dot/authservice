from flask import Flask, request, jsonify
import psycopg2
import psycopg2.extras
import bcrypt
import jwt
import os
import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("authservice")

app = Flask(__name__)

SECRET_KEY = os.environ["JWT_SECRET_KEY"]
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "postgres")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_SSLCERT = os.getenv("DB_SSLCERT")

def get_db():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        sslmode="verify-full",
        sslrootcert=DB_SSLCERT,
    )


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            SERIAL PRIMARY KEY,
            username      VARCHAR(100) UNIQUE NOT NULL,
            email         VARCHAR(200) UNIQUE NOT NULL,
            password_hash VARCHAR(200) NOT NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    cur.close()
    conn.close()
    logger.info("Database initialised")


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ── Register ──────────────────────────────────────────────────────────────────

@app.route("/register", methods=["POST"])
def register():
    data     = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "username, email and password are required"}), 400

    if len(password) < 6:
        return jsonify({"error": "password must be at least 6 characters"}), 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id",
            (username, email, pw_hash),
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
    except psycopg2.IntegrityError:
        return jsonify({"error": "username or email already exists"}), 409
    except Exception as e:
        logger.error("register db error: %s", e)
        return jsonify({"error": "internal server error"}), 500

    token = jwt.encode(
        {
            "user_id":  user_id,
            "username": username,
            "email":    email,
            "exp":      datetime.datetime.utcnow() + datetime.timedelta(hours=48),
        },
        SECRET_KEY,
        algorithm="HS256",
    )
    logger.info("registered user: %s", username)
    return jsonify({"token": token, "user_id": user_id, "username": username}), 201


# ── Login ─────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json(force=True)
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    try:
        conn = get_db()
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT id, username, email, password_hash FROM users WHERE email = %s",
            (email,),
        )
        user = cur.fetchone()
        cur.close()
        conn.close()
    except Exception as e:
        logger.error("login db error: %s", e)
        return jsonify({"error": "internal server error"}), 500

    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return jsonify({"error": "invalid email or password"}), 401

    token = jwt.encode(
        {
            "user_id":  user["id"],
            "username": user["username"],
            "email":    user["email"],
            "exp":      datetime.datetime.utcnow() + datetime.timedelta(hours=48),
        },
        SECRET_KEY,
        algorithm="HS256",
    )
    logger.info("login success: %s", user["username"])
    return jsonify({"token": token, "user_id": user["id"], "username": user["username"]}), 200


# ── Verify ────────────────────────────────────────────────────────────────────

@app.route("/verify", methods=["GET"])
def verify():
    token = request.args.get("token", "")
    if not token:
        return jsonify({"valid": False, "error": "no token provided"}), 400

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"valid": True, "user_id": payload["user_id"], "username": payload["username"]}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "invalid token"}), 401


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8081))
    init_db()
    app.run(host="0.0.0.0", port=port)
