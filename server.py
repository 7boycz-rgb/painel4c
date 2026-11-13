import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, session, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "access_logs.sqlite3"

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("PANEL_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("Configure a variável PANEL_SECRET_KEY antes de iniciar o servidor.")

# Para hospedagem atrás de UM proxy reverso confiável (ex.: Render).
# Se hospedar sem proxy, remova esta linha.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

ADMIN_PASSWORD = os.environ.get("PANEL_ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    raise RuntimeError("Configure a variável PANEL_ADMIN_PASSWORD antes de iniciar o servidor.")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                user_agent TEXT NOT NULL
            )
        """)

def cleanup_old_logs():
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    with db() as conn:
        conn.execute("DELETE FROM access_logs WHERE timestamp < ?", (cutoff,))

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify(error="Faça login como administrador."), 401
        return fn(*args, **kwargs)
    return wrapper

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/")
def home():
    return send_from_directory(BASE_DIR, "painel4c.html")

@app.get("/api/visit")
def register_visit():
    cleanup_old_logs()
    ip = request.remote_addr or "desconhecido"
    # Limita o tamanho do user-agent para evitar entradas excessivas.
    user_agent = (request.headers.get("User-Agent") or "Não informado")[:300]
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with db() as conn:
        conn.execute(
            "INSERT INTO access_logs (ip, timestamp, user_agent) VALUES (?, ?, ?)",
            (ip, timestamp, user_agent)
        )
    return jsonify(ok=True)

@app.post("/api/admin/login")
def admin_login():
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))
    if not password or password != ADMIN_PASSWORD:
        return jsonify(error="Senha incorreta."), 401
    session.clear()
    session["is_admin"] = True
    return jsonify(ok=True)

@app.get("/api/admin/logs")
@admin_required
def admin_logs():
    cleanup_old_logs()
    with db() as conn:
        rows = conn.execute(
            "SELECT ip, timestamp, user_agent FROM access_logs ORDER BY id DESC LIMIT 500"
        ).fetchall()
    return jsonify(logs=[dict(row) for row in rows])

@app.post("/api/admin/logout")
def admin_logout():
    session.clear()
    return jsonify(ok=True)

if __name__ == "__main__":
    init_db()
    cleanup_old_logs()
    # Localmente acessível; em hospedagem use o comando de produção do provedor.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
