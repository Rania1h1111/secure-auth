from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from functools import wraps
from datetime import timedelta
import sqlite3
import os
import time
import re
import secrets
import logging

app = Flask(__name__)

# =========================
# A2 - Secure configuration
# =========================
# IMPORTANT : mets une SECRET_KEY fixe via variable d'environnement si possible
# Windows PowerShell: setx SECRET_KEY "une_cle_longue_random"
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "CHANGE_ME_LOCAL_" + "1234567890abcdef")

# Cookies session (A2 + A7)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # True uniquement si HTTPS
)

# Durée de session (A7)
app.permanent_session_lifetime = timedelta(minutes=30)

# Logs (A10)
logging.basicConfig(level=logging.INFO)

DB_PATH = os.path.join(app.instance_path, "app.db")
os.makedirs(app.instance_path, exist_ok=True)

# Rate limit simple en mémoire
MAX_LOGIN_TRIES = 5
LOGIN_BLOCK_SECONDS = 60
FAILED_LOGIN = {}  # ip -> {"count": int, "until": ts}

MAX_REGISTER_TRIES = 5
REGISTER_BLOCK_SECONDS = 60
FAILED_REGISTER = {}  # ip -> {"count": int, "until": ts}


# =========================
# DB helpers
# =========================
def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)
        conn.commit()

        # Ajoute un compte de test si la table est vide
        c = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if c == 0:
            conn.execute(
                "INSERT INTO users(username, password_hash, created_at) VALUES(?,?,?)",
                ("admin", generate_password_hash("Admin123!"), int(time.time()))
            )
            conn.commit()

init_db()


# =========================
# A1 - Access control
# =========================
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            flash("Veuillez vous connecter.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# =========================
# CSRF (simple, stable)
# =========================
def ensure_csrf_token():
    # Ne dépend pas d'un token changé au login: stable
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

@app.before_request
def csrf_prepare():
    # Assure qu'on a un token dès l'arrivée sur le site (GET /login, etc.)
    ensure_csrf_token()

def csrf_protect():
    # Appliquer seulement aux POST
    if request.method == "POST":
        token_form = request.form.get("csrf_token", "")
        token_session = session.get("csrf_token", "")
        if not token_form or not token_session or token_form != token_session:
            abort(403)

@app.before_request
def csrf_check():
    csrf_protect()

@app.context_processor
def inject_csrf():
    return {"csrf_token": session.get("csrf_token", "")}


# =========================
# Security headers (A2)
# =========================
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return resp


# =========================
# Rate limit helpers
# =========================
def client_ip():
    return request.remote_addr or "unknown"

def is_blocked(store: dict) -> bool:
    ip = client_ip()
    data = store.get(ip)
    return bool(data and data.get("until", 0) > time.time())

def register_fail(store: dict, max_tries: int, block_seconds: int):
    ip = client_ip()
    data = store.get(ip, {"count": 0, "until": 0})
    data["count"] += 1
    if data["count"] >= max_tries:
        data["until"] = time.time() + block_seconds
        data["count"] = 0
    store[ip] = data


# =========================
# A7 - Password policy
# =========================
def is_strong_password(p: str) -> bool:
    if len(p) < 8:
        return False
    if not re.search(r"[A-Z]", p):
        return False
    if not re.search(r"[a-z]", p):
        return False
    if not re.search(r"\d", p):
        return False
    if not re.search(r"[^A-Za-z0-9]", p):
        return False
    return True


# =========================
# Routes
# =========================
@app.get("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    try:
        if request.method == "POST":
            if is_blocked(FAILED_LOGIN):
                flash("Trop de tentatives. Réessaie dans 1 minute.", "error")
                return render_template("login.html")

            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

            if not username or not password:
                flash("Erreur : champs obligatoires.", "error")
                return render_template("login.html")

            with db_connect() as conn:
                user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

            if user and check_password_hash(user["password_hash"], password):
                session["user"] = username
                session.permanent = True
                flash("OK : Vous êtes connecté.", "ok")
                return redirect(url_for("home"))

            register_fail(FAILED_LOGIN, MAX_LOGIN_TRIES, LOGIN_BLOCK_SECONDS)
            flash("Erreur : identifiant ou mot de passe incorrect.", "error")

        return render_template("login.html")

    except HTTPException:
        raise
    except Exception:
        app.logger.exception("Erreur dans /login")
        flash("Erreur interne. Réessayez.", "error")
        return render_template("login.html")


@app.post("/add-account")
def add_account():
    """
    Conformément à l'énoncé : création de compte possible sans être connecté.
    """
    try:
        if is_blocked(FAILED_REGISTER):
            flash("Trop de créations d'un coup. Réessaie dans 1 minute.", "error")
            return redirect(url_for("login"))

        new_user = (request.form.get("new_username") or "").strip()
        new_pass = request.form.get("new_password") or ""

        if len(new_user) < 3:
            register_fail(FAILED_REGISTER, MAX_REGISTER_TRIES, REGISTER_BLOCK_SECONDS)
            flash("Erreur : identifiant >= 3 caractères.", "error")
            return redirect(url_for("login"))

        if not is_strong_password(new_pass):
            register_fail(FAILED_REGISTER, MAX_REGISTER_TRIES, REGISTER_BLOCK_SECONDS)
            flash("Erreur : mot de passe trop faible (8+, Maj, min, chiffre, symbole).", "error")
            return redirect(url_for("login"))

        pw_hash = generate_password_hash(new_pass)

        with db_connect() as conn:
            conn.execute(
                "INSERT INTO users(username, password_hash, created_at) VALUES(?,?,?)",
                (new_user, pw_hash, int(time.time()))
            )
            conn.commit()

        flash(f"Compte créé : {new_user}", "ok")
        return redirect(url_for("login"))

    except sqlite3.IntegrityError:
        flash("Erreur : identifiant déjà existant.", "error")
        return redirect(url_for("login"))
    except HTTPException:
        raise
    except Exception:
        app.logger.exception("Erreur dans /add-account")
        flash("Erreur interne. Réessayez.", "error")
        return redirect(url_for("login"))


@app.get("/home")
@login_required
def home():
    return render_template("home.html", user=session["user"])


@app.get("/logout")
def logout():
    session.clear()
    flash("Déconnecté.", "ok")
    return redirect(url_for("login"))


# =========================
# A10 - Error handling
# =========================
@app.errorhandler(403)
def err403(e):
    return render_template("error.html", code=403, message="Requête refusée (CSRF invalide ou accès non autorisé)."), 403

@app.errorhandler(404)
def err404(e):
    return render_template("error.html", code=404, message="Page introuvable."), 404

@app.errorhandler(500)
def err500(e):
    return render_template("error.html", code=500, message="Erreur serveur."), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)