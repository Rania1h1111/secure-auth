from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import time

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-change-me") 

DB_PATH = os.path.join(app.instance_path, "app.db")
os.makedirs(app.instance_path, exist_ok=True)

# Limite (par IP) pour la page LOGIN
MAX_TRIES = 5
BLOCK_SECONDS = 60
FAILED = {}  # ip -> {"count": int, "until": timestamp}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()

    # Crée un compte par défaut si la table est vide
    cur.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()["c"] == 0:
        cur.execute(
            "INSERT INTO users(username, password_hash) VALUES(?,?)",
            ("admin", generate_password_hash("Admin123!"))
        )
        conn.commit()

    conn.close()


init_db()


def is_blocked(ip: str) -> bool:
    data = FAILED.get(ip)
    return bool(data and data.get("until", 0) > time.time())


def register_fail(ip: str):
    data = FAILED.get(ip, {"count": 0, "until": 0})
    data["count"] += 1
    if data["count"] >= MAX_TRIES:
        data["until"] = time.time() + BLOCK_SECONDS
        data["count"] = 0
    FAILED[ip] = data


@app.get("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr or "unknown"

    if request.method == "POST":
        if is_blocked(ip):
            flash("Trop de tentatives. Réessaie dans 1 minute.", "error")
            return render_template("login.html")

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        # Validation minimale
        if not username or not password:
            flash("Erreur : champs obligatoires.", "error")
            return render_template("login.html")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user"] = username
            flash("OK : Vous êtes connecté.", "ok")
            return redirect(url_for("home"))

        register_fail(ip)
        flash("Erreur : identifiant ou mot de passe incorrect.", "error")

    return render_template("login.html")


# On peut créer un compte SANS être connecté (conforme PDF)
@app.post("/add-account")
def add_account():
    new_user = (request.form.get("new_username") or "").strip()
    new_pass = request.form.get("new_password") or ""

    # Validation minimale
    if len(new_user) < 3 or len(new_pass) < 8:
        flash("Erreur : username >= 3 caractères, mot de passe >= 8.", "error")
        return redirect(url_for("login"))

    pw_hash = generate_password_hash(new_pass)

    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users(username, password_hash) VALUES(?,?)",
            (new_user, pw_hash)
        )
        conn.commit()
        conn.close()
        flash(f"Compte créé : {new_user}", "ok")
    except sqlite3.IntegrityError:
        flash("Erreur : identifiant déjà existant.", "error")

    return redirect(url_for("login"))


@app.get("/home")
def home():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("home.html", user=session["user"])


@app.get("/logout")
def logout():
    session.clear()
    flash("Déconnecté.", "ok")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
