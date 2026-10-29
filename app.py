import os
import sqlite3
from functools import wraps
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "instance" / "associacao.db"))

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "dev-only-change-this-secret-key"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)
CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=[])
ph = PasswordHasher()


def get_db():
    if "db" not in g:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS participants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            birth_date TEXT,
            guardian_name TEXT NOT NULL,
            guardian_phone TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            participant_id INTEGER NOT NULL,
            activity_name TEXT NOT NULL,
            registration_date TEXT NOT NULL DEFAULT CURRENT_DATE,
            status TEXT NOT NULL DEFAULT 'Ativa' CHECK(status IN ('Ativa', 'Cancelada')),
            FOREIGN KEY (participant_id) REFERENCES participants(id)
        );
        CREATE INDEX IF NOT EXISTS idx_participants_name ON participants(name);
        CREATE INDEX IF NOT EXISTS idx_registrations_participant ON registrations(participant_id);
    """)
    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")
    if username and password:
        row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, ph.hash(password))
            )
    db.commit()


@app.before_request
def ensure_db():
    init_db()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"
    return response


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        valid = False
        if user:
            try:
                valid = ph.verify(user["password_hash"], password)
            except VerifyMismatchError:
                valid = False
        if valid:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.permanent = True
            destination = request.args.get("next", "")
            if destination.startswith("/") and not destination.startswith("//"):
                return redirect(destination)
            return redirect(url_for("index"))
        flash("Usuário ou senha inválidos. Confira os dados e tente novamente.", "error")
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("Você saiu do sistema.", "success")
    return redirect(url_for("login"))


@app.get("/")
@login_required
def index():
    db = get_db()
    total = db.execute("SELECT COUNT(*) AS total FROM participants").fetchone()["total"]
    active = db.execute("SELECT COUNT(*) AS total FROM registrations WHERE status = 'Ativa'").fetchone()["total"]
    return render_template("index.html", total=total, active=active)


@app.route("/participants")
@login_required
def participants():
    q = request.args.get("q", "").strip()
    rows = get_db().execute(
        """SELECT * FROM participants
           WHERE name LIKE ? OR guardian_name LIKE ? OR guardian_phone LIKE ?
           ORDER BY name""",
        (f"%{q}%", f"%{q}%", f"%{q}%")
    ).fetchall()
    return render_template("participants.html", participants=rows, q=q)


@app.route("/participants/new", methods=["GET", "POST"])
@login_required
def participant_new():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        birth_date = request.form.get("birth_date", "").strip()
        guardian_name = request.form.get("guardian_name", "").strip()
        guardian_phone = request.form.get("guardian_phone", "").strip()
        if not name or not guardian_name or not guardian_phone:
            flash("Preencha nome, responsável e telefone do responsável.", "error")
            return render_template("participant_form.html", participant=request.form)
        get_db().execute(
            """INSERT INTO participants (name, birth_date, guardian_name, guardian_phone)
               VALUES (?, ?, ?, ?)""",
            (name, birth_date or None, guardian_name, guardian_phone)
        )
        get_db().commit()
        flash("Participante cadastrado com sucesso.", "success")
        return redirect(url_for("participants"))
    return render_template("participant_form.html", participant={})


@app.route("/participants/<int:participant_id>/edit", methods=["GET", "POST"])
@login_required
def participant_edit(participant_id):
    db = get_db()
    participant = db.execute("SELECT * FROM participants WHERE id = ?", (participant_id,)).fetchone()
    if participant is None:
        flash("Participante não encontrado.", "error")
        return redirect(url_for("participants"))
    participant = dict(participant)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        birth_date = request.form.get("birth_date", "").strip()
        guardian_name = request.form.get("guardian_name", "").strip()
        guardian_phone = request.form.get("guardian_phone", "").strip()
        if not name or not guardian_name or not guardian_phone:
            flash("Preencha nome, responsável e telefone do responsável.", "error")
            return render_template("participant_form.html", participant=request.form, editing=True)
        db.execute(
            """UPDATE participants SET name=?, birth_date=?, guardian_name=?, guardian_phone=?
               WHERE id=?""",
            (name, birth_date or None, guardian_name, guardian_phone, participant_id)
        )
        db.commit()
        flash("Cadastro atualizado com sucesso.", "success")
        return redirect(url_for("participants"))
    return render_template("participant_form.html", participant=participant, editing=True)


@app.post("/participants/<int:participant_id>/delete")
@login_required
def participant_delete(participant_id):
    db = get_db()
    participant = db.execute("SELECT id FROM participants WHERE id = ?", (participant_id,)).fetchone()
    if not participant:
        flash("Participante não encontrado.", "error")
    else:
        count = db.execute(
            "SELECT COUNT(*) AS total FROM registrations WHERE participant_id = ?",
            (participant_id,)
        ).fetchone()["total"]
        if count:
            flash("Não é possível excluir: existem inscrições vinculadas. Cancele-as primeiro.", "error")
        else:
            db.execute("DELETE FROM participants WHERE id = ?", (participant_id,))
            db.commit()
            flash("Participante excluído.", "success")
    return redirect(url_for("participants"))


@app.route("/registrations", methods=["GET", "POST"])
@login_required
def registrations():
    db = get_db()
    if request.method == "POST":
        participant_id = request.form.get("participant_id", type=int)
        activity_name = request.form.get("activity_name", "").strip()
        participant = db.execute("SELECT id FROM participants WHERE id = ?", (participant_id,)).fetchone()
        if not participant or not activity_name:
            flash("Selecione um participante existente e informe a atividade.", "error")
        else:
            db.execute(
                "INSERT INTO registrations (participant_id, activity_name) VALUES (?, ?)",
                (participant_id, activity_name)
            )
            db.commit()
            flash("Inscrição registrada com sucesso.", "success")
        return redirect(url_for("registrations"))
    participants = db.execute("SELECT id, name FROM participants ORDER BY name").fetchall()
    rows = db.execute(
        """SELECT r.*, p.name AS participant_name FROM registrations r
           JOIN participants p ON p.id = r.participant_id
           ORDER BY r.id DESC"""
    ).fetchall()
    return render_template("registrations.html", participants=participants, registrations=rows)


@app.post("/registrations/<int:registration_id>/cancel")
@login_required
def registration_cancel(registration_id):
    db = get_db()
    db.execute("UPDATE registrations SET status = 'Cancelada' WHERE id = ?", (registration_id,))
    db.commit()
    flash("Inscrição cancelada, se o registro existia.", "success")
    return redirect(url_for("registrations"))


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1")
