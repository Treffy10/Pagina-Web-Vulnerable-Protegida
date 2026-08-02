"""
============================================================
 APP SEGURA - VERSION 2 (CON DEVSECOPS)
============================================================
Misma funcionalidad que la v1 (login, registro, CRUD de
archivos, API JSON) pero corrigiendo TODAS las vulnerabilidades
introducidas deliberadamente en la v1.

Cada corrección referencia el hallazgo de la v1 que soluciona:
    # [FIX-VULN-XX] Descripción de la corrección

Ejecutar con HTTPS (ver certs/generate_cert.sh y README.md).
============================================================
"""

import os
import re
import sqlite3
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, send_from_directory, g, abort, jsonify
)
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
LOG_PATH = os.path.join(BASE_DIR, "security.log")

# ------------------------------------------------------------------
# Logging de eventos de seguridad (auditoría / trazabilidad)
# ------------------------------------------------------------------
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
security_logger = logging.getLogger("security")


def _load_or_create_secret_key() -> str:
    """
    [FIX-VULN-01] La secret_key ya NO está hardcodeada en el código.
    Se toma de la variable de entorno SECRET_KEY (recomendado en
    producción, p.ej. inyectada por un secrets manager / CI-CD).
    Si no existe (solo para desarrollo local), se genera una clave
    aleatoria criptográficamente segura y se persiste en un archivo
    local ignorado por git, para no perder la sesión entre reinicios
    en desarrollo.
    """
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key

    key_file = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(key_file):
        with open(key_file, "r") as f:
            return f.read().strip()

    new_key = secrets.token_hex(32)
    with open(key_file, "w") as f:
        f.write(new_key)
    os.chmod(key_file, 0o600)
    return new_key


app = Flask(__name__)
app.secret_key = _load_or_create_secret_key()

# [FIX-VULN-02] Cookies de sesión endurecidas: HttpOnly, Secure (solo
# viajan por HTTPS) y SameSite=Lax (mitiga CSRF de terceros).
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

# [FIX-VULN-03] Límite de tamaño de subida (5 MB) -> evita DoS por archivos gigantes.
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# [FIX-VULN-04] Whitelist estricta de extensiones permitidas para subida.
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt", "csv", "docx"}

# [FIX-VULN-07] Protección CSRF global para todos los formularios POST/PUT/DELETE.
csrf = CSRFProtect(app)

# [FIX-VULN-11] [FIX-VULN-12] Rate limiting global y específico en /login para
# mitigar fuerza bruta (sustituye a un CAPTCHA para este laboratorio).
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])

# [FIX-VULN-02][FIX-VULN-21] Cabeceras de seguridad + HSTS + fuerza HTTPS.
# force_https=False porque el propio servidor ya se levanta con TLS
# (ver __main__); Talisman añade CSP, X-Content-Type-Options,
# X-Frame-Options, Referrer-Policy, etc.
csp = {
    "default-src": "'self'",
    "style-src": "'self' 'unsafe-inline'",
    "script-src": "'self'",
    "img-src": "'self' data:",
}
Talisman(
    app,
    force_https=False,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    content_security_policy=csp,
    session_cookie_secure=True,
)

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 5


# ------------------------------------------------------------------
# Base de datos
# ------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            stored_filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)
    db.commit()
    db.close()


# ------------------------------------------------------------------
# Utilidades de seguridad
# ------------------------------------------------------------------

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def hash_password(password: str) -> str:
    # [FIX-VULN-05] bcrypt con salt aleatorio por contraseña (factor de coste 12).
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def is_strong_password(password: str):
    # [FIX-VULN-06] Validación de complejidad y longitud mínima de contraseña.
    if len(password) < 10:
        return "La contraseña debe tener al menos 10 caracteres."
    if not re.search(r"[A-Z]", password):
        return "La contraseña debe incluir al menos una mayúscula."
    if not re.search(r"[a-z]", password):
        return "La contraseña debe incluir al menos una minúscula."
    if not re.search(r"[0-9]", password):
        return "La contraseña debe incluir al menos un número."
    return None


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        # [FIX-VULN-13] Verificación de sesión robusta: existencia + que el
        # usuario todavía exista en la base de datos (evita sesiones huérfanas).
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))
        db = get_db()
        user = db.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            session.clear()
            return redirect(url_for("login"))
        session.permanent = True
        return view(*args, **kwargs)
    return wrapped


def get_owned_file_or_404(file_id: int):
    """[FIX-VULN-17] [FIX-VULN-14] Helper centralizado: siempre valida
    ownership (user_id de la sesión) antes de exponer/editar/borrar un
    archivo. Se usa en todos los endpoints de /files/<id> para evitar
    IDOR e inconsistencias de autorización entre endpoints."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?",
        (file_id, session["user_id"]),
    ).fetchone()
    if row is None:
        abort(404)
    return row


# ------------------------------------------------------------------
# Manejo genérico de método override (PUT/DELETE desde formularios HTML)
# [FIX-VULN-18] Permite usar verbos REST correctos (PUT/DELETE) en vez
# de sobrecargar POST para todo, manteniendo compatibilidad con
# formularios HTML planos mediante un campo oculto _method.
# ------------------------------------------------------------------
@app.before_request
def method_override():
    if request.method == "POST" and request.form.get("_method"):
        method = request.form.get("_method").upper()
        if method in ("PUT", "DELETE", "PATCH"):
            request.environ["REQUEST_METHOD"] = method


# ------------------------------------------------------------------
# AUTENTICACIÓN
# ------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not USERNAME_RE.match(username):
            return render_template(
                "register.html",
                error="El usuario debe tener 3-32 caracteres alfanuméricos (._- permitidos).",
            )

        pw_error = is_strong_password(password)  # [FIX-VULN-06]
        if pw_error:
            return render_template("register.html", error=pw_error)

        db = get_db()
        hashed = hash_password(password)

        try:
            # [FIX-VULN-08] Consulta parametrizada: el input del usuario nunca
            # se concatena en el SQL, se pasa como parámetro vinculado.
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hashed),
            )
            db.commit()
        except sqlite3.IntegrityError:
            # [FIX-VULN-09] Mensaje de error genérico, sin exponer detalles
            # internos (stack trace, esquema de BD, etc.) al usuario final.
            return render_template("register.html", error="Ese usuario ya existe.")
        except sqlite3.Error:
            security_logger.exception("Error inesperado en /register")
            return render_template("register.html", error="No se pudo completar el registro."), 500

        security_logger.info("Nuevo usuario registrado: %s", username)
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # [FIX-VULN-11] rate limiting anti fuerza bruta
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()

        # [FIX-VULN-10] Consulta parametrizada -> imposible inyectar SQL
        # a través de username/password (bypass de autenticación anulado).
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        generic_error = "Usuario o contraseña incorrectos"

        if user is None:
            security_logger.warning("Login fallido (usuario inexistente): %s", username)
            return render_template("login.html", error=generic_error)

        # [FIX-VULN-11][FIX-VULN-12] Bloqueo temporal de cuenta tras varios
        # intentos fallidos consecutivos.
        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.utcnow() < locked_until:
                security_logger.warning("Login bloqueado por lockout: %s", username)
                return render_template(
                    "login.html",
                    error="Cuenta bloqueada temporalmente por intentos fallidos. Intenta más tarde.",
                )

        if verify_password(password, user["password_hash"]):
            db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],),
            )
            db.commit()

            # [FIX-VULN-13] Rotación de sesión: se limpia cualquier sesión previa
            # antes de fijar la nueva (mitiga session fixation).
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.permanent = True
            security_logger.info("Login exitoso: %s", username)
            return redirect(url_for("dashboard"))
        else:
            attempts = user["failed_attempts"] + 1
            locked_until = None
            if attempts >= MAX_LOGIN_ATTEMPTS:
                locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                attempts = 0
            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            db.commit()
            security_logger.warning("Login fallido (password incorrecto): %s", username)
            return render_template("login.html", error=generic_error)

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------
# CRUD DE ARCHIVOS
#
# [FIX-VULN-26] El endpoint /tools/execute (RCE explícita mediante
# subprocess.run(..., shell=True) con entrada de usuario) se ELIMINA
# por completo en la v2. No existe una necesidad de negocio legítima
# para ejecutar comandos arbitrarios del sistema desde la aplicación
# web; si en el futuro se requiriera una utilidad similar, debería
# implementarse con una lista blanca fija de comandos predefinidos,
# sin `shell=True` y sin interpolar entrada de usuario en el comando.
# ------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    files = db.execute(
        "SELECT * FROM files WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    return render_template("dashboard.html", files=files, username=session.get("username"))


@app.route("/upload", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def upload_file():
    file = request.files.get("file")
    description = request.form.get("description", "")

    if not file or file.filename == "":
        return render_template("dashboard.html", files=_user_files(), username=session.get("username"),
                                upload_error="No se seleccionó ningún archivo."), 400

    # [FIX-VULN-04] Whitelist de extensión.
    if not allowed_file(file.filename):
        return render_template("dashboard.html", files=_user_files(), username=session.get("username"),
                                upload_error="Tipo de archivo no permitido."), 400

    # [FIX-VULN-15] Nombre original saneado con secure_filename() y, además,
    # se genera un nombre de almacenamiento aleatorio (UUID/hex) para eliminar
    # cualquier posibilidad de path traversal o colisión/sobrescritura.
    original_filename = secure_filename(file.filename)
    ext = original_filename.rsplit(".", 1)[1].lower()
    stored_filename = f"{secrets.token_hex(16)}.{ext}"
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)

    # Asegura que la ruta final quede dentro de UPLOAD_FOLDER (defensa en profundidad).
    if not os.path.abspath(save_path).startswith(os.path.abspath(app.config["UPLOAD_FOLDER"])):
        abort(400)

    file.save(save_path)

    db = get_db()
    # [FIX-VULN-16] Consulta parametrizada para la descripción del archivo.
    db.execute(
        "INSERT INTO files (user_id, stored_filename, original_filename, description) VALUES (?, ?, ?, ?)",
        (session["user_id"], stored_filename, original_filename, description),
    )
    db.commit()

    return redirect(url_for("dashboard"))


def _user_files():
    db = get_db()
    return db.execute("SELECT * FROM files WHERE user_id = ?", (session["user_id"],)).fetchall()


@app.route("/files/<int:file_id>", methods=["GET"])
@login_required
def get_file(file_id):
    # [FIX-VULN-17] IDOR corregido: la consulta exige que el archivo
    # pertenezca al usuario en sesión.
    row = get_owned_file_or_404(file_id)
    return send_from_directory(
        app.config["UPLOAD_FOLDER"], row["stored_filename"], as_attachment=True,
        download_name=row["original_filename"],
    )


@app.route("/files/<int:file_id>", methods=["PUT"])
@login_required
def update_file(file_id):
    # [FIX-VULN-18] Verbo HTTP correcto (PUT) vía method override.
    row = get_owned_file_or_404(file_id)  # [FIX-VULN-17]
    new_description = request.form.get("description", "")

    db = get_db()
    # [FIX-VULN-19] Consulta parametrizada.
    db.execute(
        "UPDATE files SET description = ? WHERE id = ? AND user_id = ?",
        (new_description, file_id, session["user_id"]),
    )
    db.commit()

    return redirect(url_for("dashboard"))


@app.route("/files/<int:file_id>", methods=["DELETE"])
@login_required
def delete_file(file_id):
    row = get_owned_file_or_404(file_id)  # [FIX-VULN-17 bis]

    db = get_db()
    try:
        os.remove(os.path.join(app.config["UPLOAD_FOLDER"], row["stored_filename"]))
    except OSError:
        pass
    db.execute("DELETE FROM files WHERE id = ? AND user_id = ?", (file_id, session["user_id"]))
    db.commit()

    return redirect(url_for("dashboard"))


# ------------------------------------------------------------------
# API JSON
# ------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/csrf-token")
def api_csrf_token():
    # Utilidad para clientes JS/SPA que necesiten el token CSRF actual.
    return jsonify({"csrf_token": generate_csrf()})


@app.route("/api/files", methods=["GET"])
@login_required
def api_list_files():
    # [FIX-VULN-20] Endpoint protegido con @login_required y filtrado
    # estrictamente por el usuario en sesión (ya no expone datos de
    # todos los usuarios).
    db = get_db()
    rows = db.execute(
        "SELECT id, original_filename, description, created_at FROM files WHERE user_id = ?",
        (session["user_id"],),
    ).fetchall()
    return jsonify({"files": [dict(row) for row in rows]})


# ------------------------------------------------------------------
# Manejo de errores genérico (sin stack traces al usuario)
# ------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Recurso no encontrado"), 404


@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", code=413, message="Archivo demasiado grande"), 413


@app.errorhandler(500)
def internal_error(e):
    security_logger.exception("Error interno no controlado")
    return render_template("error.html", code=500, message="Error interno del servidor"), 500


if __name__ == "__main__":
    init_db()  # idempotente (CREATE TABLE IF NOT EXISTS)

    cert_path = os.path.join(BASE_DIR, "certs", "cert.pem")
    key_path = os.path.join(BASE_DIR, "certs", "key.pem")

    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        raise SystemExit(
            "No se encontraron certificados TLS en certs/cert.pem y certs/key.pem.\n"
            "Genera uno de desarrollo con: bash certs/generate_cert.sh\n"
            "(o coloca ahi un certificado valido, p.ej. de Let's Encrypt)."
        )

    # [FIX-VULN-21] debug=False siempre; el modo debug se activa solo si
    # la variable de entorno FLASK_DEBUG=1 se define explicitamente en un
    # entorno de desarrollo local (nunca en produccion).
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5443)),
        debug=debug_mode,
        ssl_context=(cert_path, key_path),
    )
