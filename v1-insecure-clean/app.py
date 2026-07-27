"""
============================================================
 APP INSEGURA - VERSION 1 (SIN DEVSECOPS)
============================================================
Este código contiene vulnerabilidades INTRODUCIDAS A PROPÓSITO
con fines académicos (ejercicio SecDevOps - comparativa v1/v2).

Cada vulnerabilidad está marcada con un comentario:
    # [VULN-XX] Descripción

NO USAR EN PRODUCCIÓN.
============================================================
"""

from flask import Flask, request, render_template, redirect, url_for, session, send_from_directory, g
import sqlite3
import hashlib
import os

# [VULN-01] Secret key hardcodeada en el código fuente (debería ir en variable de entorno / secrets manager)
app = Flask(__name__)
app.secret_key = "supersecret123"  # [VULN-01]

# [VULN-02] Configuración de cookie de sesión insegura (sin HttpOnly explícito reforzado, sin Secure, sin SameSite)
app.config.update(
    SESSION_COOKIE_HTTPONLY=False,   # debería ser True
    SESSION_COOKIE_SECURE=False,     # debería ser True en HTTPS
    SESSION_COOKIE_SAMESITE=None,    # debería ser 'Lax' o 'Strict'
)

DB_PATH = os.path.join(os.path.dirname(__file__), "database.db")
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# [VULN-03] Sin límite de tamaño de subida de archivos (posible DoS por archivos gigantes)
# app.config['MAX_CONTENT_LENGTH'] no está configurado

# [VULN-04] Sin whitelist de extensiones/tipos MIME permitidos para subida de archivos


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
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
            password TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            description TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    db.commit()
    db.close()


def md5_hash(password: str) -> str:
    # [VULN-05] Uso de MD5 sin sal para almacenar contraseñas (algoritmo débil, sin salt)
    return hashlib.md5(password.encode()).hexdigest()


# ------------------------------------------------------------------
# AUTENTICACIÓN
# ------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # [VULN-06] Sin validación de complejidad de contraseña ni longitud mínima
        # [VULN-07] Sin protección CSRF en formularios POST (no hay token CSRF)

        db = get_db()
        hashed = md5_hash(password)

        # [VULN-08] SQL Injection: concatenación directa de input de usuario en la query
        query = "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, hashed)
        try:
            db.executescript(query)  # executescript permite múltiples statements -> más grave aún
            db.commit()
        except sqlite3.Error as e:
            # [VULN-09] Mensajes de error verbosos expuestos al usuario final (information disclosure)
            return f"Error al registrar usuario: {e}", 500

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        hashed = md5_hash(password)

        db = get_db()

        # [VULN-10] SQL Injection clásico en el login (bypass de autenticación con
        # username = admin' -- )
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed}'"
        cur = db.execute(query)
        user = cur.fetchone()

        # [VULN-11] Sin límite de intentos de login / sin rate limiting -> permite fuerza bruta
        # [VULN-12] Sin CAPTCHA ni bloqueo temporal de cuenta

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Usuario o contraseña incorrectos")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------
# CRUD DE ARCHIVOS (GET / POST / UPDATE / DELETE)
# ------------------------------------------------------------------

@app.route("/dashboard")
def dashboard():
    # [VULN-13] No hay verificación robusta de sesión (solo existencia, no expiración/rotación)
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    # [VULN-14] Sin filtrar por usuario correctamente en algunos endpoints (ver /files/<id>)
    files = db.execute("SELECT * FROM files WHERE user_id = ?", (session["user_id"],)).fetchall()
    return render_template("dashboard.html", files=files, username=session.get("username"))


@app.route("/upload", methods=["POST"])
def upload_file():
    if "user_id" not in session:
        return redirect(url_for("login"))

    file = request.files.get("file")
    description = request.form.get("description", "")

    if file:
        # [VULN-04] (aplicado aquí) Sin validar extensión, tipo MIME ni contenido real del archivo
        # Se permite subir .php, .py, .exe, .html, etc.
        filename = file.filename  # [VULN-15] Sin sanitizar el nombre del archivo -> Path Traversal
        # posible: "../../etc/passwd" o "../app.py" como nombre de archivo

        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(save_path)  # [VULN-15] guardado directo sin normalizar ruta

        db = get_db()
        # [VULN-16] SQL Injection también aquí (descripción del archivo)
        query = f"INSERT INTO files (user_id, filename, description) VALUES ({session['user_id']}, '{filename}', '{description}')"
        db.executescript(query)
        db.commit()

    return redirect(url_for("dashboard"))


@app.route("/files/<int:file_id>", methods=["GET"])
def get_file(file_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    # [VULN-17] IDOR (Insecure Direct Object Reference): no se valida que el archivo
    # pertenezca al usuario en sesión -> cualquier usuario autenticado puede leer
    # archivos de otros usuarios solo cambiando el ID en la URL.
    row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None:
        return "Archivo no encontrado", 404

    return send_from_directory(app.config["UPLOAD_FOLDER"], row["filename"])
    # [VULN-15 bis] send_from_directory con filename no saneado también es vector de path traversal


@app.route("/files/<int:file_id>", methods=["POST"])
def update_file(file_id):
    # [VULN-18] Se usa POST en vez de PUT/PATCH real (mala práctica REST, no es vuln de seguridad grave
    # pero se documenta como deuda técnica junto con el resto de hallazgos de arquitectura)
    if "user_id" not in session:
        return redirect(url_for("login"))

    new_description = request.form.get("description", "")

    db = get_db()
    # [VULN-19] SQL Injection + [VULN-17] IDOR: no valida propietario, y la query es vulnerable
    query = f"UPDATE files SET description = '{new_description}' WHERE id = {file_id}"
    db.executescript(query)
    db.commit()

    return redirect(url_for("dashboard"))


@app.route("/files/<int:file_id>/delete", methods=["POST"])
def delete_file(file_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    # [VULN-17 bis] IDOR: cualquier usuario logueado puede borrar archivos de otros usuarios
    row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if row:
        try:
            os.remove(os.path.join(app.config["UPLOAD_FOLDER"], row["filename"]))
        except OSError:
            pass
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        db.commit()

    return redirect(url_for("dashboard"))


# ------------------------------------------------------------------
# API JSON simple (para mostrar métodos GET/POST/PUT/DELETE "básicos")
# ------------------------------------------------------------------

@app.route("/api/files", methods=["GET"])
def api_list_files():
    # [VULN-20] Endpoint de API sin autenticación (falta @login_required) -> expone TODOS los archivos
    # de TODOS los usuarios, no solo los del usuario en sesión.
    db = get_db()
    rows = db.execute("SELECT * FROM files").fetchall()
    return {"files": [dict(row) for row in rows]}


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    else:
        init_db()  # idempotente por CREATE TABLE IF NOT EXISTS

    # [VULN-21] debug=True en un entorno que podría confundirse con producción
    # -> expone el debugger interactivo de Werkzeug (posible RCE) y stack traces completos
    app.run(host="0.0.0.0", port=5000, debug=True)
