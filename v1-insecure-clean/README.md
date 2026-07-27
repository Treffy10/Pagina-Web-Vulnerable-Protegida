# App Insegura — Versión 1 (sin DevSecOps)

Aplicación Flask mínima con **login**, **subida de archivos** y **CRUD básico**
(GET / POST / UPDATE / DELETE), construida **sin** prácticas de DevSecOps para
servir como línea base de un ejercicio de seguridad comparativo (v1 vs v2).

⚠️ **Este código contiene vulnerabilidades introducidas deliberadamente.**
No usar en producción, ni exponerlo a internet.

## Instalación

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

La app corre en `http://localhost:5000`. La base de datos SQLite (`database.db`)
y la carpeta `uploads/` se crean automáticamente al iniciar.

## Flujo básico

1. `/register` — crear usuario
2. `/login` — iniciar sesión
3. `/dashboard` — subir archivos, ver, actualizar descripción, eliminar
4. `/api/files` — endpoint JSON (sin autenticación, ver hallazgos)

## Vulnerabilidades introducidas (para el informe técnico)

Cada una está marcada en el código con el comentario `# [VULN-XX]`.

| ID | Categoría (OWASP) | Descripción | Ubicación |
|----|--------------------|-------------|-----------|
| VULN-01 | A02 Cryptographic Failures | `secret_key` hardcodeada en el código fuente | `app.py` |
| VULN-02 | A05 Security Misconfiguration | Cookies de sesión sin `HttpOnly`/`Secure`/`SameSite` | `app.py` |
| VULN-03 | A05 Security Misconfiguration | Sin límite de tamaño de subida (`MAX_CONTENT_LENGTH`) | `app.py` |
| VULN-04 | A04 Insecure Design | Sin whitelist de extensiones/MIME en subida de archivos | `app.py`, `dashboard.html` |
| VULN-05 | A02 Cryptographic Failures | Contraseñas con MD5 sin sal | `app.py` (`md5_hash`) |
| VULN-06 | A07 Identification & Auth Failures | Sin validación de complejidad de contraseña | `register.html` |
| VULN-07 | A01 Broken Access Control (CSRF) | Sin token CSRF en formularios | todos los `<form>` |
| VULN-08 | A03 Injection (SQLi) | SQLi en registro de usuario vía `executescript` | `app.py` (`/register`) |
| VULN-09 | A05 Security Misconfiguration | Mensajes de error verbosos (stack trace expuesto) | `app.py` (`/register`) |
| VULN-10 | A03 Injection (SQLi) | SQLi en login — permite bypass de autenticación | `app.py` (`/login`) |
| VULN-11 | A07 Auth Failures | Sin rate limiting / bloqueo por intentos fallidos | `app.py` (`/login`) |
| VULN-12 | A07 Auth Failures | Sin CAPTCHA ni protección anti fuerza bruta | `app.py` (`/login`) |
| VULN-13 | A01 Broken Access Control | Sesión validada solo por existencia, sin expiración/rotación | `app.py` (`/dashboard`) |
| VULN-14 | A01 Broken Access Control | Filtrado de usuario inconsistente entre endpoints | `app.py` |
| VULN-15 | A03 Injection (Path Traversal) | Nombre de archivo subido sin sanitizar | `app.py` (`/upload`) |
| VULN-16 | A03 Injection (SQLi) | SQLi en descripción de archivo al subir | `app.py` (`/upload`) |
| VULN-17 | A01 Broken Access Control (IDOR) | Lectura/edición/borrado de archivos de otros usuarios cambiando el ID | `app.py` (`/files/<id>`) |
| VULN-18 | Deuda técnica / mala práctica REST | Uso de POST en lugar de PUT/PATCH | `app.py` (`update_file`) |
| VULN-19 | A03 Injection (SQLi) | SQLi al actualizar descripción | `app.py` (`update_file`) |
| VULN-20 | A01 Broken Access Control | Endpoint `/api/files` sin autenticación, expone datos de todos los usuarios | `app.py` |
| VULN-21 | A05 Security Misconfiguration | `debug=True` en el servidor (debugger interactivo / RCE potencial) | `app.py` (`__main__`) |
| VULN-22 | A03 Injection (XSS reflejado) | Patrón de riesgo en render de mensajes de error | `login.html` |
| VULN-23 | A03 Injection (XSS almacenado) | Descripción de archivo renderizada con filtro `\|safe` | `dashboard.html` |
| VULN-24 | A06 Vulnerable & Outdated Components | Dependencias fijadas a versiones antiguas con CVEs conocidos | `requirements.txt` |
| VULN-25 | Proceso / DevSecOps | Sin pipeline CI/CD, sin SAST/DAST/dependency scanning, sin tests | Repositorio completo |

## Cómo explotar algunos de estos hallazgos (para evidencia en el informe)

- **Bypass de login (VULN-10):** en el campo usuario, probar `admin' -- ` (con
  el usuario `admin` ya registrado) o `' OR '1'='1' -- `.
- **IDOR (VULN-17):** iniciar sesión con dos usuarios distintos, subir un
  archivo con cada uno, y acceder a `/files/<id>` de un archivo ajeno.
- **XSS almacenado (VULN-23):** subir un archivo con descripción
  `<script>alert(document.cookie)</script>` y ver que se ejecuta en el dashboard.
- **Path traversal (VULN-15):** interceptar la petición de subida con Burp/curl
  y modificar el nombre de archivo a algo como `../app.py`.

Siguiente paso: documentar cada hallazgo con evidencia (capturas, request/response)
y pasar a la **versión 2**, corrigiendo cada punto con prácticas de SecDevOps
(prepared statements, hashing con bcrypt/argon2, control de acceso por
ownership, CSP, CI/CD con SAST/DAST/dependency scanning, etc.).
