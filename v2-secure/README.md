# App Segura — Versión 2 (con DevSecOps)

Es la **misma aplicación** que la v1 (login, registro, subida de archivos,
CRUD de archivos, API JSON), pero corrigiendo **todas** las vulnerabilidades
introducidas deliberadamente en `v1-insecure-clean/`. La v1 **no se modificó**;
esta v2 es un proyecto independiente que se ejecuta en un puerto distinto y
puede compararse en vivo contra la v1.

Cada corrección en `app.py` está marcada con `# [FIX-VULN-XX]`, donde `XX`
referencia el hallazgo original documentado en `v1-insecure-clean/README.md`.

## Requisitos

- Python 3.11+
- OpenSSL (para generar el certificado TLS de desarrollo)

## Instalación y arranque (HTTPS obligatorio)

```bash
cd v2-secure
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 1) Generar certificado TLS autofirmado (desarrollo/laboratorio)
bash certs/generate_cert.sh

# 2) (Opcional) definir una SECRET_KEY propia en vez de la autogenerada
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

# 3) Arrancar la app sobre HTTPS
python app.py
```

La app queda disponible en `https://localhost:5443`. Al ser un certificado
autofirmado, el navegador mostrará una advertencia de "conexión no privada":
es esperado en un laboratorio local — acepta la excepción para continuar.

### Con Docker

```bash
cd v2-secure
docker build -t app-segura-v2 .
docker run -p 5443:5443 app-segura-v2
```

### Certificado para un dominio público real (alternativa gratuita)

Si en vez de un laboratorio local se despliega con un dominio propio, usar
Let's Encrypt (gratis) en vez del autofirmado:

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d tu-dominio.com
cp /etc/letsencrypt/live/tu-dominio.com/fullchain.pem v2-secure/certs/cert.pem
cp /etc/letsencrypt/live/tu-dominio.com/privkey.pem   v2-secure/certs/key.pem
```

## Correcciones aplicadas (mapeo v1 → v2)

| VULN v1 | Categoría OWASP | Corrección en v2 |
|---|---|---|
| VULN-01 | A02 Cryptographic Failures | `SECRET_KEY` desde variable de entorno / generada de forma segura, nunca hardcodeada |
| VULN-02 | A05 Security Misconfiguration | Cookies `HttpOnly` + `Secure` + `SameSite=Lax`; cabeceras HSTS/CSP con Flask-Talisman |
| VULN-03 | A05 Security Misconfiguration | `MAX_CONTENT_LENGTH` = 5 MB |
| VULN-04 | A04 Insecure Design | Whitelist de extensiones permitidas para subida |
| VULN-05 | A02 Cryptographic Failures | Hash de contraseñas con **bcrypt** (salt aleatorio, coste 12) |
| VULN-06 | A07 Auth Failures | Política de contraseña: mínimo 10 caracteres, mayúscula, minúscula, número |
| VULN-07 | CSRF | Token CSRF (Flask-WTF) en todos los formularios |
| VULN-08/10/16/19 | A03 Injection (SQLi) | Consultas 100% parametrizadas (`?`), sin concatenación de strings |
| VULN-09 | A05 Security Misconfiguration | Mensajes de error genéricos; detalle solo en `security.log` |
| VULN-11/12 | A07 Auth Failures | Rate limiting (Flask-Limiter) + bloqueo de cuenta tras 5 intentos fallidos |
| VULN-13 | A01 Broken Access Control | Sesión validada contra BD + expiración de 30 min + rotación al iniciar sesión |
| VULN-14/17 | A01 Broken Access Control (IDOR) | Helper `get_owned_file_or_404` centraliza la validación de propietario en todos los endpoints |
| VULN-15 | A03 Injection (Path Traversal) | `secure_filename()` + nombre de almacenamiento aleatorio (hex) |
| VULN-18 | Deuda técnica REST | Verbos `PUT`/`DELETE` reales vía method override |
| VULN-20 | A01 Broken Access Control | `/api/files` requiere sesión y filtra por usuario |
| VULN-21 | A05 Security Misconfiguration | `debug=False` por defecto; requiere `FLASK_DEBUG=1` explícito |
| VULN-22/23 | A03 Injection (XSS) | Autoescape de Jinja2 (se eliminó el filtro `\|safe`) + CSP |
| VULN-24 | A06 Vulnerable Components | Dependencias actualizadas y fijadas a versiones sin CVEs conocidos |
| VULN-25 | Proceso DevSecOps | Pipeline CI en `.github/workflows/security.yml` (Bandit SAST + pip-audit) |
| VULN-26 | A03 Injection / RCE | Endpoint `/tools/execute` **eliminado por completo** |
| — | Transporte | Toda la app se sirve exclusivamente sobre **HTTPS/TLS** |

## Verificación de las correcciones

Ver `../pentest/PENTEST.md` para la guía completa de pruebas de penetración,
incluyendo el intento automatizado con `sqlmap` contra el login de la v2
(que debe fallar / no encontrar inyección, a diferencia de la v1).
