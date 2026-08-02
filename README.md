# Laboratorio SecDevOps — App Vulnerable vs App Protegida (v1 / v2)

Comparativa práctica de una aplicación Flask antes y después de aplicar
prácticas de SecDevOps.

```
.
├── v1-insecure-clean/     App vulnerable (línea base, sin cambios)
├── v2-secure/             App corregida — HTTPS/TLS, sin las 26 vulnerabilidades de v1
├── pentest/               Guía de pruebas de penetración + automatización sqlmap + evidencias
└── database/              Bases de datos (código + datos) de ambas versiones
```

## v1 — App Insegura

Sin cambios respecto a la línea base del ejercicio. Ver `v1-insecure-clean/README.md`
para el detalle de las 26 vulnerabilidades introducidas deliberadamente
(SQLi, XSS, CSRF, IDOR, path traversal, RCE, etc.) y cómo explotarlas.

```bash
cd v1-insecure-clean
pip install -r requirements.txt
python app.py            # http://localhost:5000
```

## v2 — App Segura (nueva)

Misma funcionalidad que v1, con cada vulnerabilidad corregida y **servida
sobre HTTPS/TLS**. Ver `v2-secure/README.md` para la tabla completa de
correcciones (`VULN-XX` → `FIX-VULN-XX`).

```bash
cd v2-secure
pip install -r requirements.txt
bash certs/generate_cert.sh   # genera certificado TLS autofirmado
python app.py                 # https://localhost:5443
```

## Pruebas de penetración

Ver [`pentest/PENTEST.md`](pentest/PENTEST.md): metodología completa, mapeo
a OWASP Top 10, y el hallazgo principal — **inyección SQL en `/login`
explotada de forma automatizada con `sqlmap` para volcar las credenciales
de acceso** (`pentest/sqlmap_dump_v1.sh`), con verificación de que el mismo
ataque falla contra v2 (`pentest/sqlmap_verify_v2.sh`). Incluye además una
prueba de concepto ejecutable sin dependencias externas
(`pentest/poc_sqli_login.py`) con evidencia real capturada en
`pentest/evidence/`.

## Bases de datos

`database/v1/` y `database/v2/` contienen un `database.db` (SQLite) y su
export `.sql` de ejemplo para cada versión — ver `database/generate_sample_dbs.py`
para regenerarlos. Sirven para comparar directamente cómo se almacenan las
contraseñas en cada versión (MD5 sin sal en v1 vs. bcrypt en v2).

## Advertencia

Ambas aplicaciones son material educativo. **No exponer a Internet ni usar
con datos reales**, especialmente la v1.

