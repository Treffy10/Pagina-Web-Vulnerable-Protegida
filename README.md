# Proyecto SecDevOps: App de notas con login y upload (Fase 1 vs Fase 2)

Este repositorio contiene dos versiones de la misma aplicacion (login,
subida de archivos y CRUD - GET/POST/PUT/DELETE - sobre "notas"):

- `fase1-insegura/`: version construida sin DevSecOps, con vulnerabilidades
  intencionales para fines de analisis y aprendizaje. **No ejecutar expuesta
  a internet ni usar sus patrones como referencia.**
- `fase2-segura/`: version refactorizada con arquitectura en capas
  (routes/controllers/services/models), practicas SecDevOps y las
  vulnerabilidades de fase 1 corregidas.

Ver `informe-tecnico.docx` para el detalle de contexto, hallazgos y
remediaciones.

## Como correr Fase 1 (puerto 3001)

```bash
cd fase1-insegura
npm install
npm start
```

Usuarios demo: `admin` / `admin123`, `javier` / `password1`.

## Como correr Fase 2 (puerto 3002)

```bash
cd fase2-segura
cp .env.example .env   # editar segun la tabla de abajo
npm install
npm start
```

Usuario demo creado automaticamente al primer arranque (solo si la tabla
de usuarios esta vacia): **`admin` / `Admin#2026`**. Se define en
`src/config/db.js` (constantes `DEMO_ADMIN_USER` / `DEMO_ADMIN_PASSWORD`) -
cambialo o borralo ahi si no lo quieres para produccion. Tambien puedes
registrar otros usuarios:

```bash
curl -X POST http://localhost:3002/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"javier","password":"unaClaveSegura123"}'
```

Luego iniciar sesion en `http://localhost:3002/login`.

### Que editar en `.env` (copiado de `.env.example`)

| Variable | Que es | Que poner |
|---|---|---|
| `PORT` | Puerto donde escucha el servidor | `3002` funciona sin tocarlo; cambialo si ese puerto ya esta ocupado |
| `NODE_ENV` | Entorno de ejecucion | `development` en tu maquina; `production` solo si lo despliegas de verdad (activa la cookie `secure`) |
| `JWT_SECRET` | Clave para firmar los tokens de sesion (JWT) | Un texto aleatorio de al menos 16 caracteres, solo tuyo. Ejemplo rapido para generarlo: `openssl rand -hex 32` |
| `COOKIE_SECRET` | Clave para firmar cookies | Igual que arriba, otro valor distinto al de `JWT_SECRET` |
| `DB_PATH` | Ruta del archivo SQLite | Dejar `./data/database.sqlite` (se crea solo); cambialo solo si quieres la base en otro lugar |
| `CORS_ORIGIN` | Origen permitido para llamar a la API | `http://localhost:3002` si abres la app desde el mismo navegador/puerto; si sirves el frontend desde otro puerto, pon ese origen exacto |
| `MAX_UPLOAD_MB` | Tamano maximo de archivo adjunto | `5` esta bien para pruebas; sube el numero si necesitas adjuntar archivos mas grandes |

Lo unico realmente obligatorio para que arranque es `JWT_SECRET` y
`COOKIE_SECRET` (la app falla al iniciar si faltan o son muy cortos, a
proposito, para no arrancar con secretos debiles). El resto tiene
valores por defecto razonables.

Nota: `fase1-insegura/` no usa `.env` a proposito -- el secreto de sesion
esta hardcodeado en `server.js`, que es justamente una de las
vulnerabilidades documentadas en el informe.

## Tests y pipeline

```bash
cd fase2-segura
npm test
npm run audit
```

El pipeline de CI (`.github/workflows/ci.yml`) corre lint, tests y
`npm audit` en cada push/PR sobre `fase2-segura/`.
