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
cp .env.example .env   # editar JWT_SECRET / COOKIE_SECRET
npm install
npm start
```

Registrar un usuario primero:

```bash
curl -X POST http://localhost:3002/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"javier","password":"unaClaveSegura123"}'
```

Luego iniciar sesion en `http://localhost:3002/login`.

## Tests y pipeline

```bash
cd fase2-segura
npm test
npm run audit
```

El pipeline de CI (`.github/workflows/ci.yml`) corre lint, tests y
`npm audit` en cada push/PR sobre `fase2-segura/`.
