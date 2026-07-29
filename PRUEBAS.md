# Guía de pruebas: cómo verificar que todo funciona

Esta guía te lleva paso a paso para levantar las dos versiones y comprobar,
con evidencia reproducible, que las vulnerabilidades de `fase1-insegura`
estén realmente corregidas en `fase2-segura`. No hace falta desplegar nada,
todo corre en tu máquina.

## 0. Requisitos

- Node.js instalado (cualquier version reciente, 18+).
- Las dos carpetas del proyecto (`fase1-insegura/`, `fase2-segura/`).
- Un navegador normal (Chrome, Edge, Firefox, Opera). **No uses el Simple
  Browser integrado de VS Code** para probar el login: bloquea cookies y
  hace parecer que la app no funciona cuando si funciona.

## 1. Levantar Fase 1 (insegura)

```powershell
cd fase1-insegura
npm install
npm start
```

Deberías ver `Fase1 (insegura) escuchando en http://localhost:3001`.
Déjala corriendo en esta terminal.

## 2. Levantar Fase 2 (segura)

Abre una **segunda terminal** (no cierres la de Fase 1):

```powershell
cd fase2-segura
copy .env.example .env
```

Edita `.env` y pon un valor real en `JWT_SECRET` y `COOKIE_SECRET` (mínimo
16 caracteres cada uno; puedes generarlos con
`node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`).

```powershell
npm install
npm start
```

Deberías ver `Fase2 (segura) escuchando en http://localhost:3002` y el
mensaje `[seed] Usuario demo creado -> usuario: admin / password: Admin#2026`.
Déjala corriendo en esta terminal.

## 3. Prueba manual rápida (en el navegador)

1. Abre `http://localhost:3001/login` (Fase 1), entra con `admin` /
   `admin123`, crea una nota con un archivo adjunto, verifica que aparece
   en la lista y que el link del archivo abre.
2. Abre `http://localhost:3002/login` (Fase 2), entra con `admin` /
   `Admin#2026`, crea una nota con archivo, verifica lista, link de
   archivo y el botón "Salir".

Si ambas funcionan igual a nivel de uso, la funcionalidad pedida
(login, subida de archivos, CRUD) está cubierta en las dos versiones.

## 4. Pruebas automatizadas de Fase 2

En la terminal de Fase 2 (sin detener el servidor, abre una **tercera
terminal** si hace falta):

```powershell
cd fase2-segura
npm test
```

Corre las pruebas unitarias (`tests/auth.test.js`): rechazo de login
invalido y bloqueo de acceso a notas sin token. Deberías ver
`pass 2`, `fail 0`.

```powershell
npm run audit
```

Analiza las dependencias en busca de vulnerabilidades conocidas (SCA).
Es normal ver algunas advertencias en dependencias de desarrollo
(eslint, herramientas de compilacion de bcrypt); no afectan el codigo
que corre en producción. Este comando es el mismo que ejecuta el
pipeline de CI (`.github/workflows/ci.yml`) en cada push.

## 5. Prueba dinámica: comparar fase1 vs fase2 en vivo

Con **las dos apps corriendo a la vez** (pasos 1 y 2), en la terminal de
Fase 2:

```powershell
npm run verify
```

Esto ataca en vivo las mismas 9 categorías de vulnerabilidades del
informe técnico contra ambos servidores y marca `PASS`/`FAIL` según si
el comportamiento observado coincide con lo esperado (fase1 vulnerable,
fase2 protegida). Resultado esperado: **16 PASS, 0 FAIL**.

| Qué se prueba | Fase 1 (se espera vulnerable) | Fase 2 (se espera protegida) |
|---|---|---|
| Inyección SQL en login | Bypass exitoso (redirect 302) | Bloqueado (401) |
| Hash de contraseña | MD5 (32 caracteres hex) | bcrypt (`$2b$...`) |
| Fuerza bruta en login | Sin límite | Bloqueado tras 10 intentos (429) |
| Whitelist de subida de archivos | — | Rechaza tipos no permitidos (400) |
| Archivos subidos | Públicos en `/uploads` sin login | Requieren sesión y ser el dueño (401) |
| CORS | Permite cualquier origen (`*`) | Solo el origen configurado |
| Cookie de sesión | Sin `Secure`/`SameSite` | `HttpOnly` + `SameSite=Strict` |
| Cabeceras de seguridad | Sin CSP | CSP de Helmet presente |
| Errores del servidor | Expone stack trace / SQL | Mensaje genérico |

Si algo sale `FAIL`, antes de asumir que es un bug revisa que:
- Las dos apps estén corriendo (revisa los avisos al inicio del script).
- No acabes de correr `npm run verify` dos veces seguidas muy rápido: el
  propio script agota el límite de intentos de login de Fase 2 (10 cada
  15 min). Si necesitas repetir la prueba pronto, reinicia el servidor
  de Fase 2 (el contador vive en memoria y se resetea al reiniciar).

## 6. Qué significa un resultado en verde (16/16 PASS)

Que las correcciones descritas en `informe-tecnico.docx` no son solo
texto: se verificaron ejecutando el ataque real contra el código real,
de forma reproducible por cualquiera que clone el repo y siga esta
guía. Es la evidencia que respalda la conclusión del informe de que
fase2-segura corrige, de forma verificable, todo lo que fase1-insegura
dejaba abierto.
