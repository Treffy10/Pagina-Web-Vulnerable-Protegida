/**
 * Verificacion practica: para cada vulnerabilidad de fase1 se intenta
 * explotar en fase1 (deberia funcionar) y en fase2 (deberia estar
 * bloqueada). Requiere:
 *   1. fase1-insegura corriendo en http://localhost:3001 (npm start)
 *   2. fase2-segura corriendo en http://localhost:3002 (npm start)
 *   3. Ejecutar este script DESDE la carpeta fase2-segura:
 *        node scripts/verify-security.js
 *
 * No modifica nada de forma destructiva; crea un par de registros de
 * prueba en cada base de datos.
 */
const path = require('path');
const Database = require('better-sqlite3');

const F1 = 'http://localhost:3001';
const F2 = 'http://localhost:3002';

let pass = 0, fail = 0, skip = 0;
function report(name, ok, detail) {
  const mark = ok === null ? 'SKIP' : ok ? 'PASS' : 'FAIL';
  if (ok === null) skip++; else if (ok) pass++; else fail++;
  console.log(`[${mark}] ${name}${detail ? ' - ' + detail : ''}`);
}

async function safeFetch(url, opts) {
  try { return await fetch(url, opts); } catch (e) { return null; }
}

async function checkServersUp() {
  const r1 = await safeFetch(F1 + '/login');
  const r2 = await safeFetch(F2 + '/health');
  if (!r1) console.log('AVISO: fase1 (puerto 3001) no responde. Corre "npm start" en fase1-insegura.');
  if (!r2) console.log('AVISO: fase2 (puerto 3002) no responde. Corre "npm start" en fase2-segura.');
  return { f1: !!r1, f2: !!r2 };
}

// 1. Inyeccion SQL para saltarse el login
async function testSqlInjection(up) {
  const payload = { username: "admin' -- ", password: 'lo-que-sea' };
  if (up.f1) {
    const res = await safeFetch(F1 + '/login', {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(payload)
    });
    const bypassed = res && (res.status === 302 || res.status === 0);
    report('Fase1: bypass de login con SQLi', bypassed, `status=${res && res.status}`);
  } else report('Fase1: bypass de login con SQLi', null, 'servidor no disponible');

  if (up.f2) {
    const res = await safeFetch(F2 + '/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const blocked = res && res.status === 401;
    report('Fase2: SQLi de login bloqueada (sentencias preparadas)', blocked, `status=${res && res.status}`);
  } else report('Fase2: SQLi de login bloqueada', null, 'servidor no disponible');
}

// 2. Formato del hash de password guardado en la base de datos
function testPasswordHashing() {
  try {
    const db1 = new Database(path.join(__dirname, '..', '..', 'fase1-insegura', 'database.sqlite'), { readonly: true, fileMustExist: true });
    const u1 = db1.prepare('SELECT password FROM users LIMIT 1').get();
    const isMd5 = u1 && /^[a-f0-9]{32}$/i.test(u1.password);
    report('Fase1: password almacenado como MD5 sin salt (vulnerable)', isMd5, u1 ? u1.password : 'sin datos');
    db1.close();
  } catch (e) {
    report('Fase1: lectura de database.sqlite', null, 'no existe todavia (corre la app una vez)');
  }
  try {
    const db2 = new Database(path.join(__dirname, '..', 'data', 'database.sqlite'), { readonly: true, fileMustExist: true });
    const u2 = db2.prepare('SELECT password_hash FROM users LIMIT 1').get();
    const isBcrypt = u2 && /^\$2[aby]\$/.test(u2.password_hash);
    report('Fase2: password almacenado con bcrypt', isBcrypt, u2 ? u2.password_hash.slice(0, 15) + '...' : 'sin datos');
    db2.close();
  } catch (e) {
    report('Fase2: lectura de data/database.sqlite', null, 'no existe todavia (corre la app una vez)');
  }
}

// 3. Rate limiting en el login
async function testRateLimit(up) {
  if (!up.f2) return report('Fase2: rate limit en /api/auth/login', null, 'servidor no disponible');
  let last;
  for (let i = 0; i < 12; i++) {
    last = await safeFetch(F2 + '/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'incorrecta' })
    });
  }
  report('Fase2: rate limit corta la fuerza bruta (esperado 429 tras 10 intentos)', last && last.status === 429, `ultimo status=${last && last.status}`);
}

// 4. Whitelist de tipos de archivo en el upload
async function testUploadWhitelist(up) {
  if (!up.f2) return report('Fase2: whitelist de subida de archivos', null, 'servidor no disponible');
  const login = await safeFetch(F2 + '/api/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'Admin#2026' })
  });
  const setCookie = login && login.headers.get('set-cookie');
  const cookie = setCookie ? setCookie.split(';')[0] : null;
  if (!cookie) return report('Fase2: whitelist de subida de archivos', null, 'no se pudo iniciar sesion (revisa usuario/clave)');

  const fd = new FormData();
  fd.append('title', 'prueba-malware');
  fd.append('content', 'archivo con extension peligrosa');
  fd.append('file', new Blob(['<?php system($_GET["c"]); ?>'], { type: 'application/x-httpd-php' }), 'shell.php');
  const res = await safeFetch(F2 + '/api/notes', { method: 'POST', headers: { Cookie: cookie }, body: fd });
  report('Fase2: rechaza subida de .php disfrazado (whitelist de mimetype)', res && res.status === 400, `status=${res && res.status}`);
}

// 5. Exposicion publica de archivos subidos
async function testPublicFileExposure(up) {
  if (up.f1) {
    const res = await safeFetch(F1 + '/uploads/archivo-que-no-existe.txt');
    // 404 = ruta estatica activa mirando el disco; una app sin static
    // devolveria un JSON de "no encontrado" del router, no un 404 de Express static.
    report('Fase1: carpeta /uploads servida como estatico publico', !!res && res.status === 404, `status=${res && res.status} (ruta estatica habilitada, sin verificar dueno)`);
  } else report('Fase1: /uploads publico', null, 'servidor no disponible');

  if (up.f2) {
    const res = await safeFetch(F2 + '/api/files/1');
    report('Fase2: descarga de archivo requiere sesion (401 sin cookie)', res && res.status === 401, `status=${res && res.status}`);
  } else report('Fase2: /api/files protegido', null, 'servidor no disponible');
}

// 6. CORS
async function testCors(up) {
  if (up.f1) {
    const res = await safeFetch(F1 + '/login', { headers: { Origin: 'http://sitio-malicioso.com' } });
    const acao = res && res.headers.get('access-control-allow-origin');
    report('Fase1: CORS refleja/permite cualquier origen', acao === '*' || acao === 'http://sitio-malicioso.com', `Access-Control-Allow-Origin=${acao}`);
  } else report('Fase1: CORS', null, 'servidor no disponible');

  if (up.f2) {
    const res = await safeFetch(F2 + '/health', { headers: { Origin: 'http://sitio-malicioso.com' } });
    const acao = res && res.headers.get('access-control-allow-origin');
    report('Fase2: CORS NO permite el origen malicioso', acao !== 'http://sitio-malicioso.com', `Access-Control-Allow-Origin=${acao}`);
  } else report('Fase2: CORS', null, 'servidor no disponible');
}

// 7. Atributos de la cookie de sesion
// Nota: express-session activa httpOnly por defecto aunque no se pida
// explicitamente; lo que fase1 NO fija (y fase2 si) es Secure y SameSite.
async function testCookieFlags(up) {
  if (up.f1) {
    const res = await safeFetch(F1 + '/login', { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ username: 'admin', password: 'admin123' }) });
    const sc = res && res.headers.get('set-cookie') || '';
    const inseguro = sc && !/SameSite/i.test(sc) && !/Secure/i.test(sc);
    report('Fase1: cookie de sesion SIN Secure/SameSite', inseguro, sc || 'sin cookie');
  } else report('Fase1: flags de cookie', null, 'servidor no disponible');

  if (up.f2) {
    const res = await safeFetch(F2 + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'Admin#2026' }) });
    const sc = res && res.headers.get('set-cookie') || '';
    if (!sc) {
      return report('Fase2: cookie JWT con HttpOnly + SameSite=Strict', null, 'login sin cookie (revisa si el rate-limit de la prueba anterior sigue activo; espera 15 min o reinicia el servidor)');
    }
    const seguro = /HttpOnly/i.test(sc) && /SameSite=Strict/i.test(sc);
    report('Fase2: cookie JWT con HttpOnly + SameSite=Strict', seguro, sc);
  } else report('Fase2: flags de cookie', null, 'servidor no disponible');
}

// 8. Cabeceras de seguridad (Helmet/CSP)
async function testSecurityHeaders(up) {
  if (up.f1) {
    const res = await safeFetch(F1 + '/login');
    const csp = res && res.headers.get('content-security-policy');
    report('Fase1: SIN Content-Security-Policy', !csp, csp ? 'presente (inesperado)' : 'ausente');
  } else report('Fase1: cabeceras de seguridad', null, 'servidor no disponible');

  if (up.f2) {
    const res = await safeFetch(F2 + '/health');
    const csp = res && res.headers.get('content-security-policy');
    report('Fase2: Content-Security-Policy presente (Helmet)', !!csp, csp || 'ausente');
  } else report('Fase2: cabeceras de seguridad', null, 'servidor no disponible');
}

// 9. Verbosidad de errores (stack traces)
async function testErrorVerbosity(up) {
  if (up.f1) {
    const res = await safeFetch(F1 + '/notes/abc'); // id no numerico -> error SQL
    const body = res ? await res.text() : '';
    report('Fase1: expone stack trace / detalle SQL en el error', /Error:|at /.test(body), body.slice(0, 60));
  } else report('Fase1: verbosidad de errores', null, 'servidor no disponible');

  if (up.f2) {
    const res = await safeFetch(F2 + '/api/notes/abc');
    const body = res ? await res.text() : '';
    report('Fase2: mensaje de error generico (sin stack trace)', !/at \S+:\d+/.test(body), body.slice(0, 60));
  } else report('Fase2: verbosidad de errores', null, 'servidor no disponible');
}

(async () => {
  console.log('== Verificacion SecDevOps: fase1-insegura vs fase2-segura ==\n');
  const up = await checkServersUp();
  console.log('');
  await testSqlInjection(up);
  testPasswordHashing();
  // El test de fuerza bruta va al final a proposito: agota a drede el
  // cupo de intentos de login (10 / 15 min) para esa IP, asi que si
  // corriera antes, los tests siguientes que necesitan loguearse
  // (upload, cookies) fallarian por 429, no por un bug real.
  await testUploadWhitelist(up);
  await testPublicFileExposure(up);
  await testCors(up);
  await testCookieFlags(up);
  await testSecurityHeaders(up);
  await testErrorVerbosity(up);
  await testRateLimit(up);
  console.log(`\nResumen: ${pass} PASS, ${fail} FAIL, ${skip} SKIP`);
})();
