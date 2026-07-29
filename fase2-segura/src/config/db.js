// Acceso a la base de datos usando better-sqlite3 con sentencias preparadas
// en todos los modelos (fix de VULN-08/VULN-12: inyeccion SQL de fase1).
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const env = require('./env');

const dir = path.dirname(env.dbPath);
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

const db = new Database(env.dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT,
    file_path TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Seed de un usuario admin de demostracion, solo si la tabla esta vacia.
// Util para poder entrar directo sin llamar antes a /api/auth/register.
// El password se hashea con bcrypt igual que en el flujo normal de
// registro (nunca se guarda en texto plano). Cambiar o borrar este
// usuario antes de usar la app fuera de un entorno de pruebas.
const DEMO_ADMIN_USER = 'admin';
const DEMO_ADMIN_PASSWORD = 'Admin#2026'; // cambiar en un entorno real

const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
if (userCount === 0) {
  const hash = bcrypt.hashSync(DEMO_ADMIN_PASSWORD, 12);
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
    .run(DEMO_ADMIN_USER, hash);
  // eslint-disable-next-line no-console
  console.log(`[seed] Usuario demo creado -> usuario: ${DEMO_ADMIN_USER} / password: ${DEMO_ADMIN_PASSWORD}`);
}

module.exports = db;
