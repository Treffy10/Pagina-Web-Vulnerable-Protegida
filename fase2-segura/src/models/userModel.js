const db = require('../config/db');

// Todas las consultas usan sentencias preparadas (parametros ?), nunca
// concatenacion de strings -> elimina la inyeccion SQL de fase 1.
const findByUsername = (username) =>
  db.prepare('SELECT * FROM users WHERE username = ?').get(username);

const findById = (id) =>
  db.prepare('SELECT id, username, created_at FROM users WHERE id = ?').get(id);

const create = (username, passwordHash) =>
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
    .run(username, passwordHash);

module.exports = { findByUsername, findById, create };
