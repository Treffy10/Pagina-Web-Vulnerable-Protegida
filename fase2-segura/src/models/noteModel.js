const db = require('../config/db');

// Todas las consultas filtran SIEMPRE por user_id -> corrige el IDOR
// (VULN-11/13/14) que permitia leer/editar/borrar notas ajenas en fase1.
const findAllByUser = (userId) =>
  db.prepare('SELECT * FROM notes WHERE user_id = ? ORDER BY id DESC').all(userId);

const findByIdAndUser = (id, userId) =>
  db.prepare('SELECT * FROM notes WHERE id = ? AND user_id = ?').get(id, userId);

const create = (userId, title, content, filePath) =>
  db.prepare('INSERT INTO notes (user_id, title, content, file_path) VALUES (?, ?, ?, ?)')
    .run(userId, title, content, filePath);

const updateByIdAndUser = (id, userId, title, content) =>
  db.prepare('UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?')
    .run(title, content, id, userId);

const deleteByIdAndUser = (id, userId) =>
  db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?').run(id, userId);

module.exports = { findAllByUser, findByIdAndUser, create, updateByIdAndUser, deleteByIdAndUser };
