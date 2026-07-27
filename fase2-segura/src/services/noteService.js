const noteModel = require('../models/noteModel');

function listNotes(userId) {
  return noteModel.findAllByUser(userId);
}

function getNote(id, userId) {
  const note = noteModel.findByIdAndUser(id, userId);
  if (!note) throw new Error('No encontrada'); // no distinguimos "no existe" de "no es tuya"
  return note;
}

function createNote(userId, title, content, filePath) {
  return noteModel.create(userId, title, content, filePath);
}

function updateNote(id, userId, title, content) {
  const result = noteModel.updateByIdAndUser(id, userId, title, content);
  if (result.changes === 0) throw new Error('No encontrada');
  return result;
}

function deleteNote(id, userId) {
  const result = noteModel.deleteByIdAndUser(id, userId);
  if (result.changes === 0) throw new Error('No encontrada');
  return result;
}

module.exports = { listNotes, getNote, createNote, updateNote, deleteNote };
