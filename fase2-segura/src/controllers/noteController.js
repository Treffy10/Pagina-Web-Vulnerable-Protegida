const { z } = require('zod');
const noteService = require('../services/noteService');

const noteSchema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().max(5000).optional().default('')
});

function list(req, res, next) {
  try {
    res.json(noteService.listNotes(req.user.id));
  } catch (err) { next(err); }
}

function getOne(req, res, next) {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'id invalido' });
    res.json(noteService.getNote(id, req.user.id));
  } catch (err) {
    err.status = 404;
    next(err);
  }
}

function create(req, res, next) {
  try {
    const { title, content } = noteSchema.parse(req.body);
    const filePath = req.file ? req.file.filename : null;
    const result = noteService.createNote(req.user.id, title, content, filePath);
    res.status(201).json({ id: result.lastInsertRowid });
  } catch (err) {
    err.status = 400;
    next(err);
  }
}

function update(req, res, next) {
  try {
    const id = Number(req.params.id);
    const { title, content } = noteSchema.parse(req.body);
    noteService.updateNote(id, req.user.id, title, content);
    res.json({ message: 'Actualizada' });
  } catch (err) {
    err.status = err.status || 404;
    next(err);
  }
}

function remove(req, res, next) {
  try {
    const id = Number(req.params.id);
    noteService.deleteNote(id, req.user.id);
    res.json({ message: 'Eliminada' });
  } catch (err) {
    err.status = 404;
    next(err);
  }
}

module.exports = { list, getOne, create, update, remove };
