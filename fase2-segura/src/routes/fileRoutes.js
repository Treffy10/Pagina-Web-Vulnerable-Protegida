const express = require('express');
const path = require('path');
const fs = require('fs');
const { requireAuth } = require('../middlewares/auth');
const noteService = require('../services/noteService');

const router = express.Router();

// Corrige VULN-04 de fase1 (uploads servidos publicamente sin control de
// acceso): el archivo solo se entrega si el usuario autenticado es dueno
// de la nota que lo referencia.
router.get('/:noteId', requireAuth, (req, res, next) => {
  try {
    const note = noteService.getNote(Number(req.params.noteId), req.user.id);
    if (!note.file_path) return res.status(404).json({ error: 'Sin archivo' });
    const filePath = path.join(__dirname, '..', '..', 'uploads', note.file_path);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'No encontrado' });
    res.sendFile(filePath);
  } catch (err) {
    err.status = 404;
    next(err);
  }
});

module.exports = router;
