const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const env = require('./../config/env');

const UPLOAD_DIR = path.join(__dirname, '..', '..', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Whitelist de mimetypes/extensiones permitidas. Corrige VULN-06 de fase1
// (sin validacion de tipo, sin limite de tamano, nombre original conservado
// -> path traversal / sobrescritura / posible ejecucion).
const ALLOWED_MIME = new Set([
  'image/png', 'image/jpeg', 'image/gif', 'application/pdf', 'text/plain'
]);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    // Nombre generado por el servidor: elimina cualquier posibilidad de
    // path traversal o colision/sobrescritura via nombre de archivo.
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${uuidv4()}${ext}`);
  }
});

function fileFilter(req, file, cb) {
  if (!ALLOWED_MIME.has(file.mimetype)) {
    const err = new Error('Tipo de archivo no permitido');
    err.status = 400; // sin esto, el error handler central lo devolvia como 500
    return cb(err);
  }
  cb(null, true);
}

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: env.maxUploadMb * 1024 * 1024 }
});

// Envuelve upload.single(field) para que cualquier error de multer
// (mimetype no permitido, archivo demasiado grande, etc.) se reporte
// como 400 en vez de caer al 500 generico del error handler central.
function uploadSingle(fieldName) {
  return (req, res, next) => {
    upload.single(fieldName)(req, res, (err) => {
      if (err) {
        if (!err.status) err.status = 400;
        return next(err);
      }
      next();
    });
  };
}

module.exports = { upload, uploadSingle };
