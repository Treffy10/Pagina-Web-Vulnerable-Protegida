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
    return cb(new Error('Tipo de archivo no permitido'));
  }
  cb(null, true);
}

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: env.maxUploadMb * 1024 * 1024 }
});

module.exports = upload;
