/**
 * FASE 1 - VERSION INSEGURA (para fines educativos / analisis de seguridad)
 * NO USAR EN PRODUCCION.
 *
 * Esta aplicacion fue construida SIN un enfoque DevSecOps: sin analisis de
 * amenazas, sin revision de dependencias, sin validacion de entradas, y
 * mezclando toda la logica en un solo archivo. Contiene vulnerabilidades
 * intencionales que se documentan en el informe tecnico (informe-tecnico.docx)
 * y que se corrigen en fase2-segura/.
 */
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const session = require('express-session');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();

// VULN-01: CORS abierto a cualquier origen, con credenciales.
app.use(cors({ origin: '*', credentials: true }));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// VULN-02: secreto de sesion hardcodeado en el codigo fuente.
// VULN-03: cookie de sesion sin flags Secure ni SameSite explicitos (queda
// en los defaults de express-session: secure=false, sameSite=false), por lo
// que viaja igual por HTTP sin cifrar y se envia en peticiones cross-site.
// httpOnly si viene activado por defecto en express-session, pero secure/
// sameSite no, y eso es justamente lo que fase2 corrige explicitamente.
app.use(session({
  secret: 'clave-secreta-super-facil-123',
  resave: false,
  saveUninitialized: true,
  cookie: {} // sin secure, sin sameSite (httpOnly viene por defecto de la libreria)
}));

// VULN-04: los archivos subidos se sirven publicamente desde /uploads
// sin control de acceso ni verificacion de propietario.
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/public', express.static(path.join(__dirname, 'public')));

// --- Base de datos ---
const db = new sqlite3.Database('./database.sqlite');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    content TEXT,
    file_path TEXT
  )`);

  // VULN-05: hashing debil (MD5, sin salt) para contrasenas.
  const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
  db.get(`SELECT COUNT(*) as c FROM users`, (err, row) => {
    if (row && row.c === 0) {
      db.run(`INSERT INTO users (username, password) VALUES (?, ?)`,
        ['admin', md5('admin123')]);
    }
  });
});

const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');

// --- Subida de archivos ---
// VULN-06: sin whitelist de tipos/extension, sin limite de tamano,
// se conserva el nombre original (riesgo de path traversal / sobrescritura
// / ejecucion si el server tiene la extension habilitada).
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

// --- Login ---
// VULN-07: sin limite de intentos (fuerza bruta libre).
// VULN-08: inyeccion SQL por concatenacion de strings.
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const hashed = md5(password || '');
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${hashed}'`;
  db.get(query, (err, user) => {
    // VULN-09: mensajes de error verbosos (exponen detalles internos/stack).
    if (err) return res.status(500).send('Error interno: ' + err.message + '\n' + err.stack);
    if (!user) return res.render('login', { error: 'Usuario o contrasena incorrectos' });
    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect('/notes');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// VULN-10: no hay middleware de autenticacion real reutilizable;
// las rutas de abajo confian unicamente en la sesion presente en el
// navegador y no verifican pertenencia de recursos (IDOR).
function noopAuth(req, res, next) { next(); } // "proteccion" decorativa

// --- CRUD de notas (con archivo adjunto opcional) ---
app.get('/notes', noopAuth, (req, res) => {
  db.all(`SELECT * FROM notes`, (err, rows) => { // VULN-11: IDOR, devuelve notas de TODOS los usuarios
    res.render('notes', { notes: rows, user: req.session.username });
  });
});

// GET por id - cualquiera con sesion (o sin ella, ver VULN-10) puede leer cualquier nota
app.get('/notes/:id', noopAuth, (req, res) => {
  const query = `SELECT * FROM notes WHERE id = ${req.params.id}`; // VULN-12: SQLi (parametro numerico sin sanitizar)
  db.get(query, (err, note) => {
    if (err) return res.status(500).send('Error: ' + err.message);
    res.json(note);
  });
});

app.post('/notes', noopAuth, upload.single('file'), (req, res) => {
  const { title, content } = req.body;
  const filePath = req.file ? req.file.filename : null;
  db.run(`INSERT INTO notes (user_id, title, content, file_path) VALUES (?, ?, ?, ?)`,
    [req.session.userId || null, title, content, filePath],
    function (err) {
      if (err) return res.status(500).send('Error: ' + err.message);
      res.redirect('/notes');
    });
});

// UPDATE - VULN-13: no verifica que la nota pertenezca al usuario en sesion.
app.put('/notes/:id', noopAuth, (req, res) => {
  const { title, content } = req.body;
  db.run(`UPDATE notes SET title = ?, content = ? WHERE id = ?`,
    [title, content, req.params.id],
    function (err) {
      if (err) return res.status(500).send('Error: ' + err.message);
      res.json({ updated: this.changes });
    });
});

// DELETE - VULN-14: mismo problema, cualquiera borra cualquier nota, sin CSRF token.
app.delete('/notes/:id', noopAuth, (req, res) => {
  db.run(`DELETE FROM notes WHERE id = ?`, [req.params.id], function (err) {
    if (err) return res.status(500).send('Error: ' + err.message);
    res.json({ deleted: this.changes });
  });
});

const PORT = 3001;
app.listen(PORT, () => console.log(`Fase1 (insegura) escuchando en http://localhost:${PORT}`));
