const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const env = require('./config/env');
const errorHandler = require('./middlewares/errorHandler');
const authRoutes = require('./routes/authRoutes');
const noteRoutes = require('./routes/noteRoutes');
const fileRoutes = require('./routes/fileRoutes');

const app = express();

app.disable('x-powered-by');

// Cabeceras de seguridad (CSP, HSTS, noSniff, etc.) - fix de VULN faltante
// en fase1 donde no habia ninguna cabecera de seguridad configurada.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:']
    }
  }
}));

// Corrige VULN-01 de fase1 (CORS abierto a "*" con credenciales):
// origen restringido a la lista blanca configurada por entorno.
app.use(cors({ origin: env.corsOrigin, credentials: true }));

// Mitigacion CSRF: la cookie de sesion usa SameSite=Strict (ver
// authController) por lo que el navegador no la envia en peticiones
// cross-site; ademas CORS restringido evita que otros origenes invoquen
// la API con credenciales. Corrige la ausencia total de proteccion CSRF
// de fase1.

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(cookieParser(env.cookieSecret));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

// JS de las vistas servido como archivo externo (no inline) para poder
// mantener una CSP estricta (scriptSrc 'self' sin 'unsafe-inline').
app.use('/js', express.static(path.join(__dirname, '..', 'public', 'js')));

app.use('/api/auth', authRoutes);
app.use('/api/notes', noteRoutes);
app.use('/api/files', fileRoutes);

app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));
app.get('/notes', (req, res) => res.render('notes'));
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Nota: NO se sirve /uploads como estatico (fix VULN-04); el acceso a
// archivos pasa siempre por /api/files/:noteId con verificacion de dueno.

app.use((req, res) => res.status(404).json({ error: 'No encontrado' }));
app.use(errorHandler);

module.exports = app;
