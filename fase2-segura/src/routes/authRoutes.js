const express = require('express');
const rateLimit = require('express-rate-limit');
const { registerHandler, loginHandler, logoutHandler } = require('../controllers/authController');

const router = express.Router();

// Corrige VULN-07 de fase1 (login sin limite de intentos -> fuerza bruta).
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos de login, intenta mas tarde' }
});

router.post('/register', loginLimiter, registerHandler);
router.post('/login', loginLimiter, loginHandler);
router.post('/logout', logoutHandler);

module.exports = router;
