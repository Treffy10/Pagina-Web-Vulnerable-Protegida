const { z } = require('zod');
const authService = require('../services/authService');
const env = require('../config/env');

const credentialsSchema = z.object({
  username: z.string().min(3).max(50),
  password: z.string().min(8).max(200)
});

async function registerHandler(req, res, next) {
  try {
    const { username, password } = credentialsSchema.parse(req.body);
    await authService.register(username, password);
    res.status(201).json({ message: 'Usuario creado' });
  } catch (err) {
    err.status = 400;
    next(err);
  }
}

async function loginHandler(req, res, next) {
  try {
    const { username, password } = credentialsSchema.parse(req.body);
    const { token, user } = await authService.login(username, password);
    // Cookie httpOnly + secure (en produccion) + sameSite=strict corrige
    // VULN-03 de fase1 (cookie de sesion sin proteccion).
    res.cookie('token', token, {
      httpOnly: true,
      secure: env.nodeEnv === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000
    });
    res.json({ message: 'Login correcto', user });
  } catch (err) {
    err.status = 401;
    next(err);
  }
}

function logoutHandler(req, res) {
  res.clearCookie('token');
  res.json({ message: 'Sesion cerrada' });
}

module.exports = { registerHandler, loginHandler, logoutHandler };
