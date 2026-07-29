const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const userModel = require('../models/userModel');
const env = require('../config/env');

const SALT_ROUNDS = 12;

// Corrige VULN-05 de fase1 (MD5 sin salt) usando bcrypt con costo adecuado.
async function register(username, password) {
  const existing = userModel.findByUsername(username);
  if (existing) throw new Error('El usuario ya existe');
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  userModel.create(username, hash);
}

async function login(username, password) {
  const user = userModel.findByUsername(username);
  // Respuesta generica para no revelar si el usuario existe (evita
  // enumeracion de usuarios, y usamos comparacion en tiempo constante
  // que ofrece bcrypt.compare).
  if (!user) {
    await bcrypt.compare(password, '$2b$12$invalidinvalidinvalidinvalidinvalidinva');
    throw new Error('Credenciales invalidas');
  }
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) throw new Error('Credenciales invalidas');

  const token = jwt.sign(
    { sub: user.id, username: user.username },
    env.jwtSecret,
    { expiresIn: '1h' }
  );
  return { token, user: { id: user.id, username: user.username } };
}

module.exports = { register, login };
