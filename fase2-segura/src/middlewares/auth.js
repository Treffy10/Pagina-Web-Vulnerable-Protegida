const jwt = require('jsonwebtoken');
const env = require('../config/env');

// Middleware de autenticacion real y reutilizable (fix de VULN-10 de fase1,
// donde existia un middleware "noop" que no verificaba nada).
function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.token;
  if (!token) return res.status(401).json({ error: 'No autenticado' });
  try {
    const payload = jwt.verify(token, env.jwtSecret);
    req.user = { id: payload.sub, username: payload.username };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Sesion invalida o expirada' });
  }
}

module.exports = { requireAuth };
