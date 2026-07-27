const logger = require('../utils/logger');

// Manejo centralizado de errores: se registra el detalle en el log del
// servidor pero al cliente solo se envia un mensaje generico. Corrige
// VULN-09 de fase1 (stack traces expuestos en la respuesta HTTP).
function errorHandler(err, req, res, _next) {
  logger.error(err.message, { stack: err.stack, path: req.path });
  const status = err.status || 500;
  const publicMessage = status < 500 ? err.message : 'Error interno del servidor';
  res.status(status).json({ error: publicMessage });
}

module.exports = errorHandler;
