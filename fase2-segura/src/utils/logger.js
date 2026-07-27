// Logging estructurado sin exponer datos sensibles (fix de VULN-09 de fase1:
// mensajes de error verbosos con stack traces enviados al cliente).
const winston = require('winston');
const env = require('../config/env');

const logger = winston.createLogger({
  level: env.nodeEnv === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()]
});

module.exports = logger;
