const app = require('./app');
const env = require('./config/env');
const logger = require('./utils/logger');

app.listen(env.port, () => {
  logger.info(`Fase2 (segura) escuchando en http://localhost:${env.port}`);
});
