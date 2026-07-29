// Carga y valida la configuracion desde variables de entorno.
// Corrige VULN-02 (secretos hardcodeados) de fase 1.
require('dotenv').config();
const { z } = require('zod');

const schema = z.object({
  PORT: z.string().default('3002'),
  NODE_ENV: z.string().default('development'),
  JWT_SECRET: z.string().min(16, 'JWT_SECRET debe tener al menos 16 caracteres'),
  COOKIE_SECRET: z.string().min(16, 'COOKIE_SECRET debe tener al menos 16 caracteres'),
  DB_PATH: z.string().default('./data/database.sqlite'),
  CORS_ORIGIN: z.string().default('http://localhost:3002'),
  MAX_UPLOAD_MB: z.string().default('5')
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  // Fallamos rapido y claro si falta configuracion critica (fail-secure).
  console.error('Configuracion invalida:', parsed.error.flatten().fieldErrors);
  process.exit(1);
}

module.exports = {
  port: Number(parsed.data.PORT),
  nodeEnv: parsed.data.NODE_ENV,
  jwtSecret: parsed.data.JWT_SECRET,
  cookieSecret: parsed.data.COOKIE_SECRET,
  dbPath: parsed.data.DB_PATH,
  corsOrigin: parsed.data.CORS_ORIGIN,
  maxUploadMb: Number(parsed.data.MAX_UPLOAD_MB)
};
