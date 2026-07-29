const test = require('node:test');
const assert = require('node:assert');

process.env.JWT_SECRET = 'test-secret-value-1234567890';
process.env.COOKIE_SECRET = 'test-cookie-secret-1234567890';
process.env.DB_PATH = './data/test.sqlite';

const app = require('../src/app');
const http = require('node:http');

function request(server, options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('rechaza login con credenciales invalidas', async () => {
  const server = app.listen(0);
  const port = server.address().port;
  const payload = JSON.stringify({ username: 'noexiste', password: 'wrongpassword' });
  const res = await request(server, {
    hostname: 'localhost', port, path: '/api/auth/login', method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
  }, payload);
  assert.strictEqual(res.status, 401);
  server.close();
});

test('rechaza acceso a notas sin token', async () => {
  const server = app.listen(0);
  const port = server.address().port;
  const res = await request(server, {
    hostname: 'localhost', port, path: '/api/notes', method: 'GET'
  });
  assert.strictEqual(res.status, 401);
  server.close();
});
