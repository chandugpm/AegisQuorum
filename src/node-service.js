const http = require('node:http');
const { SecurityNode, readJson } = require('./core');
const { validToken } = require('./runtime-config');

function json(response, status, body) { response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); response.end(JSON.stringify(body)); }
function body(request) { return new Promise((resolve, reject) => { let raw = ''; request.on('data', chunk => { raw += chunk; if (raw.length > 1_000_000) request.destroy(); }); request.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('invalid-json')); } }); }); }
function secureEqual(a, b) { return typeof a === 'string' && typeof b === 'string' && a.length === b.length && require('node:crypto').timingSafeEqual(Buffer.from(a), Buffer.from(b)); }

function startNode({ directory, name, authorityFile, port, host = '127.0.0.1', serviceToken }) {
  if (!validToken(serviceToken)) throw new Error('NODE_SERVICE_TOKEN must be a non-whitespace token of at least 32 characters');
  const trustedAuthorities = readJson(authorityFile, null);
  if (!trustedAuthorities || Object.keys(trustedAuthorities).length !== 3) throw new Error('authority trust file missing or invalid');
  const node = new SecurityNode({ directory, name, trustedAuthorities });
  const server = http.createServer(async (request, response) => {
    try {
      if (request.method === 'GET' && request.url === '/health') return json(response, 200, { ok: true, node: name });
      if (request.method === 'GET' && request.url === '/status') return json(response, 200, node.status());
      if (request.method === 'GET' && request.url === '/audit') return json(response, 200, { verification: node.verifyAudit() });
      if (request.method !== 'POST') return json(response, 404, { error: 'not-found' });
      if (!secureEqual(request.headers['x-node-service-token'], serviceToken)) return json(response, 401, { error: 'unauthorized' });
      const payload = await body(request);
      if (request.url === '/policy') return json(response, 200, node.applyPolicy(payload.update, payload.approvals));
      if (request.url === '/scan') return json(response, 200, node.scanIntegrity());
      if (request.url === '/rollback') return json(response, 200, node.rollback(payload.snapshotId));
      if (request.url === '/simulate-tamper') return json(response, 200, node.simulateTamper());
      return json(response, 404, { error: 'not-found' });
    } catch (error) { return json(response, 400, { error: error.message }); }
  });
  server.listen(port, host, () => console.log(`${name} listening at http://${host}:${server.address().port}`));
  return { server, node };
}

if (require.main === module) {
  startNode({ directory: process.env.NODE_DATA_DIR, name: process.env.NODE_NAME, authorityFile: process.env.AUTHORITY_FILE, port: Number(process.env.PORT), host: process.env.HOST || '127.0.0.1', serviceToken: process.env.NODE_SERVICE_TOKEN });
}
module.exports = { startNode };
