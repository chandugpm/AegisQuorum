const http = require('node:http');
const { SecurityNode, readJson } = require('./core');
const { validToken } = require('./runtime-config');
const { RequestError, ReplayCache, requestSecurity, createMetrics, readJsonBody } = require('./http-utils');

function json(response, status, body) { response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); response.end(JSON.stringify(body)); }
function secureEqual(a, b) { return typeof a === 'string' && typeof b === 'string' && a.length === b.length && require('node:crypto').timingSafeEqual(Buffer.from(a), Buffer.from(b)); }

function startNode({ directory, name, authorityFile, port, host = '127.0.0.1', serviceToken, quorum = Number(process.env.POLICY_QUORUM || 2), replayCache = new ReplayCache(), metrics = createMetrics() }) {
  if (!validToken(serviceToken)) throw new Error('NODE_SERVICE_TOKEN must be a non-whitespace token of at least 32 characters');
  const trustedAuthorities = readJson(authorityFile, null);
  if (!trustedAuthorities || Object.keys(trustedAuthorities).length !== 3) throw new Error('authority trust file missing or invalid');
  const node = new SecurityNode({ directory, name, trustedAuthorities, quorum });
  const server = http.createServer(async (request, response) => {
    metrics.increment('http_requests_total');
    try {
      const route = new URL(request.url, 'http://node.local').pathname;
      if (request.method === 'GET' && route === '/health') return json(response, 200, { ok: true, node: name });
      if (request.method === 'GET' && route === '/status') return json(response, 200, node.status());
      if (request.method === 'GET' && route === '/audit') return json(response, 200, node.auditReport());
      if (request.method === 'GET' && route === '/metrics') return json(response, 200, metrics.snapshot());
      if (request.method === 'GET' && route === '/snapshot') return json(response, 200, { valid: node.verifySnapshot().valid });
      if (request.method !== 'POST') return json(response, 404, { error: 'not-found' });
      if (!secureEqual(request.headers['x-node-service-token'], serviceToken)) { metrics.increment('auth_failures_total'); return json(response, 401, { error: 'unauthorized' }); }
      const security = requestSecurity(request, replayCache);
      const payload = await readJsonBody(request);
      const result = route === '/policy' ? node.applyPolicy(payload.update, payload.approvals) : route === '/scan' ? node.scanIntegrity() : route === '/rollback' ? node.rollback(payload.snapshotId) : route === '/simulate-tamper' ? node.simulateTamper() : null;
      if (result) { if (security.checked) node.appendAudit('request-accepted', { requestId: security.id, route }); return json(response, 200, result); }
      return json(response, 404, { error: 'not-found' });
    } catch (error) { metrics.increment('operation_failures_total'); return json(response, error instanceof RequestError && error.code === 'request-too-large' ? 413 : error instanceof RequestError && (error.code === 'stale-request' || error.code === 'replayed-request') ? 409 : 400, { error: error instanceof RequestError ? error.code : 'operation-rejected' }); }
  });
  server.listen(port, host, () => console.log(`${name} listening at http://${host}:${server.address().port}`));
  return { server, node };
}

if (require.main === module) {
  startNode({ directory: process.env.NODE_DATA_DIR, name: process.env.NODE_NAME, authorityFile: process.env.AUTHORITY_FILE, port: Number(process.env.PORT), host: process.env.HOST || '127.0.0.1', serviceToken: process.env.NODE_SERVICE_TOKEN });
}
module.exports = { startNode };
