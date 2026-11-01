const http = require('node:http');
const crypto = require('node:crypto');
const { SecurityNode, readJson, sha256 } = require('./core');
const { validToken } = require('./runtime-config');
const { RequestError, ReplayCache, requestSecurity, createMetrics, readJsonBody, createRateLimiter, clientKey } = require('./http-utils');
const { createIncidentAnalyst } = require('./ai-analyst');

function json(response, status, body) { response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); response.end(JSON.stringify(body)); }
function secureEqual(a, b) { return typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); }
function normalizePeerUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '::1'].includes(url.hostname) || url.username || url.password) return null;
    return url.origin;
  } catch { return null; }
}
function postPeerJson(url, payload, serviceToken) {
  return new Promise(resolve => {
    const target = new URL(url);
    const body = JSON.stringify(payload);
    const requestId = `gossip-${crypto.randomUUID()}`;
    const request = http.request({
      hostname: target.hostname, port: target.port, path: '/gossip/inoculate', method: 'POST', timeout: 2500,
      headers: {
        'content-type': 'application/json', 'content-length': Buffer.byteLength(body),
        'x-node-service-token': serviceToken, 'x-request-id': requestId,
        'x-request-timestamp': String(Date.now())
      }
    }, response => {
      let raw = '';
      response.on('data', chunk => { raw += chunk; if (raw.length > 16384) request.destroy(); });
      response.on('end', () => {
        try { resolve({ ok: response.statusCode === 200, status: response.statusCode, body: JSON.parse(raw) }); }
        catch { resolve({ ok: false, status: response.statusCode || 502 }); }
      });
    });
    request.on('error', () => resolve({ ok: false, status: 503 }));
    request.on('timeout', () => request.destroy(new Error('peer-timeout')));
    request.end(body);
  });
}

function startNode({ directory, name, authorityFile, port, host = '127.0.0.1', serviceToken, peerUrls = [], quorum = Number(process.env.POLICY_QUORUM || 2), replayCache = new ReplayCache(), metrics = createMetrics(), rateLimiter = createRateLimiter({ perClientLimit: 60, globalLimit: 300 }), shieldRateLimiter = createRateLimiter({ perClientLimit: 10, globalLimit: 60 }), deceptionAnalyst = createIncidentAnalyst() }) {
  if (!validToken(serviceToken)) throw new Error('NODE_SERVICE_TOKEN must be a non-whitespace token of at least 32 characters');
  const trustedAuthorities = readJson(authorityFile, null);
  if (!trustedAuthorities || Object.keys(trustedAuthorities).length !== 3) throw new Error('authority trust file missing or invalid');
  const node = new SecurityNode({ directory, name, trustedAuthorities, quorum });
  const peers = [...new Set((Array.isArray(peerUrls) ? peerUrls : []).map(normalizePeerUrl).filter(url => url && url !== `http://${host}:${port}`))];
  async function broadcastAntibody() {
    if (!peers.length) return [];
    const envelope = node.threatAntibody();
    const deliveries = await Promise.all(peers.map(async peer => {
      const result = await postPeerJson(peer, envelope, serviceToken);
      return { peer, inoculated: result.ok && result.body?.inoculated === true, status: result.status };
    }));
    node.appendAudit('threat-antibody-broadcast', {
      attackVectorHash: envelope.packet.attackVectorHash,
      peerCount: deliveries.length,
      inoculatedCount: deliveries.filter(item => item.inoculated).length
    });
    return deliveries;
  }
  const server = http.createServer(async (request, response) => {
    metrics.increment('http_requests_total');
    try {
      const requester = clientKey(request);
      if (!rateLimiter.allow(requester) || (node.state.shieldState === 'INOCULATED_SHIELD' && !shieldRateLimiter.allow(requester))) return json(response, 429, { error: 'rate-limited' });
      const route = new URL(request.url, 'http://node.local').pathname;
      if (request.method === 'GET' && route === '/health') return json(response, 200, { ok: true, node: name });
      if (request.method === 'GET' && route === '/status') return json(response, 200, node.status());
      if (request.method === 'GET' && route === '/audit') return json(response, 200, node.auditReport());
      if (request.method === 'GET' && route === '/metrics') return json(response, 200, metrics.snapshot());
      if (request.method === 'GET' && route === '/snapshot') return json(response, 200, { valid: node.verifySnapshot().valid });
      if (request.method === 'GET' && route === '/threat-antibody') {
        if (!secureEqual(request.headers['x-node-service-token'], serviceToken)) return json(response, 401, { error: 'unauthorized' });
        return json(response, 200, node.threatAntibody());
      }
      if (request.method !== 'POST') return json(response, 404, { error: 'not-found' });
      if (!secureEqual(request.headers['x-node-service-token'], serviceToken)) { metrics.increment('auth_failures_total'); return json(response, 401, { error: 'unauthorized' }); }
      if (!['/policy', '/scan', '/rollback', '/simulate-tamper', '/deception-probe', '/gossip/inoculate', '/dry-run', '/webauthn/authority'].includes(route)) return json(response, 404, { error: 'not-found' });
      const security = requestSecurity(request, replayCache, { required: true });
      const payload = await readJsonBody(request);
      const requestedVector = typeof payload.attackVectorHash === 'string' ? payload.attackVectorHash
        : route === '/deception-probe' && typeof payload.input === 'string' ? sha256(Buffer.from(payload.input.slice(0, 512))) : null;
      if (requestedVector && node.state.blockList?.includes(requestedVector)) {
        node.appendAudit('gossip-vector-blocked', { vectorHash: requestedVector });
        return json(response, 403, { error: 'gossip-vector-blocked' });
      }
      let result;
      if (route === '/policy') result = node.applyPolicy(payload.update, payload.approvals);
      else if (route === '/scan') {
        result = node.scanIntegrity();
        if (result.quarantined) result.gossipDeliveries = await broadcastAntibody();
      }
      else if (route === '/rollback') result = node.rollback(payload.snapshotId);
      else if (route === '/simulate-tamper') result = node.simulateTamper();
      else if (route === '/deception-probe') {
        const fingerprint = node.deceptionProbe(payload);
        const response = await deceptionAnalyst.deceptionResponse({
          commandPattern: fingerprint.threatFingerprint.commandPattern,
          payloadDigest: fingerprint.threatFingerprint.payloadDigest
        });
        result = { ...fingerprint, response: response.response, ai: response };
      } else if (route === '/gossip/inoculate') result = node.inoculate(payload.packet, payload.sourcePublicKey);
      else if (route === '/dry-run') result = node.executeDryRunSandbox(payload.candidatePolicy);
      else if (route === '/webauthn/authority') result = node.registerWebAuthnAuthority(payload.authority, payload.credential);
      if (result) { if (security.checked) node.appendAudit('request-accepted', { requestId: security.id, route }); return json(response, 200, result); }
      return json(response, 404, { error: 'not-found' });
    } catch (error) { metrics.increment('operation_failures_total'); return json(response, error instanceof RequestError && error.code === 'request-too-large' ? 413 : error instanceof RequestError && (error.code === 'stale-request' || error.code === 'replayed-request') ? 409 : 400, { error: error instanceof RequestError ? error.code : 'operation-rejected' }); }
  });
  server.listen(port, host, () => console.log(`${name} listening at http://${host}:${server.address().port}`));
  return { server, node };
}

if (require.main === module) {
  startNode({ directory: process.env.NODE_DATA_DIR, name: process.env.NODE_NAME, authorityFile: process.env.AUTHORITY_FILE, port: Number(process.env.PORT), host: process.env.HOST || '127.0.0.1', serviceToken: process.env.NODE_SERVICE_TOKEN, peerUrls: (process.env.PEER_NODE_URLS || '').split(',').filter(Boolean) });
}
module.exports = { startNode };
