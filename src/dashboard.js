const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { makePolicyUpdate, readJson, validatePolicyApprovals } = require('./core');
const { validToken } = require('./runtime-config');
const { RequestError, ReplayCache, requestSecurity, createMetrics, readJsonBody, createRateLimiter, clientKey } = require('./http-utils');

function json(response, status, body, headers = {}) { response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers }); response.end(JSON.stringify(body)); }
function equal(a, b) { return typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); }
function requestJson(url, method = 'GET', payload, token, security) {
  return new Promise((resolve, reject) => {
    const target = new URL(url); const raw = payload ? JSON.stringify(payload) : undefined;
    const req = http.request({ hostname: target.hostname, port: target.port, path: target.pathname, method, headers: { ...(raw ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) } : {}), ...(token ? { 'x-node-service-token': token } : {}), ...(security ? { 'x-request-id': security.id, 'x-request-timestamp': String(security.timestamp) } : {}) }, timeout: 4000 }, res => { let data = ''; res.on('data', c => { data += c; if (data.length > 65536) req.destroy(new Error('node-response-too-large')); }); res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(data) }); } catch { reject(new Error('node-invalid-json')); } }); });
    req.on('error', reject); req.on('timeout', () => req.destroy(new Error('node-timeout'))); if (raw) req.write(raw); req.end();
  });
}
function sanitizeNodeStatus(value, fallbackName) {
  if (!value || typeof value !== 'object' || typeof value.name !== 'string') return { name: fallbackName, mode: 'offline', error: 'unavailable' };
  return { name: value.name, mode: ['trusted', 'quarantined', 'safe-mode'].includes(value.mode) ? value.mode : 'unknown', quarantined: Boolean(value.quarantined), lastPolicySequence: Number.isSafeInteger(value.lastPolicySequence) ? value.lastPolicySequence : 0, trustedSnapshotPresent: Boolean(value.trustedSnapshot), audit: { valid: Boolean(value.audit?.valid), entries: Number.isSafeInteger(value.audit?.entries) ? value.audit.entries : 0 } };
}
function summarizeCommand(result, index) { return { node: `node-${String.fromCharCode(97 + index)}`, ok: result.status === 200, outcome: result.status === 200 ? 'completed' : 'unavailable' }; }
function summarizeWorkflow(stage, result, index) {
  const expected = { tamper: 'tampered', snapshot: 'valid', detection: 'quarantined', recovery: 'restored', verification: 'clean' }[stage];
  const ok = result.status === 200 && result.body?.[expected] === true;
  return { node: `node-${String.fromCharCode(97 + index)}`, ok, outcome: ok ? 'completed' : 'failed' };
}

function startDashboard({ port = 7000, host = '127.0.0.1', nodeUrls, authorityDirectory, authorityTrustFile, serviceToken, adminToken, operatorToken = process.env.DASHBOARD_OPERATOR_TOKEN || undefined, quorum = Number(process.env.POLICY_QUORUM || 2), staticDirectory = path.join(__dirname, '..', 'public'), logger = console, rateLimiter = createRateLimiter(), replayCache = new ReplayCache(), metrics = createMetrics() }) {
  if (operatorToken === '') operatorToken = undefined;
  if (!validToken(adminToken) || !validToken(serviceToken) || (operatorToken !== undefined && !validToken(operatorToken))) throw new Error('dashboard, operator, and service tokens must be non-whitespace tokens of at least 32 characters');
  if (!Array.isArray(nodeUrls) || nodeUrls.length === 0) throw new Error('at least one node URL is required');
  if (!Number.isSafeInteger(quorum) || quorum < 2 || quorum > 3) throw new Error('policy quorum is invalid');
  const trustedAuthorities = readJson(authorityTrustFile || path.join(path.dirname(authorityDirectory), 'authority-trust.json'), null);
  const authorityNames = ['authority-1', 'authority-2', 'authority-3'];
  if (!trustedAuthorities || authorityNames.some(name => typeof trustedAuthorities[name] !== 'string')) throw new Error('authority trust material missing or invalid');
  const statuses = () => Promise.all(nodeUrls.map(async (url, index) => { try { return sanitizeNodeStatus((await requestJson(`${url}/status`)).body, `node-${String.fromCharCode(97 + index)}`); } catch { return { name: `node-${String.fromCharCode(97 + index)}`, mode: 'offline', error: 'unavailable' }; } }));
  const auditReports = () => Promise.all(nodeUrls.map(async (url, index) => { try { const result = await requestJson(`${url}/audit`); return result.status === 200 ? result.body : { node: `node-${String.fromCharCode(97 + index)}`, verification: { valid: false }, events: [] }; } catch { return { node: `node-${String.fromCharCode(97 + index)}`, verification: { valid: false }, events: [] }; } }));
  const commandAll = (endpoint, payload, security) => Promise.all(nodeUrls.map(url => requestJson(`${url}${endpoint}`, 'POST', payload, serviceToken, security).catch(() => ({ status: 503, body: {} }))));
  let policyQueue = Promise.resolve();
  function serializePolicy(operation) {
    const result = policyQueue.then(operation, operation);
    policyQueue = result.then(() => undefined, () => undefined);
    return result;
  }
  const server = http.createServer(async (request, response) => {
    metrics.increment('http_requests_total');
    const url = new URL(request.url, 'http://dashboard.local'); const route = url.pathname;
    try {
      if (!rateLimiter.allow(clientKey(request))) return json(response, 429, { error: 'rate-limited' });
      if (request.method === 'GET' && route === '/') { response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); return response.end(fs.readFileSync(path.join(staticDirectory, 'index.html'))); }
      if (request.method === 'GET' && route === '/api/status') return json(response, 200, { nodes: await statuses() });
      if (request.method === 'GET' && route === '/api/policy/proposal') {
        const current = await statuses(); const sequence = Math.max(...current.map(node => node.lastPolicySequence || 0)) + 1;
        return json(response, 200, { update: makePolicyUpdate(sequence, { enforcement: 'observe-only', changeWindow: 'operator-requested' }), quorum });
      }
      if (request.method === 'GET' && route === '/api/audit') return json(response, 200, { nodes: await auditReports() }, url.searchParams.get('download') === '1' ? { 'content-disposition': 'attachment; filename="danms-audit-evidence.json"' } : {});
      if (request.method === 'GET' && route === '/metrics') return json(response, 200, metrics.snapshot());
      if (request.method !== 'POST') return json(response, 404, { error: 'not-found' });
      const suppliedAdmin = request.headers['x-dashboard-admin-token'];
      const suppliedOperator = request.headers['x-dashboard-operator-token'];
      const isAdmin = equal(suppliedAdmin, adminToken);
      const isOperator = operatorToken !== undefined && equal(suppliedOperator, operatorToken);
      if (!isAdmin && !isOperator) { metrics.increment('auth_failures_total'); return json(response, 401, { error: 'administrator-or-operator-token-required' }); }
      if (isOperator && route === '/api/demo') { metrics.increment('authorization_denials_total'); return json(response, 403, { error: 'admin-role-required' }); }
      const mutation = route === '/api/policy' || route === '/api/demo';
      const security = mutation ? requestSecurity(request, replayCache, { required: true }) : { checked: false };
      const input = await readJsonBody(request);
      if (route === '/api/policy') {
        if (!input.update || typeof input.update !== 'object' || Array.isArray(input.update) || !Array.isArray(input.approvals)) return json(response, 400, { error: 'invalid-policy-request' });
        return await serializePolicy(async () => {
          const current = await statuses(); const sequence = Math.max(...current.map(n => n.lastPolicySequence || 0)) + 1;
          if (input.update.sequence !== sequence) return json(response, 409, { error: 'stale-policy-proposal', expectedSequence: sequence });
          try { validatePolicyApprovals(input.update, input.approvals, trustedAuthorities, quorum, sequence - 1); }
          catch (error) { return json(response, 403, { error: error.message }); }
          const update = input.update; const approvals = input.approvals;
          const results = await commandAll('/policy', { update, approvals }, security); const summary = results.map(summarizeCommand);
          metrics.increment('replay_protected_operations_total');
          return json(response, nodeUrls.length > 0 && summary.length === nodeUrls.length && summary.every(result => result.ok) ? 200 : 503, { update: { sequence: update.sequence }, approvals: approvals.map(approval => approval.authority), results: summary });
        });
      }
      if (route === '/api/demo') {
        const downstream = stage => ({ id: `${crypto.createHash('sha256').update(security.id).digest('hex').slice(0, 32)}:${stage}`, timestamp: security.timestamp });
        const tamper = await commandAll('/simulate-tamper', {}, downstream('tamper')); const snapshot = await Promise.all(nodeUrls.map(url => requestJson(`${url}/snapshot`).catch(() => ({ status: 503, body: {} })))); const detection = await commandAll('/scan', {}, downstream('detection')); const recovery = await commandAll('/rollback', {}, downstream('recovery')); const verification = await commandAll('/scan', {}, downstream('verification'));
        const groups = { tamper, snapshot, detection, recovery, verification };
        const workflow = Object.fromEntries(Object.entries(groups).map(([name, results]) => [name, results.map((result, index) => summarizeWorkflow(name, result, index))]));
        const allOk = Object.values(workflow).flat().every(result => result.ok);
        return json(response, allOk ? 200 : 503, { workflow, nodes: await statuses(), audit: await auditReports() });
      }
      return json(response, 404, { error: 'not-found' });
    } catch (error) {
      metrics.increment('operation_failures_total');
      if (error instanceof RequestError) return json(response, error.code === 'request-too-large' ? 413 : error.code === 'stale-request' || error.code === 'replayed-request' ? 409 : 400, { error: error.code });
      logger.warn?.('dashboard-request-failed', { route });
      return json(response, 500, { error: 'request-failed' });
    }
  });
  server.listen(port, host, () => console.log(`Dashboard listening at http://${host}:${server.address().port}`)); return server;
}
if (require.main === module) startDashboard({ port: Number(process.env.PORT || 7000), host: process.env.HOST || '127.0.0.1', nodeUrls: (process.env.NODE_URLS || '').split(',').filter(Boolean), authorityDirectory: process.env.AUTHORITY_DIRECTORY, authorityTrustFile: process.env.AUTHORITY_TRUST_FILE, serviceToken: process.env.NODE_SERVICE_TOKEN, adminToken: process.env.DASHBOARD_ADMIN_TOKEN, operatorToken: process.env.DASHBOARD_OPERATOR_TOKEN });
module.exports = { startDashboard, requestJson, sanitizeNodeStatus };
