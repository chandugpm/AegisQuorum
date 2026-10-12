const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { makePolicyUpdate, approvePolicy, readJson } = require('./core');

function json(response, status, body) { response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); response.end(JSON.stringify(body)); }
function parse(request) { return new Promise((resolve, reject) => { let raw = ''; request.on('data', c => raw += c); request.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('invalid-json')); } }); }); }
function equal(a, b) { return typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); }
function requestJson(url, method = 'GET', payload, token) {
  return new Promise((resolve, reject) => {
    const target = new URL(url); const raw = payload ? JSON.stringify(payload) : undefined;
    const req = http.request({ hostname: target.hostname, port: target.port, path: target.pathname, method, headers: { ...(raw ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) } : {}), ...(token ? { 'x-node-service-token': token } : {}) }, timeout: 4000 }, res => { let data = ''; res.on('data', c => data += c); res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(data) }); } catch { reject(new Error('node-invalid-json')); } }); });
    req.on('error', reject); req.on('timeout', () => req.destroy(new Error('node-timeout'))); if (raw) req.write(raw); req.end();
  });
}
function startDashboard({ port = 7000, host = '127.0.0.1', nodeUrls, authorityDirectory, serviceToken, adminToken, staticDirectory = path.join(__dirname, '..', 'public') }) {
  if (!adminToken || adminToken.length < 24 || !serviceToken || serviceToken.length < 24) throw new Error('dashboard and service tokens must be at least 24 characters');
  const authorities = ['authority-1', 'authority-2', 'authority-3'].map(name => readJson(path.join(authorityDirectory, name, 'identity.json'), null));
  if (authorities.some(a => !a)) throw new Error('authority identities missing');
  const statuses = () => Promise.all(nodeUrls.map(async url => { try { return (await requestJson(`${url}/status`)).body; } catch (error) { return { name: url, mode: 'offline', error: error.message }; } }));
  const commandAll = (endpoint, payload) => Promise.all(nodeUrls.map(url => requestJson(`${url}${endpoint}`, 'POST', payload, serviceToken).catch(error => ({ status: 503, body: { error: error.message } }))));
  const server = http.createServer(async (request, response) => {
    try {
      if (request.method === 'GET' && request.url === '/') { response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); return response.end(fs.readFileSync(path.join(staticDirectory, 'index.html'))); }
      if (request.method === 'GET' && request.url === '/api/status') return json(response, 200, { nodes: await statuses() });
      if (request.method !== 'POST') return json(response, 404, { error: 'not-found' });
      if (!equal(request.headers['x-dashboard-admin-token'], adminToken)) return json(response, 401, { error: 'administrator-token-required' });
      const input = await parse(request);
      if (request.url === '/api/policy') {
        const current = await statuses(); const sequence = Math.max(...current.map(n => n.lastPolicySequence || 0)) + 1;
        const update = makePolicyUpdate(sequence, input.payload || { enforcement: 'observe-only' });
        const approvals = [approvePolicy(update, authorities[0]), approvePolicy(update, authorities[1])];
        return json(response, 200, { update, approvals: approvals.map(({ signature, ...visible }) => visible), results: await commandAll('/policy', { update, approvals }) });
      }
      if (request.url === '/api/demo') {
        const tamper = await commandAll('/simulate-tamper', {}); const scans = await commandAll('/scan', {}); const rollbacks = await commandAll('/rollback', {});
        return json(response, 200, { tamper, scans, rollbacks, nodes: await statuses() });
      }
      return json(response, 404, { error: 'not-found' });
    } catch (error) { return json(response, 500, { error: error.message }); }
  });
  server.listen(port, host, () => console.log(`Dashboard listening at http://${host}:${port}`)); return server;
}
if (require.main === module) startDashboard({ port: Number(process.env.PORT || 7000), host: process.env.HOST || '127.0.0.1', nodeUrls: (process.env.NODE_URLS || '').split(',').filter(Boolean), authorityDirectory: process.env.AUTHORITY_DIRECTORY, serviceToken: process.env.NODE_SERVICE_TOKEN, adminToken: process.env.DASHBOARD_ADMIN_TOKEN });
module.exports = { startDashboard, requestJson };
