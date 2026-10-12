const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const { createAuthorities, authorityTrust, writeJsonAtomic } = require('../src/core');
const { startNode } = require('../src/node-service');
const { startDashboard } = require('../src/dashboard');
const { createRateLimiter } = require('../src/http-utils');

const adminToken = 'a'.repeat(32);
const serviceToken = 'b'.repeat(32);

function requestJson(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(url); const raw = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
    const request = http.request({ hostname: target.hostname, port: target.port, path: `${target.pathname}${target.search}`, method, headers: { ...headers, ...(raw === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) }) } }, response => { let data = ''; response.on('data', chunk => data += chunk); response.on('end', () => { try { resolve({ status: response.statusCode, headers: response.headers, body: JSON.parse(data) }); } catch { reject(new Error('invalid-json-response')); } }); });
    request.on('error', reject); if (raw !== undefined) request.write(raw); request.end();
  });
}
async function waitFor(server) { if (!server.listening) await once(server, 'listening'); }
async function close(server) { if (server.listening) await new Promise(resolve => server.close(resolve)); }
async function fixture(t, { nodeUrls, rateLimiter } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-dashboard-')); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities')); const trust = path.join(root, 'trust.json'); writeJsonAtomic(trust, authorityTrust(authorities));
  const nodes = nodeUrls ? [] : ['node-a', 'node-b', 'node-c'].map(name => startNode({ directory: path.join(root, name), name, authorityFile: trust, port: 0, serviceToken }));
  await Promise.all(nodes.map(node => waitFor(node.server))); t.after(async () => { await Promise.all(nodes.map(node => close(node.server))); });
  const urls = nodeUrls || nodes.map(node => `http://127.0.0.1:${node.server.address().port}`);
  const dashboard = startDashboard({ port: 0, authorityDirectory: path.join(root, 'authorities'), nodeUrls: urls, serviceToken, adminToken, rateLimiter: rateLimiter || createRateLimiter({ perClientLimit: 100, globalLimit: 100 }) });
  await waitFor(dashboard); t.after(() => close(dashboard));
  return { root, nodes, base: `http://127.0.0.1:${dashboard.address().port}` };
}

test('dashboard reports sanitized live state and executes the authenticated real three-node workflow', async t => {
  const f = await fixture(t);
  const status = await requestJson(`${f.base}/api/status`);
  assert.equal(status.status, 200); assert.equal(status.body.nodes.length, 3); assert.ok(status.body.nodes.every(node => node.mode === 'trusted' && node.audit.valid));
  assert.equal(JSON.stringify(status.body).includes(serviceToken), false); assert.equal(JSON.stringify(status.body).includes('privateKey'), false);

  const deniedPolicy = await requestJson(`${f.base}/api/policy`, { method: 'POST', body: { payload: { enforcement: 'observe-only' } } });
  const deniedDemo = await requestJson(`${f.base}/api/demo`, { method: 'POST', body: {} });
  assert.equal(deniedPolicy.status, 401); assert.equal(deniedDemo.status, 401);

  const workflow = await requestJson(`${f.base}/api/demo`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: {} });
  assert.equal(workflow.status, 200); assert.deepEqual(Object.keys(workflow.body.workflow), ['tamper', 'snapshot', 'detection', 'recovery', 'verification']);
  assert.ok(Object.values(workflow.body.workflow).flat().every(result => result.ok));
  assert.ok(workflow.body.nodes.every(node => node.mode === 'trusted' && node.audit.valid));
  const audit = await requestJson(`${f.base}/api/audit?download=1`);
  assert.equal(audit.status, 200); assert.match(audit.headers['content-disposition'], /attachment/); assert.ok(audit.body.nodes.every(report => report.verification.valid));
  assert.equal(JSON.stringify(audit.body).includes('source'), false, 'filesystem source paths are removed from evidence');
  assert.equal(JSON.stringify(audit.body).includes('privateKey'), false);
});

test('dashboard returns safe unavailable-node results, enforces request limits, and rate limits callers', async t => {
  const f = await fixture(t, { nodeUrls: ['http://127.0.0.1:1'], rateLimiter: createRateLimiter({ perClientLimit: 3, globalLimit: 3 }) });
  const status = await requestJson(`${f.base}/api/status`);
  assert.deepEqual(status.body.nodes, [{ name: 'node-a', mode: 'offline', error: 'unavailable' }]);
  const failedPolicy = await requestJson(`${f.base}/api/policy`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: { payload: { enforcement: 'observe-only' } } });
  assert.equal(failedPolicy.status, 503); assert.deepEqual(failedPolicy.body.results, [{ node: 'node-a', ok: false, outcome: 'unavailable' }]);

  const f2 = await fixture(t, { nodeUrls: ['http://127.0.0.1:1'], rateLimiter: createRateLimiter({ perClientLimit: 100, globalLimit: 100 }) });
  const oversized = await requestJson(`${f2.base}/api/demo`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: 'x'.repeat(9000) });
  assert.equal(oversized.status, 413); assert.equal(oversized.body.error, 'request-too-large');

  const f3 = await fixture(t, { nodeUrls: ['http://127.0.0.1:1'], rateLimiter: createRateLimiter({ perClientLimit: 2, globalLimit: 2 }) });
  assert.equal((await requestJson(`${f3.base}/api/status`)).status, 200); assert.equal((await requestJson(`${f3.base}/api/status`)).status, 200); const limited = await requestJson(`${f3.base}/api/status`); assert.equal(limited.status, 429); assert.equal(limited.body.error, 'rate-limited');
});
