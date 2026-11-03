const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { once } = require('node:events');
const { createAuthorities, authorityTrust, writeJsonAtomic } = require('../src/core');
const { startNode } = require('../src/node-service');
const { startDashboard } = require('../src/dashboard');
const { createRateLimiter } = require('../src/http-utils');
const { runRedTeam } = require('../src/red-team');
const { exportStix } = require('../src/threat-intel');
const { techniquesForEvent, withEventTechniques, withAnalystTechniques, TECHNIQUES } = require('../src/mitre');
const { enabled, EXTENSION_ROUTES } = require('../src/extensions');

const adminToken = 'a'.repeat(32);
const serviceToken = 'b'.repeat(32);
let requestSequence = 0;

function requestJson(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(url); const raw = body === undefined ? undefined : JSON.stringify(body);
    const replay = method === 'POST' ? { 'x-request-id': `ext-test-${++requestSequence}`, 'x-request-timestamp': String(Date.now()) } : {};
    const request = http.request({ hostname: target.hostname, port: target.port, path: target.pathname, method, headers: { ...replay, ...headers, ...(raw === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) }) } }, response => {
      let data = ''; response.on('data', c => data += c); response.on('end', () => { try { resolve({ status: response.statusCode, body: JSON.parse(data) }); } catch { reject(new Error('invalid-json')); } });
    });
    request.on('error', reject); if (raw !== undefined) request.write(raw); request.end();
  });
}
async function waitFor(server) { if (!server.listening) await once(server, 'listening'); }
async function close(server) { if (server?.listening) await new Promise(resolve => server.close(resolve)); }

async function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-ext-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities'));
  const trust = path.join(root, 'trust.json'); writeJsonAtomic(trust, authorityTrust(authorities));
  const nodes = ['node-a', 'node-b', 'node-c'].map(name => startNode({ directory: path.join(root, name), name, authorityFile: trust, port: 0, serviceToken }));
  await Promise.all(nodes.map(node => waitFor(node.server))); t.after(async () => { await Promise.all(nodes.map(node => close(node.server))); });
  const nodeUrls = nodes.map(node => `http://127.0.0.1:${node.server.address().port}`);
  const dashboard = startDashboard({ port: 0, authorityDirectory: path.join(root, 'authorities'), authorityTrustFile: trust, nodeUrls, serviceToken, adminToken, rateLimiter: createRateLimiter({ perClientLimit: 100, globalLimit: 500 }) });
  await waitFor(dashboard); t.after(() => close(dashboard));
  return { root, nodes, base: `http://127.0.0.1:${dashboard.address().port}` };
}

test('red team blocks all five simulated attacks against temporary nodes', async () => {
  const result = await runRedTeam({ logger: { log() {}, warn() {}, error() {} } });
  assert.equal(result.scoreboard.attempted, 5);
  assert.equal(result.scoreboard.blocked, 5);
  assert.equal(result.scoreboard.succeeded, 0);
  const names = result.attacks.map(a => a.name);
  for (const expected of ['content-tamper', 'replayed-request', 'insufficient-approval', 'wrong-admin-token', 'decoy-honeypot-probe']) assert.ok(names.includes(expected));
  for (const attack of result.attacks) {
    assert.equal(attack.attempted, true);
    assert.equal(typeof attack.blocked, 'boolean');
    assert.ok(Number.isFinite(attack.detectedAtMs));
    assert.equal(typeof attack.defenseLayer, 'string');
    assert.ok(Array.isArray(attack.auditEventIds));
  }
});

test('MITRE mappings are truthful and attach as copies without mutating sources', () => {
  assert.deepEqual(techniquesForEvent('tamper-detected').map(t => t.id), ['T1565.001']);
  assert.deepEqual(techniquesForEvent('replayed-request').map(t => t.id), ['T1550']);
  assert.deepEqual(techniquesForEvent('auth-failure').map(t => t.id), ['T1078']);
  assert.deepEqual(techniquesForEvent('rollback-verified').map(t => t.id), ['M1053']);
  assert.deepEqual(techniquesForEvent('integrity-ok'), []);
  const event = { id: 'node-a:1', type: 'tamper-detected', evidence: { digest: 'x' } };
  const annotated = withEventTechniques(event);
  assert.notEqual(annotated, event);
  assert.equal(event.attackTechniques, undefined);
  assert.equal(annotated.attackTechniques[0].id, 'T1565.001');
  const response = { analysisStatus: 'fallback' };
  const withTags = withAnalystTechniques(response, ['tamper-detected', 'rollback-verified']);
  assert.deepEqual(withTags.attackTechniques.map(t => t.id).sort(), ['M1053', 'T1565.001']);
  assert.equal(response.attackTechniques, undefined);
  assert.ok(Object.values(TECHNIQUES).every(t => t.rationale && t.url));
});

test('threat-intel export builds a sanitized STIX bundle from signed antibodies', async t => {
  const f = await fixture(t);
  f.nodes[0].node.simulateTamper();
  f.nodes[0].node.scanIntegrity();
  const audit = await requestJson(`${f.base}/api/audit`);
  const bundle = exportStix(audit.body.nodes);
  assert.equal(bundle.type, 'bundle');
  const types = bundle.objects.map(o => o.type);
  assert.ok(types.includes('identity'));
  assert.ok(types.includes('attack-pattern'));
  assert.ok(types.includes('indicator'));
  const indicator = bundle.objects.find(o => o.type === 'indicator');
  assert.match(indicator.pattern, /SHA-256/);
  assert.equal(JSON.stringify(bundle).includes('privateKey'), false);
});

test('extension routes are registered and gated by admin auth and replay protection', async t => {
  const f = await fixture(t);
  if (!enabled()) {
    const off = await requestJson(`${f.base}/api/red-team/run`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: {} });
    assert.equal(off.status, 404);
    return;
  }
  const denied = await requestJson(`${f.base}/api/red-team/run`, { method: 'POST', body: {} });
  assert.equal(denied.status, 403);
  const run = await requestJson(`${f.base}/api/red-team/run`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: {} });
  assert.equal(run.status, 200);
  assert.equal(run.body.scoreboard.blocked, 5);
  const exportResult = await requestJson(`${f.base}/api/threat-intel/export`);
  assert.equal(exportResult.status, 200);
  assert.equal(exportResult.body.type, 'bundle');
  const benchmarks = await requestJson(`${f.base}/api/benchmarks`);
  assert.ok([200, 404].includes(benchmarks.status));
});

test('extensions flag and route set are correct', () => {
  assert.equal(enabled(), process.env.ENABLE_EXTENSIONS !== 'false');
  assert.deepEqual(EXTENSION_ROUTES, ['/api/red-team/run', '/api/benchmarks', '/api/threat-intel/export']);
});
