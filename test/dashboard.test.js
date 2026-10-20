const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const { createAuthorities, authorityTrust, approvePolicy, writeJsonAtomic } = require('../src/core');
const { startNode } = require('../src/node-service');
const { startDashboard } = require('../src/dashboard');
const { createRateLimiter } = require('../src/http-utils');

const adminToken = 'a'.repeat(32);
const serviceToken = 'b'.repeat(32);
const operatorToken = 'o'.repeat(32);
let requestSequence = 0;

function requestJson(url, { method = 'GET', headers = {}, body, replayProtection = true } = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(url); const raw = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
    const replayHeaders = method === 'POST' && replayProtection ? { 'x-request-id': `dashboard-test-${++requestSequence}`, 'x-request-timestamp': String(Date.now()) } : {};
    const request = http.request({ hostname: target.hostname, port: target.port, path: `${target.pathname}${target.search}`, method, headers: { ...replayHeaders, ...headers, ...(raw === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) }) } }, response => { let data = ''; response.on('data', chunk => data += chunk); response.on('end', () => { try { resolve({ status: response.statusCode, headers: response.headers, body: JSON.parse(data) }); } catch { reject(new Error('invalid-json-response')); } }); });
    request.on('error', reject); if (raw !== undefined) request.write(raw); request.end();
  });
}
function requestText(url) {
  return new Promise((resolve, reject) => {
    http.get(url, response => { let data = ''; response.on('data', chunk => data += chunk); response.on('end', () => resolve({ status: response.statusCode, body: data })); }).on('error', reject);
  });
}
async function waitFor(server) { if (!server.listening) await once(server, 'listening'); }
async function close(server) { if (server.listening) await new Promise(resolve => server.close(resolve)); }
async function fixture(t, { nodeUrls, rateLimiter, incidentRateLimiter, incidentAnalyst, quorum = 2, configuredOperatorToken = operatorToken } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-dashboard-')); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities')); const trust = path.join(root, 'trust.json'); writeJsonAtomic(trust, authorityTrust(authorities));
  const nodes = nodeUrls ? [] : ['node-a', 'node-b', 'node-c'].map(name => startNode({ directory: path.join(root, name), name, authorityFile: trust, port: 0, serviceToken, quorum }));
  await Promise.all(nodes.map(node => waitFor(node.server))); t.after(async () => { await Promise.all(nodes.map(node => close(node.server))); });
  const urls = nodeUrls || nodes.map(node => `http://127.0.0.1:${node.server.address().port}`);
  const dashboard = startDashboard({ port: 0, authorityDirectory: path.join(root, 'authorities'), authorityTrustFile: trust, nodeUrls: urls, serviceToken, adminToken, operatorToken: configuredOperatorToken, quorum, rateLimiter: rateLimiter || createRateLimiter({ perClientLimit: 100, globalLimit: 100 }), incidentRateLimiter, incidentAnalyst });
  await waitFor(dashboard); t.after(() => close(dashboard));
  return { root, nodes, authorities, base: `http://127.0.0.1:${dashboard.address().port}` };
}
async function approvedPolicy(f, quorum = 2) {
  const proposal = await requestJson(`${f.base}/api/policy/proposal`);
  const update = proposal.body.update;
  const approvals = f.authorities.slice(0, quorum).map(authority => approvePolicy(update, authority));
  return { update, approvals };
}

test('dashboard reports sanitized live state and executes the authenticated real three-node workflow', async t => {
  const f = await fixture(t);
  const status = await requestJson(`${f.base}/api/status`);
  assert.equal(status.status, 200); assert.equal(status.body.nodes.length, 3); assert.ok(status.body.nodes.every(node => node.mode === 'trusted' && node.audit.valid));
  assert.equal(JSON.stringify(status.body).includes(serviceToken), false); assert.equal(JSON.stringify(status.body).includes('privateKey'), false);
  const page = await requestText(f.base);
  assert.equal(page.status, 200);
  assert.equal(page.body.includes(adminToken), false);
  assert.equal(page.body.includes(serviceToken), false);
  assert.equal(page.body.includes('MODEL_API_KEY'), false);
  assert.equal(page.body.includes('api.meta.ai'), false);

  const deniedPolicy = await requestJson(`${f.base}/api/policy`, { method: 'POST', body: { payload: { enforcement: 'observe-only' } } });
  const deniedDemo = await requestJson(`${f.base}/api/demo`, { method: 'POST', body: {} });
  const forgedRole = await requestJson(`${f.base}/api/demo`, { method: 'POST', headers: { 'x-dashboard-admin-token': 'wrong', 'x-dashboard-role': 'admin' }, body: {} });
  const operatorDemo = await requestJson(`${f.base}/api/demo`, { method: 'POST', headers: { 'x-dashboard-operator-token': operatorToken }, body: {} });
  assert.equal(deniedPolicy.status, 401); assert.equal(deniedDemo.status, 401); assert.equal(forgedRole.status, 401); assert.equal(operatorDemo.status, 403);

  const workflow = await requestJson(`${f.base}/api/demo`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: {} });
  assert.equal(workflow.status, 200); assert.deepEqual(Object.keys(workflow.body.workflow), ['tamper', 'snapshot', 'detection', 'recovery', 'verification']);
  assert.ok(Object.values(workflow.body.workflow).flat().every(result => result.ok));
  assert.ok(workflow.body.nodes.every(node => node.mode === 'trusted' && node.audit.valid));
  const audit = await requestJson(`${f.base}/api/audit?download=1`);
  assert.equal(audit.status, 200); assert.match(audit.headers['content-disposition'], /attachment/); assert.ok(audit.body.nodes.every(report => report.verification.valid));
  assert.equal(JSON.stringify(audit.body).includes('source'), false, 'filesystem source paths are removed from evidence');
  assert.equal(JSON.stringify(audit.body).includes('privateKey'), false);
});

test('policy submission rejects missing and invalid administrator tokens and accepts the configured token', async t => {
  const f = await fixture(t);
  const payload = { payload: { enforcement: 'observe-only', changeWindow: 'operator-requested' } };
  const missing = await requestJson(`${f.base}/api/policy`, { method: 'POST', body: payload });
  const invalid = await requestJson(`${f.base}/api/policy`, { method: 'POST', headers: { 'x-dashboard-admin-token': 'not-the-configured-token' }, body: payload });
  const signedPolicy = await approvedPolicy(f);
  const unsigned = await requestJson(`${f.base}/api/policy`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: { update: signedPolicy.update, approvals: [] } });
  const valid = await requestJson(`${f.base}/api/policy`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: signedPolicy });

  assert.equal(missing.status, 401);
  assert.equal(invalid.status, 401);
  assert.equal(unsigned.status, 403);
  assert.equal(unsigned.body.error, 'policy-needs-two-valid-distinct-approvals');
  assert.equal(valid.status, 200);
  assert.deepEqual(valid.body.approvals, ['authority-1', 'authority-2']);
  assert.ok(valid.body.results.every(result => result.ok));
});

test('incident analysis is admin-only, replay-protected, and separately rate limited', async t => {
  let analyses = 0;
  const f = await fixture(t, {
    incidentRateLimiter: createRateLimiter({ perClientLimit: 1, globalLimit: 1 }),
    incidentAnalyst: { analyze: async ({ statuses, reports }) => {
      analyses++;
      assert.equal(statuses.length, 3);
      assert.equal(reports.length, 3);
      return { analysisStatus: 'fallback', providerStatus: 'not-configured', analysis: { incidentSummary: { statement: 'deterministic' } } };
    } }
  });
  const missing = await requestJson(`${f.base}/api/incident-analysis`, { method: 'POST', body: {} });
  const invalid = await requestJson(`${f.base}/api/incident-analysis`, { method: 'POST', headers: { 'x-dashboard-admin-token': 'invalid' }, body: {} });
  const operator = await requestJson(`${f.base}/api/incident-analysis`, { method: 'POST', headers: { 'x-dashboard-operator-token': operatorToken }, body: {} });
  assert.equal(missing.status, 401);
  assert.equal(invalid.status, 401);
  assert.equal(operator.status, 403);
  assert.equal(analyses, 0);

  const replayHeaders = { 'x-dashboard-admin-token': adminToken, 'x-request-id': 'incident-analysis-replay', 'x-request-timestamp': String(Date.now()) };
  const valid = await requestJson(`${f.base}/api/incident-analysis`, { method: 'POST', headers: replayHeaders, body: {} });
  const replay = await requestJson(`${f.base}/api/incident-analysis`, { method: 'POST', headers: replayHeaders, body: {} });
  const limited = await requestJson(`${f.base}/api/incident-analysis`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: {} });
  assert.equal(valid.status, 200);
  assert.equal(valid.body.analysisStatus, 'fallback');
  assert.deepEqual(valid.body.analysis.incidentSummary, { statement: 'deterministic' });
  assert.equal(replay.status, 409);
  assert.equal(replay.body.error, 'replayed-request');
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error, 'incident-analysis-rate-limited');
  assert.equal(analyses, 1);
  assert.equal(JSON.stringify(valid.body).includes(adminToken), false);
});

test('timeline includes only verified recorded events and exposes unavailable evidence limitations', async t => {
  const f = await fixture(t);
  const response = await requestJson(`${f.base}/api/timeline`);
  assert.equal(response.status, 200);
  assert.equal(response.body.events.length, 3);
  assert.ok(response.body.events.every(event => event.id === event.evidenceRef));
  assert.deepEqual(new Set(response.body.events.map(event => event.node)), new Set(['node-a', 'node-b', 'node-c']));
  assert.ok(response.body.events.every(event => event.category === 'snapshot'));
  assert.ok(response.body.limitations.some(item => item.includes('rejections are counters')));
});

test('human-approved incident actions are admin-only and recovery verifies the node after restore', async t => {
  const f = await fixture(t);
  const denied = await requestJson(`${f.base}/api/incident-response`, { method: 'POST', body: { node: 'node-a', action: 'scan' } });
  const operator = await requestJson(`${f.base}/api/incident-response`, { method: 'POST', headers: { 'x-dashboard-operator-token': operatorToken }, body: { node: 'node-a', action: 'recover' } });
  const prematureRecovery = await requestJson(`${f.base}/api/incident-response`, {
    method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: { node: 'node-a', action: 'recover' }
  });
  assert.equal(denied.status, 401);
  assert.equal(operator.status, 403);
  assert.equal(prematureRecovery.status, 409);
  assert.equal(prematureRecovery.body.error, 'node-not-quarantined');

  f.nodes[0].node.simulateTamper();
  const scan = await requestJson(`${f.base}/api/incident-response`, {
    method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: { node: 'node-a', action: 'scan' }
  });
  assert.equal(scan.status, 200);
  assert.equal(scan.body.operationStatus, 'quarantined');
  assert.equal(f.nodes[0].node.status().mode, 'quarantined');

  const recover = await requestJson(`${f.base}/api/incident-response`, {
    method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: { node: 'node-a', action: 'recover' }
  });
  assert.equal(recover.status, 200);
  assert.equal(recover.body.operationStatus, 'verified');
  assert.equal(recover.body.restored, true);
  assert.equal(recover.body.postRecoveryVerified, true);
  assert.equal(f.nodes[0].node.status().mode, 'trusted');

  const audit = await requestJson(`${f.base}/api/audit`);
  const eventTypes = audit.body.nodes[0].events.map(event => event.type);
  assert.ok(eventTypes.includes('tamper-detected'));
  assert.ok(eventTypes.includes('rollback-verified'));
  assert.ok(eventTypes.includes('integrity-ok'));
});

test('dashboard mutations require replay headers and serialize concurrent policy sequences', async t => {
  const f = await fixture(t);
  const signedPolicy = await approvedPolicy(f);
  const missingReplay = await requestJson(`${f.base}/api/policy`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: signedPolicy, replayProtection: false });
  assert.equal(missingReplay.status, 400);
  assert.equal(missingReplay.body.error, 'replay-protection-required');

  const requests = [1, 2].map(() => requestJson(`${f.base}/api/policy`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: signedPolicy }));
  const results = await Promise.all(requests);
  assert.deepEqual(results.map(result => result.status).sort(), [200, 409]);
  assert.ok(f.nodes.every(node => node.node.status().lastPolicySequence === 1));

  const nextSignedPolicy = await approvedPolicy(f);
  const replayHeaders = { 'x-dashboard-admin-token': adminToken, 'x-request-id': 'dashboard-replay-check', 'x-request-timestamp': String(Date.now()) };
  const first = await requestJson(`${f.base}/api/policy`, { method: 'POST', headers: replayHeaders, body: nextSignedPolicy });
  const replay = await requestJson(`${f.base}/api/policy`, { method: 'POST', headers: replayHeaders, body: nextSignedPolicy });
  assert.equal(first.status, 200);
  assert.equal(replay.status, 409);
  assert.equal(replay.body.error, 'replayed-request');
});

test('dashboard policy quorum matches the node quorum setting', async t => {
  const f = await fixture(t, { quorum: 3 });
  const signedPolicy = await approvedPolicy(f, 3);
  const result = await requestJson(`${f.base}/api/policy`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: signedPolicy });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body.approvals, ['authority-1', 'authority-2', 'authority-3']);
});

test('dashboard rejects empty node configuration', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-dashboard-empty-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  createAuthorities(path.join(root, 'authorities'));
  assert.throws(() => startDashboard({ port: 0, authorityDirectory: path.join(root, 'authorities'), nodeUrls: [], serviceToken, adminToken, operatorToken }), /at least one node URL is required/);
});

test('empty optional operator token disables operator authentication without breaking admin auth', async t => {
  const f = await fixture(t, { nodeUrls: ['http://127.0.0.1:1'], configuredOperatorToken: '' });
  const adminRequest = await requestJson(`${f.base}/api/policy`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: await approvedPolicy(f) });
  const operatorRequest = await requestJson(`${f.base}/api/policy`, { method: 'POST', headers: { 'x-dashboard-operator-token': operatorToken }, body: { payload: { enforcement: 'observe-only' } } });
  assert.equal(adminRequest.status, 503);
  assert.equal(operatorRequest.status, 401);
});

test('dashboard returns safe unavailable-node results, enforces request limits, and rate limits callers', async t => {
  const f = await fixture(t, { nodeUrls: ['http://127.0.0.1:1'], rateLimiter: createRateLimiter({ perClientLimit: 3, globalLimit: 3 }) });
  const status = await requestJson(`${f.base}/api/status`);
  assert.deepEqual(status.body.nodes, [{ name: 'node-a', mode: 'offline', error: 'unavailable' }]);
  const failedPolicy = await requestJson(`${f.base}/api/policy`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: await approvedPolicy(f) });
  assert.equal(failedPolicy.status, 503); assert.deepEqual(failedPolicy.body.results, [{ node: 'node-a', ok: false, outcome: 'unavailable' }]);

  const f2 = await fixture(t, { nodeUrls: ['http://127.0.0.1:1'], rateLimiter: createRateLimiter({ perClientLimit: 100, globalLimit: 100 }) });
  const oversized = await requestJson(`${f2.base}/api/demo`, { method: 'POST', headers: { 'x-dashboard-admin-token': adminToken }, body: 'x'.repeat(9000) });
  assert.equal(oversized.status, 413); assert.equal(oversized.body.error, 'request-too-large');

  const f3 = await fixture(t, { nodeUrls: ['http://127.0.0.1:1'], rateLimiter: createRateLimiter({ perClientLimit: 2, globalLimit: 2 }) });
  assert.equal((await requestJson(`${f3.base}/api/status`)).status, 200); assert.equal((await requestJson(`${f3.base}/api/status`)).status, 200); const limited = await requestJson(`${f3.base}/api/status`); assert.equal(limited.status, 429); assert.equal(limited.body.error, 'rate-limited');
});
