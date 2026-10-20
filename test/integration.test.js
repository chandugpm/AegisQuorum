const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createAuthorities, authorityTrust, writeJsonAtomic, makePolicyUpdate, approvePolicy } = require('../src/core');
const { startNode } = require('../src/node-service');
const { requestJson } = require('../src/dashboard');
let requestSequence = 0;

test('three independent HTTP nodes each verify signed policy and recover after tamper', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-integration-')); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities')); const trust = path.join(root, 'trust.json'); writeJsonAtomic(trust, authorityTrust(authorities)); const token = 's'.repeat(32);
  const services = ['a', 'b', 'c'].map(name => startNode({ directory: path.join(root, name), name, authorityFile: trust, port: 0, serviceToken: token }));
  t.after(() => services.forEach(s => s.server.close())); await Promise.all(services.map(s => new Promise(resolve => s.server.on('listening', resolve))));
  const urls = services.map(s => `http://127.0.0.1:${s.server.address().port}`); const update = makePolicyUpdate(1, { enforcement: 'observe-only' }); const approvals = [approvePolicy(update, authorities[0]), approvePolicy(update, authorities[2])];
  const request = (base, endpoint, payload = {}) => requestJson(`${base}${endpoint}`, 'POST', payload, token, { id: `integration-request-${++requestSequence}`, timestamp: Date.now() });
  assert.equal((await requestJson(`${urls[0]}/scan`, 'POST', {})).status, 401, 'unauthenticated node administration is rejected');
  assert.equal((await requestJson(`${urls[0]}/scan`, 'POST', {}, token)).body.error, 'replay-protection-required');
  const replay = { id: 'integration-replay-request', timestamp: Date.now() };
  assert.equal((await requestJson(`${urls[0]}/scan`, 'POST', {}, token, replay)).status, 200);
  assert.equal((await requestJson(`${urls[0]}/scan`, 'POST', {}, token, replay)).body.error, 'replayed-request');
  for (const url of urls) assert.equal((await request(url, '/policy', { update, approvals })).body.accepted, true);
  const before = await Promise.all(urls.map(url => requestJson(`${url}/status`))); assert.equal(new Set(before.map(x => x.body.nodePublicKeyFingerprint)).size, 3);
  for (const url of urls) await request(url, '/simulate-tamper');
  for (const url of urls) { assert.equal((await request(url, '/scan')).body.quarantined, true); assert.equal((await request(url, '/rollback')).body.restored, true); }
  const after = await Promise.all(urls.map(url => requestJson(`${url}/status`))); assert.ok(after.every(x => x.body.mode === 'trusted' && x.body.audit.valid));
});
