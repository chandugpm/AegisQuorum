const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { SecurityNode, createAuthorities, authorityTrust, makePolicyUpdate, approvePolicy, writeJsonAtomic } = require('../src/core');
const { ReplayCache, requestSecurity, createMetrics } = require('../src/http-utils');

test('replay cache accepts unique requests and rejects stale or duplicate IDs', () => {
  const cache = new ReplayCache({ ttlMs: 1000 });
  assert.equal(cache.accept('request-123', 1000), true);
  assert.equal(cache.accept('request-123', 1001), false);
  assert.equal(cache.accept('request-456', 2001), true);
  assert.equal(cache.accept('bad', 2002), false);
});

test('request security validates timestamp and replay identity', () => {
  const cache = new ReplayCache();
  const originalNow = Date.now;
  Date.now = () => 1000000;
  try {
    assert.deepEqual(requestSecurity({ headers: { 'x-request-id': 'request-123', 'x-request-timestamp': '1000000' } }, cache), { checked: true, id: 'request-123', timestamp: 1000000 });
    assert.throws(() => requestSecurity({ headers: { 'x-request-id': 'request-123', 'x-request-timestamp': '1000000' } }, cache), /replayed-request/);
    assert.equal(requestSecurity({ headers: { 'x-request-id': 'request-boundary', 'x-request-timestamp': '970000' } }, cache).checked, true);
    assert.throws(() => requestSecurity({ headers: { 'x-request-id': 'request-too-old', 'x-request-timestamp': '969999' } }, cache), /stale-request/);
    assert.throws(() => requestSecurity({ headers: { 'x-request-id': 'request-config-cannot-widen', 'x-request-timestamp': '969999' } }, cache, { maxAgeMs: 300000 }), /stale-request/);
    assert.throws(() => requestSecurity({ headers: { 'x-request-id': 'request-456', 'x-request-timestamp': '1' } }, cache), /stale-request/);
    assert.throws(() => requestSecurity({ headers: {} }, cache, { required: true }), /replay-protection-required/);
  } finally { Date.now = originalNow; }
});

test('quorum is configurable and quarantined nodes cannot approve sensitive policies', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-advanced-')); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities'));
  const node = new SecurityNode({ directory: path.join(root, 'node'), name: 'node-a', trustedAuthorities: authorityTrust(authorities), quorum: 3 });
  assert.throws(() => new SecurityNode({ directory: path.join(root, 'other'), name: 'node-b', trustedAuthorities: authorityTrust(authorities), quorum: 4 }), /quorum is invalid/);
  node.state.quarantined = true; node.state.mode = 'quarantined';
  const update = makePolicyUpdate(1, { enforcement: 'observe-only' });
  assert.throws(() => node.applyPolicy(update, [approvePolicy(update, authorities[0]), approvePolicy(update, authorities[1])]), /not-eligible/);
  node.state.quarantined = false; node.state.mode = 'trusted';
  assert.throws(() => node.applyPolicy(update, [approvePolicy(update, authorities[0]), approvePolicy(update, authorities[1])]), /needs-3/);
  assert.equal(node.applyPolicy(update, authorities.map(authority => approvePolicy(update, authority))).accepted, true);
});

test('metrics remain numeric and contain no request payloads', () => {
  const metrics = createMetrics(); metrics.increment('auth_failures_total'); metrics.increment('auth_failures_total', 2);
  assert.deepEqual(metrics.snapshot(), { auth_failures_total: 3 });
  assert.equal(JSON.stringify(metrics.snapshot()).includes('secret'), false);
});
