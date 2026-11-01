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

test('tamper scan automatically broadcasts signed antibodies and inoculates loopback peers', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-gossip-integration-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities'));
  const trust = path.join(root, 'trust.json');
  writeJsonAtomic(trust, authorityTrust(authorities));
  const token = 'g'.repeat(32);
  const waitForListen = server => server.listening ? Promise.resolve() : new Promise(resolve => server.once('listening', resolve));
  const peers = ['node-b', 'node-c'].map(name => startNode({
    directory: path.join(root, name), name, authorityFile: trust, port: 0, serviceToken: token
  }));
  t.after(() => peers.forEach(peer => peer.server.close()));
  await Promise.all(peers.map(peer => waitForListen(peer.server)));
  const peerUrls = peers.map(peer => `http://127.0.0.1:${peer.server.address().port}`);
  const source = startNode({
    directory: path.join(root, 'node-a'), name: 'node-a', authorityFile: trust,
    port: 0, serviceToken: token, peerUrls
  });
  t.after(() => source.server.close());
  await waitForListen(source.server);
  const sourceUrl = `http://127.0.0.1:${source.server.address().port}`;
  const security = () => ({ id: `gossip-test-${++requestSequence}`, timestamp: Date.now() });
  const peerRequest = (base, endpoint, payload) => requestJson(`${base}${endpoint}`, 'POST', payload, token, security());

  const tamper = await peerRequest(sourceUrl, '/simulate-tamper', {});
  assert.equal(tamper.status, 200);
  const scan = await peerRequest(sourceUrl, '/scan', {});
  assert.equal(scan.status, 200);
  assert.equal(scan.body.quarantined, true);
  assert.equal(scan.body.gossipDeliveries.length, 2);
  assert.ok(scan.body.gossipDeliveries.every(item => item.inoculated));

  for (let index = 0; index < peers.length; index++) {
    const peer = peers[index];
    assert.equal(peer.node.status().shieldState, 'INOCULATED_SHIELD');
    assert.ok(peer.node.state.blockList.includes(source.node.state.antibodyPacket.vector));
    assert.equal(peer.node.verifyAudit().valid, true);
    const blocked = await peerRequest(peerUrls[index], '/policy', { attackVectorHash: source.node.state.antibodyPacket.vector });
    assert.equal(blocked.status, 403);
    assert.equal(blocked.body.error, 'gossip-vector-blocked');
  }
  assert.ok(source.node.audit.some(record => record.type === 'threat-antibody-broadcast'));
});
