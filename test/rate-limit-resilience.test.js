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

// Regression guard for the reported "rollback failed: rate-limited" defect.
// The dashboard's own control-plane traffic (15s status polling + audit
// refreshes interleaved with the seven-stage demo) must stay inside every
// rate budget — including after peers gain the inoculated-shield budget.
// This test intentionally uses the PRODUCTION DEFAULT limiters (nothing
// injected) and the real forked-node HTTP transport.

const adminToken = 'a'.repeat(32);
const serviceToken = 'b'.repeat(32);
let requestSequence = 0;

function requestJson(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(url); const raw = body === undefined ? undefined : JSON.stringify(body);
    const replayHeaders = method === 'POST' ? { 'x-request-id': `rate-limit-test-${++requestSequence}`, 'x-request-timestamp': String(Date.now()) } : {};
    const request = http.request({ hostname: target.hostname, port: target.port, path: `${target.pathname}${target.search}`, method, headers: { ...replayHeaders, ...headers, ...(raw === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) }) } }, response => { let data = ''; response.on('data', chunk => data += chunk); response.on('end', () => { try { resolve({ status: response.statusCode, headers: response.headers, body: JSON.parse(data) }); } catch { reject(new Error('invalid-json-response')); } }); });
    request.on('error', reject); if (raw !== undefined) request.write(raw); request.end();
  });
}
async function waitFor(server) { if (!server.listening) await once(server, 'listening'); }
async function close(server) { if (server.listening) await new Promise(resolve => server.close(resolve)); }

test('control-plane traffic never trips rate limits during the full seven-stage workflow', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-ratelimit-')); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities')); const trust = path.join(root, 'trust.json'); writeJsonAtomic(trust, authorityTrust(authorities));
  const nodes = ['node-a', 'node-b', 'node-c'].map(name => startNode({ directory: path.join(root, name), name, authorityFile: trust, port: 0, serviceToken }));
  await Promise.all(nodes.map(node => waitFor(node.server))); t.after(async () => { await Promise.all(nodes.map(node => close(node.server))); });
  const urls = nodes.map(node => `http://127.0.0.1:${node.server.address().port}`);
  // No limiter injection: exercises the production default budgets.
  const dashboard = startDashboard({ port: 0, authorityDirectory: path.join(root, 'authorities'), authorityTrustFile: trust, nodeUrls: urls, serviceToken, adminToken });
  await waitFor(dashboard); t.after(() => close(dashboard));
  const base = `http://127.0.0.1:${dashboard.address().port}`;
  const admin = { 'x-dashboard-admin-token': adminToken };
  const post = (route, body = {}) => requestJson(`${base}${route}`, { method: 'POST', headers: admin, body });

  const log = [];
  const track = (label, response) => { log.push(`${label}:${response.status}`); return response; };

  // Background polling identical to the dashboard UI (status + audit refresh),
  // kept running for the whole workflow so node rate budgets see real load.
  let polling = true;
  const poll = (async () => {
    while (polling) {
      const [status, audit, audit360] = await Promise.all([
        requestJson(`${base}/api/status`), requestJson(`${base}/api/audit`), requestJson(`${base}/api/audit/360`)
      ]);
      track('poll-status', status); track('poll-audit', audit); track('poll-360', audit360);
      await new Promise(resolve => setTimeout(resolve, 2200));
    }
  })();

  try {
    const tamper = track('tamper', await post('/api/incident-response', { node: 'node-a', action: 'tamper' }));
    assert.equal(tamper.status, 200); assert.equal(tamper.body.tampered, true);

    const scan = track('scan', await post('/api/incident-response', { node: 'node-a', action: 'scan' }));
    assert.equal(scan.status, 200); assert.equal(scan.body.quarantined, true);

    const deception = track('deception', await post('/api/deception/simulate', { node: 'node-a', input: 'help', durationMs: 25 }));
    assert.equal(deception.status, 200); assert.ok(deception.body.threatFingerprint?.digest);

    const precog = track('pre-cog', await post('/api/pre-cog/analyze', {}));
    assert.equal(precog.status, 200); assert.ok(precog.body.verifiedEventIds.length >= 1, 'pre-cog must find verified tamper evidence');

    // Key regression: peers accept the signed antibody even though the UI's
    // polling kept reading node state the whole time.
    const gossip = track('gossip', await post('/api/gossip/broadcast', { sourceNode: 'node-a' }));
    assert.equal(gossip.status, 200, `gossip deliveries: ${JSON.stringify(gossip.body)}`);
    assert.equal(gossip.body.deliveries.filter(item => item.inoculated).length, 2);

    const synthesis = track('synthesize', await post('/api/policy/synthesize', {}));
    assert.equal(synthesis.status, 200); assert.ok(synthesis.body.sandbox);

    const recover = track('recover', await post('/api/incident-response', { node: 'node-a', action: 'recover' }));
    assert.equal(recover.status, 200); assert.equal(recover.body.operationStatus, 'verified'); assert.equal(recover.body.postRecoveryVerified, true);

    // Duplicate recovery is serialized and idempotent: the second request is
    // honestly rejected because node-a is no longer quarantined — never 429.
    const duplicate = track('recover-duplicate', await post('/api/incident-response', { node: 'node-a', action: 'recover' }));
    assert.equal(duplicate.status, 409); assert.equal(duplicate.body.error, 'node-not-quarantined');

    // Concurrent mutations on the same node are single-flighted, never raced.
    const [concurrentA, concurrentB] = await Promise.all([
      post('/api/incident-response', { node: 'node-a', action: 'tamper' }),
      post('/api/incident-response', { node: 'node-a', action: 'recover' })
    ]);
    track('concurrent-tamper', concurrentA); track('concurrent-recover', concurrentB);
    assert.ok(![concurrentA.status, concurrentB.status].includes(429));
    assert.ok(![concurrentA.status, concurrentB.status].includes(500));
    // Restore the node so the final assertions start from a clean state.
    track('recover-final', await post('/api/incident-response', { node: 'node-a', action: 'recover' }));
  } finally {
    polling = false; await poll;
  }

  const limited = log.filter(entry => entry.endsWith(':429'));
  assert.deepEqual(limited, [], `no request may be rate-limited; log: ${log.join(',')}`);

  const finalStatus = track('final-status', await requestJson(`${base}/api/status`));
  assert.equal(finalStatus.status, 200);
  assert.ok(finalStatus.body.nodes.every(node => node.mode === 'trusted' && node.audit.valid), JSON.stringify(finalStatus.body.nodes.map(node => node.mode)));

  const ledger = track('final-360', await requestJson(`${base}/api/audit/360`));
  assert.equal(ledger.status, 200);
  assert.ok(ledger.body.hashChainLedger.chainVerificationStatus.every(item => item.valid));
  assert.notEqual(ledger.body.complianceSummary.mttdMs, null, 'MTTD must be computed from verified audit evidence');
  assert.notEqual(ledger.body.complianceSummary.mttrMs, null, 'MTTR must be computed from verified audit evidence');
});
