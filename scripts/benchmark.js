#!/usr/bin/env node
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createAuthorities, authorityTrust, makePolicyUpdate, approvePolicy, writeJsonAtomic, verify, verifySnapshotArtifact } = require('../src/core');
const { startNode } = require('../src/node-service');
const { startDashboard } = require('../src/dashboard');
const http = require('node:http');
const { once } = require('node:events');

// Performance benchmark. Uses temporary directories and test keys only; it
// never touches .runtime, real authority keys, or the running nodes' data.
// Writes benchmark-results.json (no secrets) and prints a markdown table.

async function waitFor(server) { if (!server.listening) await once(server, 'listening'); }
async function close(server) { if (server?.listening) await new Promise(resolve => server.close(resolve)); }

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

async function runBenchmark({ outputFile = path.join(process.cwd(), 'benchmark-results.json'), logger = console } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-benchmark-'));
  const serviceToken = 'b'.repeat(32);
  const authorityDirectory = path.join(root, 'authorities');
  const trustFile = path.join(root, 'authority-trust.json');
  const authorities = createAuthorities(authorityDirectory);
  writeJsonAtomic(trustFile, authorityTrust(authorities));
  const node = startNode({ directory: path.join(root, 'node-a'), name: 'node-a', authorityFile: trustFile, port: 0, serviceToken });
  try {
    await waitFor(node.server);
    const target = node.node;

    // MTTD: tamper -> detection.
    const mttdSamples = [];
    for (let i = 0; i < 5; i++) {
      target.simulateTamper();
      const start = Date.now();
      target.scanIntegrity();
      mttdSamples.push(Date.now() - start);
      target.rollback();
    }

    // MTTR: quarantined -> verified recovery.
    const mttrSamples = [];
    for (let i = 0; i < 5; i++) {
      target.simulateTamper();
      target.scanIntegrity();
      const start = Date.now();
      target.rollback();
      mttrSamples.push(Date.now() - start);
    }

    // Approval verification time.
    const approvalSamples = [];
    for (let sequence = 1; sequence <= 5; sequence++) {
      const update = makePolicyUpdate(sequence, { enforcement: 'observe-only' });
      const approvals = [approvePolicy(update, authorities[0]), approvePolicy(update, authorities[1])];
      const start = Date.now();
      target.applyPolicy(update, approvals);
      approvalSamples.push(Date.now() - start);
    }

    // Audit-chain verification for 100 and 1000 events.
    const auditVerification = {};
    for (const count of [100, 1000]) {
      while (target.audit.length < count) target.appendAudit('integrity-ok', { digest: 'a'.repeat(64) });
      const start = Date.now();
      target.verifyAudit();
      auditVerification[`events${count}`] = Date.now() - start;
    }

    // False positives over 50+ clean scans.
    let falsePositives = 0;
    const cleanScans = 50;
    for (let i = 0; i < cleanScans; i++) {
      const result = target.scanIntegrity();
      if (result.clean !== true) falsePositives++;
    }

    // Synthetic security scenario suite: expected-vs-actual outcomes on the
    // same isolated stack. Scenario durations are execution records, not
    // performance claims; MTTD/MTTR above remain the only timing metrics.
    const adminToken = 'a'.repeat(32);
    const dashboard = startDashboard({ port: 0, authorityDirectory, authorityTrustFile: trustFile, nodeUrls: [`http://127.0.0.1:${node.server.address().port}`], serviceToken, adminToken });
    await waitFor(dashboard);
    let requestSequence = 0;
    const requestJson = (route, { method = 'GET', headers = {}, body } = {}) => new Promise((resolve, reject) => {
      const raw = body === undefined ? undefined : JSON.stringify(body);
      const replay = method === 'POST' ? { 'x-request-id': `benchmark-${++requestSequence}`, 'x-request-timestamp': String(Date.now()) } : {};
      const request = http.request({ hostname: '127.0.0.1', port: dashboard.address().port, path: route, method, headers: { ...replay, ...headers, ...(raw === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) }) } }, response => { let data = ''; response.on('data', chunk => data += chunk); response.on('end', () => { try { resolve({ status: response.statusCode, body: JSON.parse(data) }); } catch { reject(new Error('invalid-json')); } }); });
      request.on('error', reject); if (raw !== undefined) request.write(raw); request.end();
    });
    const post = (route, body, headers = { 'x-dashboard-admin-token': adminToken }) => requestJson(route, { method: 'POST', body, headers });
    const scenarios = [];
    const record = (id, expected, actual, startedAt, evidenceRef) => scenarios.push({ id, expected, actual, pass: expected === actual, durationMs: Date.now() - startedAt, evidenceRef: evidenceRef || null });
    const lastEventRef = () => { const event = target.audit.at(-1); return event ? `node-a:${event.index}` : null; };

    // 9. Recovery on a healthy node must be rejected before mutating anything.
    let started = Date.now();
    let response = await post('/api/incident-response', { node: 'node-a', action: 'recover' });
    record('recovery-without-incident', 'recovery-rejected', response.status === 409 && response.body.error === 'node-not-quarantined' ? 'recovery-rejected' : `status-${response.status}`, started, response.body.error);

    // 1. Normal operation: clean integrity scan.
    started = Date.now();
    record('normal-operation', 'clean', target.scanIntegrity().clean === true ? 'clean' : 'not-clean', started, lastEventRef());

    // 2. File tampering is detected and quarantined.
    started = Date.now();
    target.simulateTamper();
    record('file-tampering', 'quarantined', target.scanIntegrity().quarantined === true ? 'quarantined' : 'not-quarantined', started, lastEventRef());

    // Recover through the dashboard, then 8. duplicate recovery is an
    // idempotent rejection, never a rate-limit error.
    started = Date.now();
    response = await post('/api/incident-response', { node: 'node-a', action: 'recover' });
    const recovered = response.status === 200 && response.body.operationStatus === 'verified';
    response = await post('/api/incident-response', { node: 'node-a', action: 'recover' });
    record('duplicate-recovery-request', 'idempotent-rejection', recovered && response.status === 409 && response.body.error === 'node-not-quarantined' ? 'idempotent-rejection' : `status-${response.status}`, started, response.body.error || null);

    // 6. Unauthorized policy submission.
    started = Date.now();
    response = await requestJson('/api/policy', { method: 'POST', body: {} });
    record('unauthorized-policy-submission', 'unauthorized', response.status === 401 ? 'unauthorized' : `status-${response.status}`, started, response.body.error);

    // 7. Invalid quorum: a single approval never satisfies 2-of-3.
    started = Date.now();
    let sequence = (target.state.lastPolicySequence || 0) + 1;
    let update = makePolicyUpdate(sequence, { enforcement: 'observe-only' });
    response = await post('/api/policy', { update, approvals: [approvePolicy(update, authorities[0])] });
    record('invalid-quorum', 'quorum-rejected', response.status === 403 ? 'quorum-rejected' : `status-${response.status}`, started, response.body.error);

    // 5. Replayed request: a valid submission once, the same request-id twice.
    started = Date.now();
    const approvals = [approvePolicy(update, authorities[0]), approvePolicy(update, authorities[1])];
    const replayHeaders = { 'x-dashboard-admin-token': adminToken, 'x-request-id': `benchmark-replay-${++requestSequence}`, 'x-request-timestamp': String(Date.now()) };
    response = await requestJson('/api/policy', { method: 'POST', body: { update, approvals }, headers: replayHeaders });
    const applied = response.status === 200;
    const replay = await requestJson('/api/policy', { method: 'POST', body: { update, approvals }, headers: replayHeaders });
    record('replayed-request', 'replay-rejected', applied && replay.status === 409 && replay.body.error === 'replayed-request' ? 'replay-rejected' : `status-${replay.status}`, started, replay.body.error || (applied ? 'node-a:policy-accepted' : null));

    // 4. Invalid Ed25519 signature is never accepted.
    started = Date.now();
    record('invalid-ed25519-signature', 'signature-invalid', verify(target.identity.publicKey, 'payload', Buffer.alloc(64).toString('base64')) === false ? 'signature-invalid' : 'signature-accepted', started, null);

    // 3. Snapshot artifact digest mismatch is rejected.
    started = Date.now();
    const snapshotId = target.status().trustedSnapshot;
    const snapshotBytes = fs.readFileSync(path.join(target.paths.snapshots, `${snapshotId}.json`));
    const artifact = verifySnapshotArtifact(snapshotBytes, { nodeName: 'node-a', snapshotId, expectedArtifactDigest: '0'.repeat(64), trustedPublicKey: target.identity.publicKey });
    record('snapshot-digest-mismatch', 'artifact-rejected', artifact.valid === false ? 'artifact-rejected' : 'artifact-accepted', started, artifact.reason || null);

    // 10. Post-recovery integrity failure: a corrupted trusted snapshot must
    // fail closed into safe mode, and the post-recovery scan must not pass.
    started = Date.now();
    target.simulateTamper();
    target.scanIntegrity();
    fs.writeFileSync(path.join(target.paths.snapshots, `${snapshotId}.json`), Buffer.from('corrupted-artifact'));
    const failedRollback = target.rollback();
    const postScan = target.scanIntegrity();
    record('post-recovery-integrity-failure', 'recovery-failed-safe', failedRollback.restored !== true && postScan.clean !== true ? 'recovery-failed-safe' : 'unexpected', started, lastEventRef());

    await close(dashboard);

    const scenarioPass = scenarios.filter(scenario => scenario.pass).length;

    const results = {
      generatedAt: new Date().toISOString(),
      isolatedDirectory: 'temporary (removed at completion)',
      metrics: {
        mttdMs: median(mttdSamples),
        mttrMs: median(mttrSamples),
        approvalVerificationMs: median(approvalSamples),
        auditChainVerificationMs: auditVerification,
        falsePositivesOverCleanScans: { falsePositives, cleanScans }
      },
      scenarios
    };
    fs.writeFileSync(outputFile, JSON.stringify(results, null, 2));
    logger.log('| Metric | Value |');
    logger.log('| --- | --- |');
    logger.log(`| MTTD (tamper → detect) | ${results.metrics.mttdMs} ms |`);
    logger.log(`| MTTR (quarantine → verified recovery) | ${results.metrics.mttrMs} ms |`);
    logger.log(`| Approval verification (2-of-3) | ${results.metrics.approvalVerificationMs} ms |`);
    logger.log(`| Audit-chain verification (100 events) | ${auditVerification.events100} ms |`);
    logger.log(`| Audit-chain verification (1000 events) | ${auditVerification.events1000} ms |`);
    logger.log(`| False positives over ${cleanScans} clean scans | ${falsePositives} |`);
    logger.log(`| Synthetic scenarios passed | ${scenarioPass}/${scenarios.length} |`);
    for (const scenario of scenarios) logger.log(`| ${scenario.pass ? '✓' : '✗'} ${scenario.id} | expected ${scenario.expected} · actual ${scenario.actual} · ${scenario.durationMs} ms${scenario.evidenceRef ? ` · ${scenario.evidenceRef}` : ''} |`);
    return results;
  } finally {
    await close(node.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
}

if (require.main === module) {
  runBenchmark().catch(error => { console.error(`benchmark failed: ${error.message}`); process.exitCode = 1; });
}

module.exports = { runBenchmark };
