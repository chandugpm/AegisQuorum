const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const {
  SecurityNode,
  createAuthorities,
  authorityTrust,
  sha256,
  writeJsonAtomic
} = require('../src/core');
const { startNode } = require('../src/node-service');
const { startDashboard } = require('../src/dashboard');
const { buildRecoveryCertificate, verifyRecoveryCertificate, CERTIFICATE_FORMAT } = require('../src/recovery-certificate');

const adminToken = 'a'.repeat(32);
const serviceToken = 'b'.repeat(32);
let requestSequence = 0;

// One complete tamper -> quarantine -> restore -> post-recovery cycle.
function recoveryFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-cert-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities'));
  const node = new SecurityNode({ directory: path.join(root, 'node-a'), name: 'node-a', trustedAuthorities: authorityTrust(authorities) });
  const snapshotId = node.status().trustedSnapshot;
  const snapshotBytes = fs.readFileSync(path.join(node.paths.snapshots, `${snapshotId}.json`));
  node.simulateTamper();
  node.scanIntegrity();
  node.deceptionProbe({ input: 'help' });
  assert.equal(node.rollback().restored, true);
  node.appendAudit('integrity-ok', { digest: node.digestProtected() });
  return { root, node, report: node.auditReport(), snapshotBytes, trustedPublicKey: node.identity.publicKey };
}

test('certificate builder records the full recovery evidence chain without overclaiming', t => {
  const f = recoveryFixture(t);
  const certificate = buildRecoveryCertificate(f.report, { aiProvenance: { at: new Date().toISOString(), providerMode: 'Deterministic Fallback', modelsInvoked: [], referencesValidated: true, verifiedEventIds: ['node-a:0'] } });
  assert.equal(certificate.format, CERTIFICATE_FORMAT);
  assert.equal(certificate.node, 'node-a');
  assert.equal(certificate.claims.tamperEvent.eventId.startsWith('node-a:'), true);
  assert.match(certificate.claims.tamperEvent.actualDigest, /^[a-f0-9]{64}$/);
  assert.equal(certificate.claims.threatFingerprint.digest.length, 64);
  assert.equal(certificate.claims.restoreEvent.eventId.startsWith('node-a:'), true);
  assert.equal(certificate.claims.postRecoveryEvent.eventId.startsWith('node-a:'), true);
  assert.equal(certificate.claims.snapshot.artifactDigest.length, 64);
  assert.equal(certificate.claims.recoverySucceeded, true);
  assert.ok(certificate.claims.evidenceRefs.length >= 5);
  assert.equal(certificate.aiProvenance.boundary.includes('never authorized'), true);
  // Issuance never claims independent proof: anchors are required for that.
  assert.equal(certificate.verification.completeRecoveryProof, 'not-verified');
  assert.equal(certificate.verification.auditOnlyProof, 'not-verified');
  assert.equal(certificate.verification.externalNodeIdentity, 'not-verified-no-independent-trust-record');
  assert.equal(certificate.verification.snapshotArtifact, 'not-verified-artifact-not-supplied');
  assert.equal(certificate.verification.auditChain, 'verified-self-asserted');
  assert.match(certificate.certificateDigest, /^[a-f0-9]{64}$/);
  // Portable evidence must stay sanitized.
  const raw = JSON.stringify(certificate);
  assert.equal(raw.includes('privateKey'), false);
  assert.equal(raw.includes(f.root), false);
});

test('verifier recomputes proof and reserves verified for independent anchors', t => {
  const f = recoveryFixture(t);
  const certificate = buildRecoveryCertificate(f.report);
  // No trust record: chain is self-consistent but never independently verified.
  const selfAsserted = verifyRecoveryCertificate(certificate);
  assert.equal(selfAsserted.consistent, true);
  assert.equal(selfAsserted.verification.auditChain, 'verified-self-asserted');
  assert.equal(selfAsserted.verification.postRecoveryIntegrity, 'verified-clean');
  assert.equal(selfAsserted.verification.recoveryOperation, 'succeeded');
  assert.equal(selfAsserted.verification.auditOnlyProof, 'not-verified');
  assert.equal(selfAsserted.verification.completeRecoveryProof, 'not-verified');

  const trusted = verifyRecoveryCertificate(certificate, { trustedPublicKey: f.trustedPublicKey });
  assert.equal(trusted.verification.auditChain, 'verified');
  assert.equal(trusted.verification.externalNodeIdentity, 'trusted');
  assert.equal(trusted.verification.auditOnlyProof, 'verified');
  assert.equal(trusted.verification.snapshotArtifact, 'not-verified-artifact-not-supplied');
  assert.equal(trusted.verification.completeRecoveryProof, 'not-verified');

  const full = verifyRecoveryCertificate(certificate, { trustedPublicKey: f.trustedPublicKey, snapshotBytes: f.snapshotBytes });
  assert.equal(full.verification.externalNodeIdentity, 'trusted');
  assert.equal(full.verification.snapshotArtifact, 'verified');
  assert.equal(full.verification.completeRecoveryProof, 'verified');
});

test('verifier fails closed on tampered embedded evidence and on overclaiming certificates', t => {
  const f = recoveryFixture(t);
  const certificate = buildRecoveryCertificate(f.report);
  const tampered = JSON.parse(JSON.stringify(certificate));
  tampered.evidence.report.proof.records[0].hash = '0'.repeat(64);
  // Keep the certificate digest consistent so only the embedded evidence is wrong.
  const { certificateDigest, ...unsigned } = tampered;
  tampered.certificateDigest = sha256(require('../src/core').stable(unsigned));
  const result = verifyRecoveryCertificate(tampered, { trustedPublicKey: f.trustedPublicKey, snapshotBytes: f.snapshotBytes });
  assert.equal(result.verification.auditChain, 'failed');
  assert.equal(result.verification.completeRecoveryProof, 'not-verified');

  const overclaimed = buildRecoveryCertificate(f.report);
  overclaimed.verification = { ...overclaimed.verification, completeRecoveryProof: 'verified' };
  const { certificateDigest: ignored, ...unsignedOver } = overclaimed;
  overclaimed.certificateDigest = sha256(require('../src/core').stable(unsignedOver));
  // Without independent material the claim cannot be confirmed: overclaim.
  const checked = verifyRecoveryCertificate(overclaimed);
  assert.equal(checked.consistent, false);
  assert.equal(checked.verification.completeRecoveryProof, 'not-verified');
  assert.equal(checked.verification.overclaim, 'certificate-claims-a-proof-level-the-evidence-does-not-support');

  const wrongKey = verifyRecoveryCertificate(certificate, { trustedPublicKey: createAuthorities(path.join(f.root, 'other'))[0].publicKey, snapshotBytes: f.snapshotBytes });
  assert.equal(wrongKey.verification.externalNodeIdentity.startsWith('not-verified'), true);
  assert.equal(wrongKey.verification.completeRecoveryProof, 'not-verified');
});

test('verify-recovery CLI verifies certificate files in audit-only and full modes', t => {
  const f = recoveryFixture(t);
  const certificate = buildRecoveryCertificate(f.report);
  const certificateFile = path.join(f.root, 'recovery-certificate.json');
  const keyFile = path.join(f.root, 'trusted-node-a.json');
  writeJsonAtomic(certificateFile, certificate);
  writeJsonAtomic(keyFile, {
    format: 'danms-node-trust-v1', node: 'node-a', algorithm: 'Ed25519',
    fingerprint: sha256(f.trustedPublicKey), publicKey: f.trustedPublicKey
  });
  const cli = path.join(__dirname, '..', 'src', 'verify-recovery.js');
  const auditOnly = spawnSync(process.execPath, [cli, '--certificate', certificateFile, '--trusted-key', keyFile], { encoding: 'utf8' });
  assert.equal(auditOnly.status, 0, auditOnly.stderr);
  assert.equal(JSON.parse(auditOnly.stdout).certificateVerification.auditOnlyProof, 'verified');
  const full = spawnSync(process.execPath, [cli, '--certificate', certificateFile, '--trusted-key', keyFile, '--snapshot', path.join(f.node.paths.snapshots, `${f.node.status().trustedSnapshot}.json`)], { encoding: 'utf8' });
  assert.equal(full.status, 0, full.stderr);
  assert.equal(JSON.parse(full.stdout).certificateVerification.completeRecoveryProof, 'verified');
  // The existing audit-export mode keeps working unchanged.
  const exportFile = path.join(f.root, 'audit-evidence.json');
  writeJsonAtomic(exportFile, { nodes: [f.report] });
  const legacy = spawnSync(process.execPath, [cli, exportFile, '--node', 'node-a', '--trusted-key', keyFile], { encoding: 'utf8' });
  assert.equal(legacy.status, 0, legacy.stderr);
});

// --- dashboard route ---

function requestJson(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(url); const raw = body === undefined ? undefined : JSON.stringify(body);
    const replayHeaders = method === 'POST' ? { 'x-request-id': `certificate-test-${++requestSequence}`, 'x-request-timestamp': String(Date.now()) } : {};
    const request = http.request({ hostname: target.hostname, port: target.port, path: `${target.pathname}${target.search}`, method, headers: { ...replayHeaders, ...headers, ...(raw === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) }) } }, response => { let data = ''; response.on('data', chunk => data += chunk); response.on('end', () => { try { resolve({ status: response.statusCode, body: JSON.parse(data) }); } catch { reject(new Error('invalid-json-response')); } }); });
    request.on('error', reject); if (raw !== undefined) request.write(raw); request.end();
  });
}
async function waitFor(server) { if (!server.listening) await once(server, 'listening'); }
async function close(server) { if (server.listening) await new Promise(resolve => server.close(resolve)); }

test('GET /api/recovery/certificate issues a sanitized portable certificate after a real recovery', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-cert-route-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities'));
  const trust = path.join(root, 'trust.json'); writeJsonAtomic(trust, authorityTrust(authorities));
  const nodes = ['node-a', 'node-b', 'node-c'].map(name => startNode({ directory: path.join(root, name), name, authorityFile: trust, port: 0, serviceToken }));
  await Promise.all(nodes.map(node => waitFor(node.server))); t.after(async () => { await Promise.all(nodes.map(node => close(node.server))); });
  const urls = nodes.map(node => `http://127.0.0.1:${node.server.address().port}`);
  const dashboard = startDashboard({ port: 0, authorityDirectory: path.join(root, 'authorities'), authorityTrustFile: trust, nodeUrls: urls, serviceToken, adminToken });
  await waitFor(dashboard); t.after(() => close(dashboard));
  const base = `http://127.0.0.1:${dashboard.address().port}`;
  const admin = { 'x-dashboard-admin-token': adminToken };
  const post = (route, body = {}) => requestJson(`${base}${route}`, { method: 'POST', headers: admin, body });

  assert.equal((await post('/api/incident-response', { node: 'node-a', action: 'tamper' })).status, 200);
  assert.equal((await post('/api/incident-response', { node: 'node-a', action: 'scan' })).body.quarantined, true);
  const recover = await post('/api/incident-response', { node: 'node-a', action: 'recover' });
  assert.equal(recover.body.operationStatus, 'verified');

  const response = await requestJson(`${base}/api/recovery/certificate?node=node-a`);
  assert.equal(response.status, 200);
  assert.equal(response.body.format, CERTIFICATE_FORMAT);
  assert.equal(response.body.claims.recoverySucceeded, true);
  assert.equal(response.body.verification.auditChain, 'verified-self-asserted');
  assert.equal(response.body.verification.auditOnlyProof, 'not-verified');
  assert.equal(response.body.verification.completeRecoveryProof, 'not-verified');
  const raw = JSON.stringify(response.body);
  assert.equal(raw.includes('privateKey'), false);
  assert.equal(raw.includes('source'), false);
  const missing = await requestJson(`${base}/api/recovery/certificate?node=node-z`);
  assert.equal(missing.status, 404);
  const wrongMethod = await requestJson(`${base}/api/recovery/certificate?node=node-a`, { method: 'POST', headers: admin, body: {} });
  assert.equal(wrongMethod.status, 405);
});

test('GET /api/recovery/verify returns trust-anchored full proof when provisioned, and degrades honestly', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-recovery-verify-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities'));
  const trust = path.join(root, 'trust.json'); writeJsonAtomic(trust, authorityTrust(authorities));
  const nodes = ['node-a', 'node-b', 'node-c'].map(name => startNode({ directory: path.join(root, name), name, authorityFile: trust, port: 0, serviceToken }));
  await Promise.all(nodes.map(node => waitFor(node.server))); t.after(async () => { await Promise.all(nodes.map(node => close(node.server))); });
  const urls = nodes.map(node => `http://127.0.0.1:${node.server.address().port}`);
  const dashboard = startDashboard({ port: 0, authorityDirectory: path.join(root, 'authorities'), authorityTrustFile: trust, nodeUrls: urls, serviceToken, adminToken });
  await waitFor(dashboard); t.after(() => close(dashboard));
  const base = `http://127.0.0.1:${dashboard.address().port}`;
  const admin = { 'x-dashboard-admin-token': adminToken };
  const post = (route, body = {}) => requestJson(`${base}${route}`, { method: 'POST', headers: admin, body });

  assert.equal((await post('/api/incident-response', { node: 'node-a', action: 'tamper' })).status, 200);
  assert.equal((await post('/api/incident-response', { node: 'node-a', action: 'scan' })).body.quarantined, true);
  assert.equal((await post('/api/incident-response', { node: 'node-a', action: 'recover' })).body.operationStatus, 'verified');

  // Without a provisioned trust record the proof degrades honestly.
  const unprovisioned = await requestJson(`${base}/api/recovery/verify?node=node-a`);
  assert.equal(unprovisioned.status, 200);
  assert.equal(unprovisioned.body.proofInputs.trustRecord, 'not-provisioned');
  assert.equal(unprovisioned.body.verification.externalNodeIdentity, 'not-verified-trust-record-not-provisioned');
  assert.equal(unprovisioned.body.verification.completeRecoveryProof, 'not-verified');

  // Provision the independent danms-node-trust-v1 record (launch-local layout).
  const publicKey = nodes[0].node.identity.publicKey;
  const pem = `${publicKey.trim().replace(/\r\n/g, '\n')}\n`;
  fs.mkdirSync(path.join(root, 'node-trust'), { recursive: true });
  writeJsonAtomic(path.join(root, 'node-trust', 'node-a-trust.json'), {
    format: 'danms-node-trust-v1', node: 'node-a', algorithm: 'Ed25519',
    fingerprint: sha256(pem), publicKey: pem
  });

  const response = await requestJson(`${base}/api/recovery/verify?node=node-a`);
  assert.equal(response.status, 200);
  assert.equal(response.body.node, 'node-a');
  assert.equal(response.body.consistent, true);
  assert.equal(response.body.proofInputs.trustRecord, 'provisioned-danms-node-trust-v1');
  assert.equal(response.body.verification.externalNodeIdentity, 'trusted');
  assert.equal(response.body.verification.auditChain, 'verified');
  assert.equal(response.body.verification.snapshotArtifact, 'verified');
  assert.equal(response.body.verification.recoveryOperation, 'succeeded');
  assert.equal(response.body.verification.postRecoveryIntegrity, 'verified-clean');
  assert.equal(response.body.verification.completeRecoveryProof, 'verified');
  const raw = JSON.stringify(response.body);
  assert.equal(raw.includes('privateKey'), false);
  const missing = await requestJson(`${base}/api/recovery/verify?node=node-z`);
  assert.equal(missing.status, 404);

  // Quorum consistency: the proposal endpoint reports the two REAL offline
  // authority approvals (validated by validatePolicyApprovals, never applied)
  // with distinct authority IDs and signature fingerprints.
  const proposal = await requestJson(`${base}/api/policy/proposal`);
  assert.equal(proposal.status, 200);
  assert.equal(proposal.body.demoApprovals.verified, true);
  assert.deepEqual(proposal.body.demoApprovals.authorities, ['authority-1', 'authority-2']);
  assert.equal(proposal.body.demoApprovals.applied, false);
  assert.equal(proposal.body.demoApprovals.entries.length, 2);
  assert.match(proposal.body.demoApprovals.entries[0].signatureFingerprint, /^[a-f0-9]{16}$/);
  assert.notEqual(proposal.body.demoApprovals.entries[0].signatureFingerprint, proposal.body.demoApprovals.entries[1].signatureFingerprint);
});

test('recovery routes degrade honestly when a persisted node audit chain is invalid', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-degraded-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities'));
  const trust = path.join(root, 'trust.json'); writeJsonAtomic(trust, authorityTrust(authorities));
  let node = startNode({ directory: path.join(root, 'node-a'), name: 'node-a', authorityFile: trust, port: 0, serviceToken });
  await waitFor(node.server); await close(node.server);
  // Corrupt one persisted hash link so the chain cannot verify on next boot.
  const auditFile = path.join(root, 'node-a', 'audit.json');
  const text = fs.readFileSync(auditFile, 'utf8');
  const match = text.match(/[a-f0-9]{64}/);
  assert.ok(match, 'expected a persisted hash to corrupt');
  const flipped = match[0].startsWith('0') ? `1${match[0].slice(1)}` : `0${match[0].slice(1)}`;
  fs.writeFileSync(auditFile, text.replace(match[0], flipped));
  node = startNode({ directory: path.join(root, 'node-a'), name: 'node-a', authorityFile: trust, port: 0, serviceToken });
  await waitFor(node.server); t.after(async () => close(node.server));
  const dashboard = startDashboard({ port: 0, authorityDirectory: path.join(root, 'authorities'), authorityTrustFile: trust, nodeUrls: [`http://127.0.0.1:${node.server.address().port}`], serviceToken, adminToken });
  await waitFor(dashboard); t.after(() => close(dashboard));
  const base = `http://127.0.0.1:${dashboard.address().port}`;

  const certificate = await requestJson(`${base}/api/recovery/certificate?node=node-a`);
  assert.equal(certificate.status, 409);
  assert.equal(certificate.body.error, 'node-report-incomplete');

  const verify = await requestJson(`${base}/api/recovery/verify?node=node-a`);
  assert.equal(verify.status, 200);
  assert.equal(verify.body.consistent, false);
  assert.equal(verify.body.verification.auditChain, 'not-verified');
  assert.equal(verify.body.verification.completeRecoveryProof, 'not-verified');
});
