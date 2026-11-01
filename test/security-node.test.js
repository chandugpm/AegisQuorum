const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { SecurityNode, createAuthorities, authorityTrust, makePolicyUpdate, approvePolicy, readJson, writeJsonAtomic, verify, verifyThreatAntibody, stable, calculateEntropy, simulateSIR } = require('../src/core');

function fixture() { const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-')); const authorities = createAuthorities(path.join(root, 'authorities')); const node = new SecurityNode({ directory: path.join(root, 'node'), name: 'test-node', trustedAuthorities: authorityTrust(authorities), clock: () => '2026-10-12T00:00:00.000Z' }); return { root, node, authorities }; }
function policy(sequence = 1) { return makePolicyUpdate(sequence, { enforcement: 'observe-only' }, '2026-10-12T00:00:00.000Z'); }

test('accepts a policy with two distinct valid Ed25519 approvals', t => { const f = fixture(); t.after(() => fs.rmSync(f.root, { recursive: true, force: true })); const update = policy(); const result = f.node.applyPolicy(update, [approvePolicy(update, f.authorities[0]), approvePolicy(update, f.authorities[1])]); assert.equal(result.accepted, true); assert.equal(f.node.status().lastPolicySequence, 1); });
test('accepted policy sequence and decision survive node restart and reject replay', t => { const f = fixture(); t.after(() => fs.rmSync(f.root, { recursive: true, force: true })); const update = policy(); const approvals = [approvePolicy(update, f.authorities[0]), approvePolicy(update, f.authorities[1])]; f.node.applyPolicy(update, approvals); const restarted = new SecurityNode({ directory: f.node.directory, name: 'test-node', trustedAuthorities: f.node.trustedAuthorities }); assert.equal(restarted.status().lastPolicySequence, 1); assert.deepEqual(restarted.state.policy, update); assert.ok(restarted.audit.some(record => record.type === 'policy-accepted' && record.details.sequence === 1)); assert.throws(() => restarted.applyPolicy(update, approvals), /policy-replay-or-invalid-sequence/); });
test('separate authority CLI approvals satisfy node quorum without dashboard-held signer keys', t => {
  const f = fixture(); t.after(() => fs.rmSync(f.root, { recursive: true, force: true }));
  const update = policy(); const proposalFile = path.join(f.root, 'proposal.json'); writeJsonAtomic(proposalFile, { update });
  const cliFile = path.join(__dirname, '..', 'src', 'approve-policy.js');
  const approvals = f.authorities.slice(0, 2).map(authority => {
    const identityFile = path.join(f.root, 'authorities', authority.name, 'identity.json');
    const result = spawnSync(process.execPath, [cliFile, identityFile, proposalFile], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.includes('privateKey'), false);
    return JSON.parse(result.stdout);
  });
  assert.equal(f.node.applyPolicy(update, approvals).accepted, true);
});
test('rejects a one-approval policy and preserves sequence', t => { const f = fixture(); t.after(() => fs.rmSync(f.root, { recursive: true, force: true })); const update = policy(); assert.throws(() => f.node.applyPolicy(update, [approvePolicy(update, f.authorities[0])]), /two-valid/); assert.equal(f.node.status().lastPolicySequence, 0); });
test('rejects duplicate approvals from one authority', t => { const f = fixture(); t.after(() => fs.rmSync(f.root, { recursive: true, force: true })); const update = policy(); const approval = approvePolicy(update, f.authorities[0]); assert.throws(() => f.node.applyPolicy(update, [approval, approval]), /duplicate-approval/); assert.equal(f.node.status().lastPolicySequence, 0); });
test('rejects replay and forged approvals', t => { const f = fixture(); t.after(() => fs.rmSync(f.root, { recursive: true, force: true })); const update = policy(); const approvals = [approvePolicy(update, f.authorities[0]), approvePolicy(update, f.authorities[1])]; f.node.applyPolicy(update, approvals); assert.throws(() => f.node.applyPolicy(update, approvals), /replay/); const next = policy(2); const forged = [{ ...approvePolicy(next, f.authorities[0]), signature: 'not-a-signature' }, approvePolicy(next, f.authorities[1])]; assert.throws(() => f.node.applyPolicy(next, forged), /invalid-approval/); });
test('detects tamper, quarantines, and rolls back only a signed snapshot', t => { const f = fixture(); t.after(() => fs.rmSync(f.root, { recursive: true, force: true })); assert.equal(f.node.scanIntegrity().clean, true); f.node.simulateTamper(); const detected = f.node.scanIntegrity(); assert.equal(detected.quarantined, true); assert.equal(f.node.status().mode, 'quarantined'); const restored = f.node.rollback(); assert.equal(restored.restored, true); assert.equal(f.node.status().mode, 'trusted'); assert.equal(f.node.scanIntegrity().clean, true); });
test('corrupt snapshot failure injection enters safe mode and will not restore', t => { const f = fixture(); t.after(() => fs.rmSync(f.root, { recursive: true, force: true })); const id = f.node.status().trustedSnapshot; const filename = path.join(f.root, 'node', 'snapshots', `${id}.json`); const snapshot = readJson(filename); snapshot.content = Buffer.from('attacker-controlled-data').toString('base64'); writeJsonAtomic(filename, snapshot); f.node.simulateTamper(); const result = f.node.rollback(); assert.equal(result.safeMode, true); assert.equal(f.node.status().mode, 'safe-mode'); });
test('audit record modification is detected by chain and signature verification', t => { const f = fixture(); t.after(() => fs.rmSync(f.root, { recursive: true, force: true })); f.node.scanIntegrity(); assert.equal(f.node.verifyAudit().valid, true); const filename = path.join(f.root, 'node', 'audit.json'); const audit = readJson(filename); audit[0].type = 'attacker-rewrote-history'; writeJsonAtomic(filename, audit); const reloaded = new SecurityNode({ directory: path.join(f.root, 'node'), name: 'test-node', trustedAuthorities: authorityTrust(f.authorities) }); assert.equal(reloaded.verifyAudit().valid, false); });

test('sandbox certificates, honeypot fingerprints, threat antibodies, and inoculation receipts are Ed25519 signed', t => {
  const f = fixture(); t.after(() => fs.rmSync(f.root, { recursive: true, force: true }));
  const candidatePolicy = makePolicyUpdate(1, {
    enforcement: 'quarantine-on-integrity-mismatch', requireSignedPolicy: true, triggerEvents: ['tamper-detected']
  });
  const certificate = f.node.executeDryRunSandbox(candidatePolicy);
  assert.equal(certificate.dryRunPassed, true);
  assert.equal(certificate.replayedEventsCount, 1);
  assert.equal(certificate.falsePositives, 0);
  assert.equal(certificate.safetyScore, 100);
  assert.match(certificate.sandboxDigest, /^[a-f0-9]{64}$/);
  const { signature: certificateSignature, ...unsignedCertificate } = certificate;
  assert.equal(verify(f.node.identity.publicKey, stable(unsignedCertificate), certificateSignature), true);

  f.node.simulateTamper();
  f.node.scanIntegrity();
  const antibody = f.node.threatAntibody();
  assert.equal(verifyThreatAntibody(antibody.packet, antibody.sourcePublicKey), true);
  const probe = f.node.deceptionProbe({ input: 'curl https://edge.invalid', durationMs: 18 });
  assert.equal(probe.decoy, true);
  const fingerprintFile = path.join(f.node.paths.quarantine, 'threat-fingerprint.json');
  const fingerprints = readJson(fingerprintFile, []);
  const { signature: fingerprintSignature, auditIndex, ...fingerprint } = fingerprints.at(-1);
  assert.equal(Number.isSafeInteger(auditIndex), true);
  assert.equal(verify(f.node.identity.publicKey, stable(fingerprint), fingerprintSignature), true);

  const peer = new SecurityNode({ directory: path.join(f.root, 'peer'), name: 'node-b', trustedAuthorities: authorityTrust(f.authorities) });
  const result = peer.inoculate(antibody.packet, antibody.sourcePublicKey);
  const { signature: receiptSignature, publicKey, ...unsignedReceipt } = result.receipt;
  assert.equal(peer.status().shieldState, 'INOCULATED_SHIELD');
  assert.equal(verify(publicKey, stable(unsignedReceipt), receiptSignature), true);
});

test('Shannon entropy classifies encrypted tampering and SIR metrics are signed into the audit fingerprint', t => {
  const f = fixture(); t.after(() => fs.rmSync(f.root, { recursive: true, force: true }));
  const uniformBytes = Buffer.from(Array.from({ length: 2048 }, (_, index) => index % 256));
  assert.equal(calculateEntropy(Buffer.alloc(128)), 0);
  assert.equal(calculateEntropy(uniformBytes), 8);
  const sir = simulateSIR(0.85, 0.4, { population: 3 });
  assert.equal(sir.basicReproductionNumber, 2.125);
  assert.ok(sir.series.length > 1);
  assert.ok(sir.predictedBlastRadius >= 1 && sir.predictedBlastRadius <= 3);

  fs.writeFileSync(f.node.paths.protected, uniformBytes);
  const result = f.node.scanIntegrity();
  assert.equal(result.attackClassification, 'RANSOMWARE_ENCRYPTION_ATTACK');
  assert.equal(result.entropyScore, 8);
  assert.equal(result.sirBetaValue, 0.85);
  assert.equal(result.sirGammaValue, 0.4);
  assert.ok(Number.isFinite(result.predictedBlastRadius));
  assert.equal(f.node.verifyAudit().valid, true);

  const fingerprints = readJson(path.join(f.node.paths.quarantine, 'threat-fingerprint.json'), []);
  const { signature, auditIndex, ...fingerprint } = fingerprints.at(-1);
  assert.equal(Number.isSafeInteger(auditIndex), true);
  assert.equal(fingerprint.attackClassification, 'RANSOMWARE_ENCRYPTION_ATTACK');
  assert.equal(fingerprint.entropyScore, 8);
  assert.equal(verify(f.node.identity.publicKey, stable(fingerprint), signature), true);
  const auditFingerprint = f.node.audit.find(record => record.type === 'threat-fingerprint');
  assert.equal(auditFingerprint.details.sirBetaValue, 0.85);
  assert.equal(auditFingerprint.details.predictedBlastRadius, result.predictedBlastRadius);
});
