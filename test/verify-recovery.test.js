const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  SecurityNode,
  createAuthorities,
  authorityTrust,
  readJson,
  sha256,
  verifySnapshotArtifact,
  writeJsonAtomic
} = require('../src/core');
const { createRecoveryVerificationReport } = require('../src/verify-recovery');

function fixture(t, { failedPostCheck = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-recovery-proof-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities'));
  const node = new SecurityNode({ directory: path.join(root, 'node-a'), name: 'node-a', trustedAuthorities: authorityTrust(authorities) });
  const snapshotId = node.status().trustedSnapshot;
  const snapshotPath = path.join(node.paths.snapshots, `${snapshotId}.json`);
  const snapshotBytes = fs.readFileSync(snapshotPath);
  node.simulateTamper();
  node.scanIntegrity();
  assert.equal(node.rollback().restored, true);
  node.appendAudit('integrity-ok', { digest: failedPostCheck ? 'f'.repeat(64) : node.digestProtected() });
  return {
    root,
    node,
    report: node.auditReport(),
    snapshotId,
    snapshotBytes,
    trustedPublicKey: node.identity.publicKey
  };
}

function writeInputFiles(f) {
  const exportFile = path.join(f.root, 'audit-evidence.json');
  const keyFile = path.join(f.root, 'trusted-node-a.json');
  writeJsonAtomic(exportFile, { nodes: [f.report] });
  writeJsonAtomic(keyFile, {
    format: 'danms-node-trust-v1',
    node: 'node-a',
    algorithm: 'Ed25519',
    fingerprint: sha256(f.trustedPublicKey),
    publicKey: f.trustedPublicKey
  });
  return { exportFile, keyFile };
}

function runCli(f, extraArgs = []) {
  const { exportFile, keyFile } = writeInputFiles(f);
  const cli = path.join(__dirname, '..', 'src', 'verify-recovery.js');
  return spawnSync(process.execPath, [
    cli, exportFile, '--node', 'node-a', '--trusted-key', keyFile, ...extraArgs
  ], { encoding: 'utf8' });
}

test('audit-only and full modes report distinct proof boundaries with a trusted key', t => {
  const f = fixture(t);
  const auditOnly = createRecoveryVerificationReport(f.report, { trustedPublicKey: f.trustedPublicKey });
  assert.equal(auditOnly.verificationMode, 'audit-only');
  assert.equal(auditOnly.trustAnchor.status, 'trusted');
  assert.equal(auditOnly.auditVerification.status, 'verified');
  assert.equal(auditOnly.postRecoveryIntegrity.status, 'verified-clean');
  assert.equal(auditOnly.auditOnlyValid, true);
  assert.equal(auditOnly.snapshotAuthenticity.status, 'not-verified-artifact-not-supplied');
  assert.equal(auditOnly.fullRecoveryValid, false);
  assert.ok(auditOnly.incompleteChecks.some(item => item.includes('original snapshot artifact was not supplied')));

  const full = createRecoveryVerificationReport(f.report, {
    trustedPublicKey: f.trustedPublicKey,
    snapshotBytes: f.snapshotBytes
  });
  assert.equal(full.verificationMode, 'full-recovery');
  assert.equal(full.auditVerification.valid, true);
  assert.equal(full.snapshotAuthenticity.status, 'verified');
  assert.equal(full.snapshotAuthenticity.signatureAlgorithm, 'Ed25519');
  assert.equal(full.snapshotAuthenticity.snapshotId, f.snapshotId);
  assert.equal(full.recoveryOperation.snapshotAuditMetadataConsistent, true);
  assert.equal(full.postRecoveryIntegrity.status, 'verified-clean');
  assert.equal(full.fullRecoveryValid, true);
  assert.equal(full.complete, true);

  const auditCli = runCli(f);
  assert.equal(auditCli.status, 0, auditCli.stderr);
  const auditCliReport = JSON.parse(auditCli.stdout).reports[0];
  assert.equal(auditCliReport.verificationMode, 'audit-only');
  assert.equal(auditCliReport.snapshotAuthenticity.status, 'not-verified-artifact-not-supplied');
  const fullCli = runCli(f, ['--snapshot', path.join(f.node.paths.snapshots, `${f.snapshotId}.json`)]);
  assert.equal(fullCli.status, 0, fullCli.stderr);
  assert.equal(JSON.parse(fullCli.stdout).reports[0].fullRecoveryValid, true);
});

test('snapshot verification rejects altered exact artifact bytes', t => {
  const f = fixture(t);
  const altered = Buffer.concat([f.snapshotBytes, Buffer.from(' ')]);
  const result = createRecoveryVerificationReport(f.report, {
    trustedPublicKey: f.trustedPublicKey,
    snapshotBytes: altered
  });
  assert.equal(result.snapshotAuthenticity.status, 'failed');
  assert.equal(result.snapshotAuthenticity.reason, 'snapshot-artifact-digest-mismatch');
  assert.equal(result.fullRecoveryValid, false);
});

test('missing supplied snapshot artifact is explicit and fails full verification', t => {
  const f = fixture(t);
  const result = runCli(f, ['--snapshot', path.join(f.root, 'absent-snapshot.json')]);
  assert.equal(result.status, 1);
  const report = JSON.parse(result.stdout).reports[0];
  assert.equal(report.verificationMode, 'full-recovery');
  assert.equal(report.snapshotAuthenticity.status, 'failed');
  assert.equal(report.snapshotAuthenticity.reason, 'snapshot-artifact-missing-or-unreadable');
});

test('snapshot signature failure is detected after checking the supplied artifact digest', t => {
  const f = fixture(t);
  const snapshot = JSON.parse(f.snapshotBytes.toString('utf8'));
  snapshot.signature = `${snapshot.signature[0] === 'A' ? 'B' : 'A'}${snapshot.signature.slice(1)}`;
  const corruptedBytes = Buffer.from(`${JSON.stringify(snapshot, null, 2)}\n`);
  const result = verifySnapshotArtifact(corruptedBytes, {
    nodeName: 'node-a',
    snapshotId: f.snapshotId,
    expectedArtifactDigest: sha256(corruptedBytes),
    trustedPublicKey: f.trustedPublicKey
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'snapshot-signature-invalid');
});

test('independent trust anchor is required and key mismatches are explicit', t => {
  const f = fixture(t);
  const missing = createRecoveryVerificationReport(f.report);
  assert.equal(missing.trustAnchor.status, 'missing');
  assert.equal(missing.auditVerification.status, 'failed');
  assert.equal(missing.auditOnlyValid, false);

  const otherAuthorities = createAuthorities(path.join(f.root, 'other-authorities'));
  const untrustedKey = otherAuthorities[0].publicKey;
  const mismatch = createRecoveryVerificationReport(f.report, {
    trustedPublicKey: untrustedKey,
    snapshotBytes: f.snapshotBytes
  });
  assert.equal(mismatch.trustAnchor.status, 'fingerprint-mismatch');
  assert.equal(mismatch.auditVerification.reason, 'trusted-key-fingerprint-mismatch');
  assert.equal(mismatch.snapshotAuthenticity.status, 'not-verified-audit-evidence-invalid');
  assert.equal(mismatch.fullRecoveryValid, false);
});

test('CLI fails explicitly when its independent trust record is unavailable', t => {
  const f = fixture(t);
  const { exportFile } = writeInputFiles(f);
  const cli = path.join(__dirname, '..', 'src', 'verify-recovery.js');
  const result = spawnSync(process.execPath, [
    cli, exportFile, '--node', 'node-a', '--trusted-key', path.join(f.root, 'missing-trust-record.json')
  ], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  const report = JSON.parse(result.stdout).reports[0];
  assert.equal(report.trustAnchor.status, 'unavailable-or-invalid');
  assert.equal(report.auditVerification.status, 'failed');
});

test('CLI rejects a trusted key record bound to a different node identity', t => {
  const f = fixture(t);
  const { exportFile, keyFile } = writeInputFiles(f);
  const misplacedTrust = readJson(keyFile);
  misplacedTrust.node = 'node-b';
  writeJsonAtomic(keyFile, misplacedTrust);
  const cli = path.join(__dirname, '..', 'src', 'verify-recovery.js');
  const result = spawnSync(process.execPath, [
    cli, exportFile, '--node', 'node-a', '--trusted-key', keyFile
  ], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  const report = JSON.parse(result.stdout).reports[0];
  assert.equal(report.trustAnchor.status, 'node-identity-mismatch');
  assert.equal(report.auditVerification.status, 'failed');
});

test('CLI rejects a trust record whose pinned fingerprint does not match its public key', t => {
  const f = fixture(t);
  const { exportFile, keyFile } = writeInputFiles(f);
  const trust = readJson(keyFile);
  trust.fingerprint = '0'.repeat(64);
  writeJsonAtomic(keyFile, trust);
  const cli = path.join(__dirname, '..', 'src', 'verify-recovery.js');
  const result = spawnSync(process.execPath, [
    cli, exportFile, '--node', 'node-a', '--trusted-key', keyFile
  ], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stdout).reports[0].trustAnchor.status, 'fingerprint-mismatch');
});

test('audit evidence tampering fails even when the original snapshot is valid', t => {
  const f = fixture(t);
  const edited = structuredClone(f.report);
  edited.events[0].evidence.digest = 'a'.repeat(64);
  edited.proof.records[0].evidence.digest = 'a'.repeat(64);
  const result = createRecoveryVerificationReport(edited, {
    trustedPublicKey: f.trustedPublicKey,
    snapshotBytes: f.snapshotBytes
  });
  assert.equal(result.auditVerification.status, 'failed');
  assert.equal(result.auditOnlyValid, false);
  assert.equal(result.snapshotAuthenticity.status, 'not-verified-audit-evidence-invalid');
  assert.equal(result.fullRecoveryValid, false);
});

test('valid snapshot authenticity is reported separately from failed post-recovery integrity', t => {
  const f = fixture(t, { failedPostCheck: true });
  const result = createRecoveryVerificationReport(f.report, {
    trustedPublicKey: f.trustedPublicKey,
    snapshotBytes: f.snapshotBytes
  });
  assert.equal(result.auditVerification.status, 'verified');
  assert.equal(result.snapshotAuthenticity.status, 'verified');
  assert.equal(result.postRecoveryIntegrity.status, 'failed');
  assert.equal(result.postRecoveryIntegrity.valid, false);
  assert.equal(result.auditOnlyValid, false);
  assert.equal(result.fullRecoveryValid, false);
});

test('unsupported snapshot signing algorithms and non-Ed25519 trust keys are rejected', t => {
  const f = fixture(t);
  const snapshot = JSON.parse(f.snapshotBytes.toString('utf8'));
  snapshot.signatureAlgorithm = 'RSA-SHA256';
  const unsupported = Buffer.from(`${JSON.stringify(snapshot, null, 2)}\n`);
  const result = verifySnapshotArtifact(unsupported, {
    nodeName: 'node-a',
    snapshotId: f.snapshotId,
    expectedArtifactDigest: sha256(unsupported),
    trustedPublicKey: f.trustedPublicKey
  });
  assert.equal(result.reason, 'snapshot-signature-algorithm-unsupported');

  const rsa = require('node:crypto').generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'pem' });
  const wrongAlgorithm = verifySnapshotArtifact(f.snapshotBytes, {
    nodeName: 'node-a',
    snapshotId: f.snapshotId,
    expectedArtifactDigest: sha256(f.snapshotBytes),
    trustedPublicKey: rsa
  });
  assert.equal(wrongAlgorithm.reason, 'trusted-key-invalid-or-unsupported');
});

test('recovery report marks failed restore and absent post-check without claiming trust', t => {
  const f = fixture(t);
  const failed = readJson(path.join(f.node.paths.snapshots, `${f.snapshotId}.json`));
  failed.content = Buffer.from('invalid snapshot').toString('base64');
  writeJsonAtomic(path.join(f.node.paths.snapshots, `${f.snapshotId}.json`), failed);
  assert.equal(f.node.rollback().safeMode, true);
  const result = createRecoveryVerificationReport(f.node.auditReport(), { trustedPublicKey: f.trustedPublicKey });
  assert.equal(result.auditVerification.status, 'verified');
  assert.equal(result.recoveryOperation.status, 'failed');
  assert.equal(result.postRecoveryIntegrity.status, 'not-verified');
  assert.equal(result.finalTrustState, 'safe-mode-at-event-time');
  assert.equal(result.auditOnlyValid, false);
});
