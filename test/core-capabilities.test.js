const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { SecurityNode, createAuthorities, authorityTrust, readJson, writeJsonAtomic } = require('../src/core');

const fixedClock = () => '2026-10-12T00:00:00.000Z';
const fixtureContent = Buffer.from('{"allow":["10.10.0.0/16"],"mode":"observe-only","revision":7}\n');
const tamperedContent = Buffer.from('{"allow":["0.0.0.0/0"],"mode":"enforce","revision":999}\n');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-capability-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'test-authorities'));
  const node = new SecurityNode({ directory: path.join(root, 'test-node'), name: 'isolated-test-node', trustedAuthorities: authorityTrust(authorities), clock: fixedClock });
  fs.writeFileSync(node.paths.protected, fixtureContent, { mode: 0o600 });
  const baseline = Buffer.from(fs.readFileSync(node.paths.protected));
  const snapshotId = node.createTrustedSnapshot('deterministic-test-baseline');
  return { root, node, baseline, baselineHash: crypto.createHash('sha256').update(baseline).digest('hex'), snapshotId };
}

function snapshotPath(fixtureValue, id) { return path.join(fixtureValue.node.paths.snapshots, `${id}.json`); }
function writeSyntheticTamper(node) { fs.writeFileSync(node.paths.protected, tamperedContent, { mode: 0o600 }); }

test('A: real SHA-256 integrity detector reports a mismatch for a modified isolated fixture', t => {
  const f = fixture(t);
  assert.equal(f.node.verifySnapshot(f.snapshotId).valid, true);
  assert.equal(f.node.verifySnapshot(f.snapshotId).snapshot.digest, f.baselineHash);
  writeSyntheticTamper(f.node);

  const result = f.node.scanIntegrity();
  assert.equal(result.clean, false);
  assert.equal(result.quarantined, true);
  assert.equal(result.expected, f.baselineHash);
  assert.equal(result.actual, crypto.createHash('sha256').update(tamperedContent).digest('hex'));
  assert.equal(f.node.state.mode, 'quarantined');
  assert.ok(fs.readdirSync(f.node.paths.quarantine).some(name => name.endsWith('-tamper-evidence.json')));
});

test('B: valid signed snapshot is accepted; modified content is rejected before restoration', t => {
  const f = fixture(t);
  const valid = f.node.verifySnapshot(f.snapshotId);
  assert.equal(valid.valid, true);
  assert.equal(valid.snapshot.digest, f.baselineHash);

  const modifiedId = 'modified-content';
  const modified = readJson(snapshotPath(f, f.snapshotId));
  modified.content = Buffer.from('synthetic attacker content').toString('base64');
  writeJsonAtomic(snapshotPath(f, modifiedId), modified);
  writeSyntheticTamper(f.node);
  const before = Buffer.from(fs.readFileSync(f.node.paths.protected));

  assert.deepEqual(f.node.verifySnapshot(modifiedId), { valid: false, reason: 'content-digest-mismatch' });
  const recovery = f.node.rollback(modifiedId);
  assert.equal(recovery.restored, undefined);
  assert.equal(recovery.safeMode, true);
  assert.deepEqual(fs.readFileSync(f.node.paths.protected), before, 'unverified content was never written');
});

test('B: invalid signature and unreadable snapshot are rejected before restoration', t => {
  const f = fixture(t);
  const signatureId = 'invalid-signature';
  const badSignature = readJson(snapshotPath(f, f.snapshotId));
  badSignature.signature = Buffer.from('not an Ed25519 signature').toString('base64');
  writeJsonAtomic(snapshotPath(f, signatureId), badSignature);
  writeSyntheticTamper(f.node);
  const beforeInvalidSignature = Buffer.from(fs.readFileSync(f.node.paths.protected));
  assert.deepEqual(f.node.verifySnapshot(signatureId), { valid: false, reason: 'snapshot-signature-invalid' });
  assert.equal(f.node.rollback(signatureId).safeMode, true);
  assert.deepEqual(fs.readFileSync(f.node.paths.protected), beforeInvalidSignature);

  const unreadableId = 'corrupt-json';
  fs.writeFileSync(snapshotPath(f, unreadableId), '{not valid json', { mode: 0o600 });
  assert.deepEqual(f.node.verifySnapshot(unreadableId), { valid: false, reason: 'snapshot-unreadable' });
});

test('C: verified recovery restores exact baseline and post-recovery scan verifies integrity', t => {
  const f = fixture(t);
  writeSyntheticTamper(f.node);
  assert.equal(f.node.scanIntegrity().quarantined, true);

  const recovery = f.node.rollback(f.snapshotId);
  assert.equal(recovery.restored, true);
  assert.equal(recovery.digest, f.baselineHash);
  assert.deepEqual(fs.readFileSync(f.node.paths.protected), f.baseline);
  assert.equal(f.node.digestProtected(), f.baselineHash);
  const postRecovery = f.node.scanIntegrity();
  assert.equal(postRecovery.clean, true);
  assert.equal(postRecovery.digest, f.baselineHash);
});

test('C: missing snapshot and real filesystem recovery failure cannot report success or overwrite target', t => {
  const missing = fixture(t);
  writeSyntheticTamper(missing.node);
  const beforeMissing = Buffer.from(fs.readFileSync(missing.node.paths.protected));
  assert.deepEqual(missing.node.verifySnapshot('does-not-exist'), { valid: false, reason: 'snapshot-missing' });
  const missingRecovery = missing.node.rollback('does-not-exist');
  assert.equal(missingRecovery.restored, undefined);
  assert.equal(missingRecovery.safeMode, true);
  assert.deepEqual(fs.readFileSync(missing.node.paths.protected), beforeMissing);

  const failed = fixture(t);
  fs.rmSync(failed.node.paths.protected);
  fs.mkdirSync(failed.node.paths.protected);
  const failedRecovery = failed.node.rollback(failed.snapshotId);
  assert.equal(failedRecovery.restored, undefined);
  assert.equal(failedRecovery.safeMode, true);
  assert.match(failedRecovery.reason, /^rollback-io-failure-/);
  assert.equal(fs.statSync(failed.node.paths.protected).isDirectory(), true, 'real recovery failure did not overwrite target');
});

test('D: detection, quarantine, recovery, and post-recovery audit events chain correctly and copied-record tampering is detected', t => {
  const f = fixture(t);
  writeSyntheticTamper(f.node);
  f.node.scanIntegrity();
  f.node.rollback(f.snapshotId);
  f.node.scanIntegrity();
  const types = f.node.audit.map(record => record.type);
  for (const required of ['tamper-detected', 'quarantine-applied', 'rollback-verified', 'integrity-ok']) assert.ok(types.includes(required), `expected ${required} audit event`);
  assert.equal(f.node.verifyAudit().valid, true);

  const copiedAudit = JSON.parse(JSON.stringify(readJson(f.node.paths.audit)));
  copiedAudit.find(record => record.type === 'quarantine-applied').details.simulated = false;
  writeJsonAtomic(f.node.paths.audit, copiedAudit);
  const reloaded = new SecurityNode({ directory: f.node.directory, name: 'isolated-test-node', trustedAuthorities: f.node.trustedAuthorities, clock: fixedClock });
  assert.deepEqual(reloaded.verifyAudit(), { valid: false, index: copiedAudit.findIndex(record => record.type === 'quarantine-applied') });
});
