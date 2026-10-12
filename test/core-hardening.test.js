const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { SecurityNode, createAuthorities, authorityTrust, readJson, writeJsonAtomic } = require('../src/core');

function fixture(t) { const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-hardening-')); t.after(() => fs.rmSync(root, { recursive: true, force: true })); const authorities = createAuthorities(path.join(root, 'authorities')); const node = new SecurityNode({ directory: path.join(root, 'node'), name: 'node-a', trustedAuthorities: authorityTrust(authorities) }); return { root, node }; }

test('audit witness detects deletion and audit verification detects reordering and invalid signatures', t => {
  const f = fixture(t); f.node.scanIntegrity(); f.node.simulateTamper(); const auditFile = f.node.paths.audit;
  const deleted = readJson(auditFile); deleted.pop(); writeJsonAtomic(auditFile, deleted);
  const afterDeletion = new SecurityNode({ directory: f.node.directory, name: 'node-a', trustedAuthorities: f.node.trustedAuthorities });
  assert.equal(afterDeletion.verifyAudit().valid, false);

  const reordered = JSON.parse(JSON.stringify(f.node.audit)); [reordered[0], reordered[1]] = [reordered[1], reordered[0]]; afterDeletion.audit = reordered; assert.equal(afterDeletion.verifyAudit().valid, false);
  const invalidSignature = JSON.parse(JSON.stringify(f.node.audit)); invalidSignature[0].signature = 'invalid'; afterDeletion.audit = invalidSignature; assert.equal(afterDeletion.verifyAudit().valid, false);
});

test('snapshot metadata and stale snapshot rollback are rejected without accepting recovery', t => {
  const f = fixture(t); const first = f.node.state.trustedSnapshot; const second = f.node.createTrustedSnapshot('next-version');
  assert.notEqual(first, second); assert.equal(f.node.rollback(first).safeMode, true);
  const snapshot = readJson(path.join(f.node.paths.snapshots, `${second}.json`)); snapshot.nodeName = 'other-node'; writeJsonAtomic(path.join(f.node.paths.snapshots, `${second}.json`), snapshot);
  assert.deepEqual(f.node.verifySnapshot(second), { valid: false, reason: 'snapshot-metadata-invalid' });
});

test('sanitized audit report excludes source paths and private identity material', t => {
  const f = fixture(t); f.node.simulateTamper(); f.node.scanIntegrity(); const report = f.node.auditReport();
  assert.equal(report.verification.valid, true); assert.equal(JSON.stringify(report).includes('source'), false); assert.equal(JSON.stringify(report).includes('privateKey'), false);
});
