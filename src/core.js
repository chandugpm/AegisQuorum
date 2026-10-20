const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const stable = (value) => {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${stable(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
};
const encoded = (value) => Buffer.from(value).toString('base64');
const decoded = (value) => Buffer.from(value, 'base64');
const now = () => new Date().toISOString();
const SNAPSHOT_VERSION = 3;
const SUPPORTED_SNAPSHOT_VERSIONS = [2, SNAPSHOT_VERSION];
const snapshotIdIsSafe = (id) => typeof id === 'string' && /^[A-Za-z0-9-]{1,128}$/.test(id);
const auditEvidenceCanonical = (record) => stable({
  index: record.index,
  at: record.at,
  type: record.type,
  outcome: record.outcome,
  evidence: record.evidence,
  previousHash: record.previousHash
});
function sanitizeAuditValue(value) {
  if (Array.isArray(value)) return value.map(sanitizeAuditValue);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !/^(?:source|path|filename|directory|.*(?:token|secret|private.?key).*)$/i.test(key))
    .map(([key, nested]) => [key, sanitizeAuditValue(nested)]));
}
function hasSensitiveAuditField(value) {
  if (Array.isArray(value)) return value.some(hasSensitiveAuditField);
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, nested]) =>
    /^(?:source|path|filename|directory|.*(?:token|secret|private.?key).*)$/i.test(key) || hasSensitiveAuditField(nested));
}

function verifySanitizedAuditEvidence(report) {
  const proof = report?.proof;
  if (!report || report.verification?.valid !== true || typeof report.node !== 'string' ||
      !proof || proof.version !== 1 || proof.node !== report.node ||
      typeof proof.publicKey !== 'string' || !Array.isArray(proof.records) ||
      !Array.isArray(report.events) || !Number.isSafeInteger(proof.entries) ||
      proof.entries !== proof.records.length || proof.records.length !== report.events.length ||
      sha256(proof.publicKey) !== report.nodePublicKeyFingerprint) {
    return { valid: false, reason: 'evidence-metadata-invalid' };
  }

  let previousHash = 'GENESIS';
  for (let index = 0; index < proof.records.length; index++) {
    const record = proof.records[index];
    const event = report.events[index];
    if (!record || !event || record.index !== index || record.previousHash !== previousHash ||
        record.at !== event.at || record.type !== event.type || record.outcome !== event.outcome ||
        stable(record.evidence) !== stable(event.evidence) || !record.evidence ||
        hasSensitiveAuditField(record.evidence) || typeof record.hash !== 'string' ||
        !/^[a-f0-9]{64}$/.test(record.hash) ||
        record.hash !== sha256(auditEvidenceCanonical(record)) ||
        !verify(proof.publicKey, record.hash, record.signature)) {
      return { valid: false, index, reason: 'evidence-record-invalid' };
    }
    previousHash = record.hash;
  }
  if (proof.head !== previousHash) return { valid: false, index: proof.records.length, reason: 'evidence-witness-mismatch' };
  return { valid: true, entries: proof.records.length, head: previousHash };
}
function verifySanitizedAuditEvidenceWithTrust(report, trustedPublicKey) {
  const trusted = ed25519PublicKey(trustedPublicKey);
  if (!trusted) return { valid: false, reason: 'trusted-key-missing-invalid-or-unsupported' };
  const proofKey = ed25519PublicKey(report?.proof?.publicKey);
  if (!proofKey) return { valid: false, reason: 'evidence-public-key-invalid-or-unsupported' };
  if (trusted.fingerprint !== proofKey.fingerprint ||
      trusted.fingerprint !== report?.nodePublicKeyFingerprint) return {
    valid: false,
    reason: 'trusted-key-fingerprint-mismatch',
    trustedFingerprint: trusted.fingerprint,
    evidenceFingerprint: report?.nodePublicKeyFingerprint
  };
  const result = verifySanitizedAuditEvidence(report);
  return result.valid ? { ...result, signerFingerprint: trusted.fingerprint, signatureAlgorithm: 'Ed25519' } : result;
}

function ensureDirectory(directory) { fs.mkdirSync(directory, { recursive: true }); }
function writeJsonAtomic(filename, value) {
  ensureDirectory(path.dirname(filename));
  const temporary = `${filename}.${process.pid}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, filename);
}
function readJson(filename, fallback) { return fs.existsSync(filename) ? JSON.parse(fs.readFileSync(filename, 'utf8')) : fallback; }
function createIdentity(directory, name) {
  const filename = path.join(directory, 'identity.json');
  const existing = readJson(filename, null);
  if (existing) return existing;
  const pair = crypto.generateKeyPairSync('ed25519');
  const identity = {
    name,
    publicKey: pair.publicKey.export({ type: 'spki', format: 'pem' }),
    privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'pem' })
  };
  writeJsonAtomic(filename, identity);
  return identity;
}
function sign(privateKey, payload) { return encoded(crypto.sign(null, Buffer.from(payload), privateKey)); }
function verify(publicKey, payload, signature) {
  try { return crypto.verify(null, Buffer.from(payload), publicKey, decoded(signature)); } catch { return false; }
}
function normalizedPublicKey(publicKey) {
  return typeof publicKey === 'string' ? `${publicKey.trim().replace(/\r\n/g, '\n')}\n` : '';
}
function ed25519PublicKey(publicKey) {
  try {
    const normalized = normalizedPublicKey(publicKey);
    const key = crypto.createPublicKey(normalized);
    return key.asymmetricKeyType === 'ed25519' ? { key, pem: normalized, fingerprint: sha256(normalized) } : null;
  } catch {
    return null;
  }
}
function verifySnapshotArtifact(artifactBytes, { nodeName, snapshotId, expectedArtifactDigest, trustedPublicKey } = {}) {
  const fail = (reason, fields = {}) => ({ valid: false, reason, ...fields });
  if (!Buffer.isBuffer(artifactBytes) || artifactBytes.length === 0 || artifactBytes.length > 16 * 1024 * 1024) return fail('snapshot-artifact-size-invalid');
  const artifactDigest = sha256(artifactBytes);
  if (typeof expectedArtifactDigest !== 'string' || !/^[a-f0-9]{64}$/.test(expectedArtifactDigest) || artifactDigest !== expectedArtifactDigest) {
    return fail('snapshot-artifact-digest-mismatch', { artifactDigest });
  }
  const trusted = ed25519PublicKey(trustedPublicKey);
  if (!trusted) return fail('trusted-key-invalid-or-unsupported', { artifactDigest });
  let snapshot;
  try { snapshot = JSON.parse(artifactBytes.toString('utf8')); }
  catch { return fail('snapshot-artifact-invalid-json', { artifactDigest }); }
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot) ||
      !SUPPORTED_SNAPSHOT_VERSIONS.includes(snapshot.version)) return fail('snapshot-format-unsupported', { artifactDigest });
  const signatureAlgorithm = snapshot.version >= 3 ? snapshot.signatureAlgorithm : 'Ed25519';
  const signerFingerprint = snapshot.version >= 3 ? snapshot.signerKeyId : snapshot.identityFingerprint;
  if (signatureAlgorithm !== 'Ed25519') return fail('snapshot-signature-algorithm-unsupported', { artifactDigest, signatureAlgorithm });
  if (typeof snapshotId !== 'string' || !/^[A-Za-z0-9-]{1,128}$/.test(snapshotId) ||
      typeof nodeName !== 'string' || snapshot.nodeName !== nodeName) return fail('snapshot-identity-mismatch', { artifactDigest });
  if (signerFingerprint !== trusted.fingerprint || snapshot.identityFingerprint !== trusted.fingerprint) {
    return fail('snapshot-signer-fingerprint-mismatch', { artifactDigest, signerFingerprint, trustedFingerprint: trusted.fingerprint });
  }
  if (typeof snapshot.reason !== 'string' || !snapshot.reason || typeof snapshot.createdAt !== 'string' ||
      Number.isNaN(Date.parse(snapshot.createdAt)) || Date.parse(snapshot.createdAt) > Date.now() + 300000 ||
      typeof snapshot.content !== 'string' || typeof snapshot.digest !== 'string' ||
      !/^[a-f0-9]{64}$/.test(snapshot.digest) || typeof snapshot.signature !== 'string' ||
      !/^[A-Za-z0-9+/]{86}==$/.test(snapshot.signature) ||
      Buffer.from(snapshot.signature, 'base64').toString('base64') !== snapshot.signature) return fail('snapshot-metadata-invalid', { artifactDigest, signatureAlgorithm, signerFingerprint });
  const content = decoded(snapshot.content);
  if (content.toString('base64') !== snapshot.content || sha256(content) !== snapshot.digest) {
    return fail('snapshot-content-digest-mismatch', { artifactDigest, signatureAlgorithm, signerFingerprint });
  }
  const { signature, ...unsigned } = snapshot;
  if (!verify(trusted.pem, stable(unsigned), signature)) return fail('snapshot-signature-invalid', { artifactDigest, signatureAlgorithm, signerFingerprint });
  return {
    valid: true,
    artifactDigest,
    contentDigest: snapshot.digest,
    snapshotId,
    snapshotVersion: snapshot.version,
    signatureAlgorithm,
    signerFingerprint
  };
}
function policyDigest(update) { return sha256(stable(update)); }
function makePolicyUpdate(sequence, payload, issuedAt = now()) { return { kind: 'policy-update', sequence, issuedAt, payload }; }
function approvePolicy(update, authority) {
  const digest = policyDigest(update);
  return { authority: authority.name, digest, signature: sign(authority.privateKey, digest) };
}
function validatePolicyApprovals(update, approvals, trustedAuthorities, quorum, lastSequence = 0) {
  if (!update || update.kind !== 'policy-update' || !Number.isSafeInteger(update.sequence) || update.sequence <= lastSequence) throw new Error('policy-replay-or-invalid-sequence');
  const digest = policyDigest(update);
  if (!Array.isArray(approvals)) throw new Error(quorum === 2 ? 'policy-needs-two-valid-distinct-approvals' : `policy-needs-${quorum}-valid-distinct-approvals`);
  const seen = new Set();
  for (const approval of approvals) {
    if (!approval || typeof approval.authority !== 'string') throw new Error('policy-invalid-approval');
    if (seen.has(approval.authority)) throw new Error('policy-duplicate-approval');
    seen.add(approval.authority);
    const key = trustedAuthorities[approval.authority];
    if (!key || approval.digest !== digest || !verify(key, digest, approval.signature)) throw new Error('policy-invalid-approval');
  }
  if (seen.size < quorum) throw new Error(quorum === 2 ? 'policy-needs-two-valid-distinct-approvals' : `policy-needs-${quorum}-valid-distinct-approvals`);
  return digest;
}
function createAuthorities(directory) {
  ensureDirectory(directory);
  return ['authority-1', 'authority-2', 'authority-3'].map(name => createIdentity(path.join(directory, name), name));
}
function authorityTrust(authorities) { return Object.fromEntries(authorities.map(a => [a.name, a.publicKey])); }

class SecurityNode {
  constructor({ directory, name, trustedAuthorities, quorum = 2, clock = now }) {
    if (!Number.isSafeInteger(quorum) || quorum < 2 || quorum > Object.keys(trustedAuthorities || {}).length) throw new Error('policy quorum is invalid');
    this.directory = directory;
    this.name = name;
    this.trustedAuthorities = trustedAuthorities;
    this.quorum = quorum;
    this.clock = clock;
    this.paths = {
      protected: path.join(directory, 'protected', 'config.json'),
      snapshots: path.join(directory, 'snapshots'),
      quarantine: path.join(directory, 'quarantine'),
      state: path.join(directory, 'state.json'),
      audit: path.join(directory, 'audit.json')
    };
    ensureDirectory(directory); ensureDirectory(this.paths.snapshots); ensureDirectory(this.paths.quarantine);
    this.identity = createIdentity(directory, name);
    if (!fs.existsSync(this.paths.protected)) writeJsonAtomic(this.paths.protected, { node: name, routing: 'normal', revision: 1 });
    this.state = readJson(this.paths.state, { lastPolicySequence: 0, mode: 'trusted', quarantined: false, trustedSnapshot: null, policy: null });
    this.audit = readJson(this.paths.audit, []);
    if (!this.state.trustedSnapshot) this.createTrustedSnapshot('initial-baseline');
    else this.ensureAuditWitness();
  }
  saveState() { writeJsonAtomic(this.paths.state, this.state); }
  canonicalAudit(entry) { return stable({ index: entry.index, at: entry.at, type: entry.type, details: entry.details, previousHash: entry.previousHash }); }
  appendAudit(type, details = {}) {
    const previousHash = this.audit.length ? this.audit[this.audit.length - 1].hash : 'GENESIS';
    const draft = { index: this.audit.length, at: this.clock(), type, details, previousHash };
    const hash = sha256(this.canonicalAudit(draft));
    const record = { ...draft, hash, signature: sign(this.identity.privateKey, hash) };
    this.audit.push(record); writeJsonAtomic(this.paths.audit, this.audit);
    this.state.auditEntries = this.audit.length; this.state.auditHead = hash; this.saveState();
    return record;
  }
  verifyAudit({ ignoreWitness = false } = {}) {
    let previousHash = 'GENESIS';
    for (let index = 0; index < this.audit.length; index++) {
      const record = this.audit[index];
      if (record.index !== index || record.previousHash !== previousHash || record.hash !== sha256(this.canonicalAudit(record)) || !verify(this.identity.publicKey, record.hash, record.signature)) return { valid: false, index };
      previousHash = record.hash;
    }
    if (!ignoreWitness && (this.state.auditEntries !== undefined || this.state.auditHead !== undefined) && (this.state.auditEntries !== this.audit.length || this.state.auditHead !== previousHash)) return { valid: false, index: this.audit.length, reason: 'audit-witness-mismatch' };
    return { valid: true, entries: this.audit.length, head: previousHash };
  }
  ensureAuditWitness() {
    if (this.state.auditEntries !== undefined && this.state.auditHead !== undefined) return;
    const verification = this.verifyAudit({ ignoreWitness: true });
    if (!verification.valid) return;
    this.state.auditEntries = verification.entries; this.state.auditHead = verification.head; this.saveState();
  }
  digestProtected() { return sha256(fs.readFileSync(this.paths.protected)); }
  createTrustedSnapshot(reason) {
    const content = fs.readFileSync(this.paths.protected);
    const digest = sha256(content);
    const signerKeyId = sha256(this.identity.publicKey);
    const snapshot = { version: SNAPSHOT_VERSION, signatureAlgorithm: 'Ed25519', signerKeyId, nodeName: this.name, identityFingerprint: signerKeyId, createdAt: this.clock(), reason, digest, content: encoded(content) };
    snapshot.signature = sign(this.identity.privateKey, stable(snapshot));
    const id = `${Date.now()}-${digest.slice(0, 12)}`;
    const filename = path.join(this.paths.snapshots, `${id}.json`);
    writeJsonAtomic(filename, snapshot);
    const verification = this.verifySnapshot(id);
    if (!verification.valid) throw new Error(`trusted-snapshot-write-verification-failed:${verification.reason}`);
    this.state.trustedSnapshot = id; this.saveState();
    this.appendAudit('snapshot-created', {
      id,
      digest,
      artifactDigest: verification.artifactDigest,
      signatureAlgorithm: 'Ed25519',
      signerFingerprint: signerKeyId,
      snapshotSignatureVerified: true,
      snapshotContentDigestVerified: true,
      snapshotArtifactDigestVerified: true,
      reason
    });
    return id;
  }
  readSnapshot(id = this.state.trustedSnapshot) { return snapshotIdIsSafe(id) ? readJson(path.join(this.paths.snapshots, `${id}.json`), null) : null; }
  verifySnapshot(id = this.state.trustedSnapshot) {
    if (!snapshotIdIsSafe(id)) return { valid: false, reason: 'snapshot-id-invalid' };
    const filename = path.join(this.paths.snapshots, `${id}.json`);
    if (!fs.existsSync(filename)) return { valid: false, reason: 'snapshot-missing' };
    let snapshot;
    let artifactBytes;
    try {
      artifactBytes = fs.readFileSync(filename);
      snapshot = JSON.parse(artifactBytes.toString('utf8'));
    } catch { return { valid: false, reason: 'snapshot-unreadable' }; }
    if (!snapshot || typeof snapshot.content !== 'string' || typeof snapshot.digest !== 'string' || typeof snapshot.signature !== 'string') return { valid: false, reason: 'snapshot-malformed' };
    try {
      const { signature, ...unsigned } = snapshot;
      if (snapshot.version !== undefined) {
        if (!SUPPORTED_SNAPSHOT_VERSIONS.includes(snapshot.version) || snapshot.nodeName !== this.name || snapshot.identityFingerprint !== sha256(this.identity.publicKey) || typeof snapshot.reason !== 'string' || !snapshot.reason || typeof snapshot.createdAt !== 'string' || Number.isNaN(Date.parse(snapshot.createdAt)) || Date.parse(snapshot.createdAt) > Date.now() + 300000 ||
            (snapshot.version >= 3 && (snapshot.signatureAlgorithm !== 'Ed25519' || snapshot.signerKeyId !== sha256(this.identity.publicKey)))) return { valid: false, reason: 'snapshot-metadata-invalid' };
      }
      const content = decoded(snapshot.content);
      if (sha256(content) !== snapshot.digest) return { valid: false, reason: 'content-digest-mismatch' };
      if (!verify(this.identity.publicKey, stable(unsigned), signature)) return { valid: false, reason: 'snapshot-signature-invalid' };
      return { valid: true, snapshot, artifactDigest: sha256(artifactBytes) };
    } catch { return { valid: false, reason: 'snapshot-malformed' }; }
  }
  validatePolicy(update, approvals) {
    return validatePolicyApprovals(update, approvals, this.trustedAuthorities, this.quorum, this.state.lastPolicySequence);
  }
  applyPolicy(update, approvals) {
    if (this.state.quarantined || this.state.mode !== 'trusted') throw new Error('node-not-eligible-while-quarantined');
    const digest = this.validatePolicy(update, approvals);
    this.state.lastPolicySequence = update.sequence; this.state.policy = update; this.saveState();
    this.appendAudit('policy-accepted', { sequence: update.sequence, digest, approvers: approvals.map(a => a.authority) });
    return { accepted: true, sequence: update.sequence, digest };
  }
  scanIntegrity() {
    const checked = this.verifySnapshot();
    if (!checked.valid) return this.enterSafeMode(`trusted-snapshot-${checked.reason}`);
    const actual = this.digestProtected();
    if (actual === checked.snapshot.digest) { this.appendAudit('integrity-ok', { digest: actual }); return { clean: true, digest: actual, mode: this.state.mode }; }
    const evidence = { detectedAt: this.clock(), expected: checked.snapshot.digest, actual, source: this.paths.protected };
    writeJsonAtomic(path.join(this.paths.quarantine, `${Date.now()}-tamper-evidence.json`), evidence);
    this.state.quarantined = true; this.state.mode = 'quarantined'; this.saveState();
    this.appendAudit('tamper-detected', evidence); this.appendAudit('quarantine-applied', { simulated: true, actual });
    return { clean: false, quarantined: true, expected: evidence.expected, actual };
  }
  enterSafeMode(reason) { this.state.mode = 'safe-mode'; this.state.quarantined = true; this.saveState(); this.appendAudit('safe-mode-entered', { reason }); return { clean: false, safeMode: true, reason }; }
  rollback(id = this.state.trustedSnapshot) {
    this.appendAudit('recovery-attempted', { snapshotId: typeof id === 'string' ? id : 'invalid' });
    if (id !== this.state.trustedSnapshot) return this.enterSafeMode('rollback-snapshot-not-current');
    const result = this.verifySnapshot(id);
    if (!result.valid) return this.enterSafeMode(`rollback-${result.reason}`);
    const content = decoded(result.snapshot.content);
    let temporary;
    try {
      const before = this.digestProtected();
      temporary = `${this.paths.protected}.${crypto.randomUUID()}.restore`;
      fs.writeFileSync(temporary, content, { mode: 0o600 });
      if (sha256(fs.readFileSync(temporary)) !== result.snapshot.digest) { fs.rmSync(temporary, { force: true }); return this.enterSafeMode('rollback-write-verification-failed'); }
      fs.renameSync(temporary, this.paths.protected);
      if (this.digestProtected() !== result.snapshot.digest) return this.enterSafeMode('rollback-post-write-verification-failed');
      const postRecoverySnapshot = this.verifySnapshot(id);
      if (!postRecoverySnapshot.valid || postRecoverySnapshot.artifactDigest !== result.artifactDigest ||
          this.digestProtected() !== postRecoverySnapshot.snapshot.digest) return this.enterSafeMode('rollback-post-recovery-check-failed');
      this.state.mode = 'trusted'; this.state.quarantined = false; this.saveState(); this.appendAudit('rollback-verified', {
        id,
        before,
        restored: result.snapshot.digest,
        artifactDigest: result.artifactDigest,
        signatureAlgorithm: result.snapshot.signatureAlgorithm || 'Ed25519',
        signerFingerprint: result.snapshot.signerKeyId || result.snapshot.identityFingerprint,
        snapshotSignatureVerified: true,
        snapshotContentDigestVerified: true,
        snapshotArtifactDigestVerified: true
      });
      return { restored: true, digest: result.snapshot.digest, id };
    } catch (error) {
      if (temporary) fs.rmSync(temporary, { force: true });
      return this.enterSafeMode(`rollback-io-failure-${error.code || 'unknown'}`);
    }
  }
  simulateTamper() { fs.appendFileSync(this.paths.protected, `\n/* simulated tamper ${this.clock()} */\n`); this.appendAudit('tamper-simulated', {}); return { tampered: true }; }
  auditReport() {
    const outcome = { 'tamper-detected': 'detected', 'quarantine-applied': 'applied', 'rollback-verified': 'success', 'integrity-ok': 'success', 'safe-mode-entered': 'failed', 'policy-accepted': 'accepted' };
    const verification = this.verifyAudit();
    const events = this.audit.map(record => {
      const evidence = sanitizeAuditValue(record.details);
      return { index: record.index, at: record.at, type: record.type, outcome: outcome[record.type] || 'recorded', evidence };
    });
    let previousHash = 'GENESIS';
    const records = events.map(event => {
      const draft = { index: event.index, at: event.at, type: event.type, outcome: event.outcome, evidence: event.evidence, previousHash };
      const hash = sha256(auditEvidenceCanonical(draft));
      const record = { ...draft, hash, signature: sign(this.identity.privateKey, hash) };
      previousHash = hash;
      return record;
    });
    return {
      node: this.name,
      nodePublicKeyFingerprint: sha256(this.identity.publicKey),
      verification,
      events,
      proof: verification.valid ? { version: 1, node: this.name, publicKey: this.identity.publicKey, entries: records.length, head: previousHash, records } : null
    };
  }
  status() { return { name: this.name, nodePublicKeyFingerprint: sha256(this.identity.publicKey).slice(0, 16), mode: this.state.mode, quarantined: this.state.quarantined, lastPolicySequence: this.state.lastPolicySequence, trustedSnapshot: this.state.trustedSnapshot, currentDigest: this.digestProtected(), audit: this.verifyAudit() }; }
}

module.exports = { SecurityNode, sha256, stable, createAuthorities, authorityTrust, makePolicyUpdate, approvePolicy, validatePolicyApprovals, policyDigest, verify, verifySanitizedAuditEvidence, verifySanitizedAuditEvidenceWithTrust, verifySnapshotArtifact, readJson, writeJsonAtomic, SNAPSHOT_VERSION };
