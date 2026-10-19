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
const SNAPSHOT_VERSION = 2;
const snapshotIdIsSafe = (id) => typeof id === 'string' && /^[A-Za-z0-9-]{1,128}$/.test(id);

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
function policyDigest(update) { return sha256(stable(update)); }
function makePolicyUpdate(sequence, payload, issuedAt = now()) { return { kind: 'policy-update', sequence, issuedAt, payload }; }
function approvePolicy(update, authority) {
  const digest = policyDigest(update);
  return { authority: authority.name, digest, signature: sign(authority.privateKey, digest) };
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
    const snapshot = { version: SNAPSHOT_VERSION, nodeName: this.name, identityFingerprint: sha256(this.identity.publicKey), createdAt: this.clock(), reason, digest, content: encoded(content) };
    snapshot.signature = sign(this.identity.privateKey, stable(snapshot));
    const id = `${Date.now()}-${digest.slice(0, 12)}`;
    writeJsonAtomic(path.join(this.paths.snapshots, `${id}.json`), snapshot);
    this.state.trustedSnapshot = id; this.saveState(); this.appendAudit('snapshot-created', { id, digest, reason }); return id;
  }
  readSnapshot(id = this.state.trustedSnapshot) { return snapshotIdIsSafe(id) ? readJson(path.join(this.paths.snapshots, `${id}.json`), null) : null; }
  verifySnapshot(id = this.state.trustedSnapshot) {
    if (!snapshotIdIsSafe(id)) return { valid: false, reason: 'snapshot-id-invalid' };
    const filename = path.join(this.paths.snapshots, `${id}.json`);
    if (!fs.existsSync(filename)) return { valid: false, reason: 'snapshot-missing' };
    let snapshot;
    try { snapshot = readJson(filename, null); } catch { return { valid: false, reason: 'snapshot-unreadable' }; }
    if (!snapshot || typeof snapshot.content !== 'string' || typeof snapshot.digest !== 'string' || typeof snapshot.signature !== 'string') return { valid: false, reason: 'snapshot-malformed' };
    try {
      const { signature, ...unsigned } = snapshot;
      if (snapshot.version !== undefined) {
        if (snapshot.version !== SNAPSHOT_VERSION || snapshot.nodeName !== this.name || snapshot.identityFingerprint !== sha256(this.identity.publicKey) || typeof snapshot.reason !== 'string' || !snapshot.reason || typeof snapshot.createdAt !== 'string' || Number.isNaN(Date.parse(snapshot.createdAt)) || Date.parse(snapshot.createdAt) > Date.now() + 300000) return { valid: false, reason: 'snapshot-metadata-invalid' };
      }
      const content = decoded(snapshot.content);
      if (sha256(content) !== snapshot.digest) return { valid: false, reason: 'content-digest-mismatch' };
      if (!verify(this.identity.publicKey, stable(unsigned), signature)) return { valid: false, reason: 'snapshot-signature-invalid' };
      return { valid: true, snapshot };
    } catch { return { valid: false, reason: 'snapshot-malformed' }; }
  }
  validatePolicy(update, approvals) {
    if (!update || update.kind !== 'policy-update' || !Number.isSafeInteger(update.sequence) || update.sequence <= this.state.lastPolicySequence) throw new Error('policy-replay-or-invalid-sequence');
    const digest = policyDigest(update); const seen = new Set(); let valid = 0;
    for (const approval of approvals || []) {
      const key = this.trustedAuthorities[approval.authority];
      if (key && !seen.has(approval.authority) && approval.digest === digest && verify(key, digest, approval.signature)) { seen.add(approval.authority); valid++; }
    }
    if (valid < this.quorum) throw new Error(this.quorum === 2 ? 'policy-needs-two-valid-distinct-approvals' : `policy-needs-${this.quorum}-valid-distinct-approvals`);
    return digest;
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
      this.state.mode = 'trusted'; this.state.quarantined = false; this.saveState(); this.appendAudit('rollback-verified', { id, before, restored: result.snapshot.digest });
      return { restored: true, digest: result.snapshot.digest, id };
    } catch (error) {
      if (temporary) fs.rmSync(temporary, { force: true });
      return this.enterSafeMode(`rollback-io-failure-${error.code || 'unknown'}`);
    }
  }
  simulateTamper() { fs.appendFileSync(this.paths.protected, `\n/* simulated tamper ${this.clock()} */\n`); this.appendAudit('tamper-simulated', {}); return { tampered: true }; }
  auditReport() {
    const outcome = { 'tamper-detected': 'detected', 'quarantine-applied': 'applied', 'rollback-verified': 'success', 'integrity-ok': 'success', 'safe-mode-entered': 'failed', 'policy-accepted': 'accepted' };
    return {
      node: this.name,
      verification: this.verifyAudit(),
      events: this.audit.map(record => {
        const evidence = { ...record.details };
        delete evidence.source;
        return { index: record.index, at: record.at, type: record.type, outcome: outcome[record.type] || 'recorded', evidence };
      })
    };
  }
  status() { return { name: this.name, nodePublicKeyFingerprint: sha256(this.identity.publicKey).slice(0, 16), mode: this.state.mode, quarantined: this.state.quarantined, lastPolicySequence: this.state.lastPolicySequence, trustedSnapshot: this.state.trustedSnapshot, currentDigest: this.digestProtected(), audit: this.verifyAudit() }; }
}

module.exports = { SecurityNode, sha256, stable, createAuthorities, authorityTrust, makePolicyUpdate, approvePolicy, policyDigest, verify, readJson, writeJsonAtomic, SNAPSHOT_VERSION };
