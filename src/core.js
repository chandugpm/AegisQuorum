const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
function calculateEntropy(value) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value || []);
  if (!buffer.length) return 0;
  const frequencies = new Uint32Array(256);
  for (const byte of buffer) frequencies[byte]++;
  let entropy = 0;
  for (const frequency of frequencies) {
    if (!frequency) continue;
    const probability = frequency / buffer.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}
function simulateSIR(beta = 0.85, gamma = 0.4, { population = 3, initialInfected = 1, timeStep = 0.1, horizonSeconds = 60, saturationThreshold = 0.8 } = {}) {
  if (!Number.isFinite(beta) || beta < 0 || beta > 10 || !Number.isFinite(gamma) || gamma <= 0 || gamma > 10 ||
      !Number.isSafeInteger(population) || population < 2 || population > 10000 ||
      !Number.isFinite(initialInfected) || initialInfected <= 0 || initialInfected >= population ||
      !Number.isFinite(timeStep) || timeStep <= 0 || timeStep > 1 ||
      !Number.isFinite(horizonSeconds) || horizonSeconds <= 0 || horizonSeconds > 300 ||
      !Number.isFinite(saturationThreshold) || saturationThreshold <= 0 || saturationThreshold >= 1) {
    throw new Error('sir-parameters-invalid');
  }
  let susceptible = population - initialInfected;
  let infected = initialInfected;
  let recovered = 0;
  let peakInfected = infected;
  let timeToSaturationSeconds = null;
  const series = [];
  const steps = Math.ceil(horizonSeconds / timeStep);
  for (let step = 0; step <= steps; step++) {
    const timeSeconds = Math.min(horizonSeconds, step * timeStep);
    const infectionRate = beta * susceptible * infected / population;
    const recoveryRate = gamma * infected;
    if (step === 0 || Math.abs(timeSeconds - Math.round(timeSeconds)) < timeStep / 2 || step === steps) {
      series.push({
        timeSeconds: Number(timeSeconds.toFixed(2)),
        susceptible: Number(susceptible.toFixed(4)),
        infected: Number(infected.toFixed(4)),
        recovered: Number(recovered.toFixed(4)),
        infectionRate: Number(infectionRate.toFixed(4)),
        recoveryRate: Number(recoveryRate.toFixed(4))
      });
    }
    if (timeToSaturationSeconds === null && susceptible <= population * (1 - saturationThreshold)) {
      timeToSaturationSeconds = Number(timeSeconds.toFixed(2));
    }
    if (step === steps) break;
    // Euler-integrate dS/dt=-βSI/N, dI/dt=βSI/N−γI, dR/dt=γI; β models peer spread and γ models antibody recovery.
    const infectedDelta = (infectionRate - recoveryRate) * timeStep;
    const susceptibleDelta = -infectionRate * timeStep;
    const recoveredDelta = recoveryRate * timeStep;
    susceptible = Math.max(0, susceptible + susceptibleDelta);
    infected = Math.max(0, infected + infectedDelta);
    recovered = Math.min(population, recovered + recoveredDelta);
    const total = susceptible + infected + recovered;
    if (Math.abs(total - population) > 1e-8) susceptible = Math.max(0, susceptible + population - total);
    peakInfected = Math.max(peakInfected, infected);
  }
  const affected = population - (series.at(-1)?.susceptible || 0);
  return {
    beta,
    gamma,
    basicReproductionNumber: Number((beta / gamma).toFixed(4)),
    population,
    timeStep,
    horizonSeconds,
    saturationThreshold,
    timeToSaturationSeconds,
    predictedBlastRadius: Number(affected.toFixed(3)),
    peakInfected: Number(peakInfected.toFixed(3)),
    series
  };
}
const calculateShannonEntropy = calculateEntropy;
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
function signThreatAntibody(packet, privateKey) {
  const { signature, ...unsigned } = packet;
  return { ...unsigned, signature: sign(privateKey, stable(unsigned)) };
}
class AntibodyGenerator {
  constructor({ privateKey, sourceNode, clock = Date.now }) {
    if (typeof privateKey !== 'string' || typeof sourceNode !== 'string' || !/^[A-Za-z0-9-]{1,64}$/.test(sourceNode) || typeof clock !== 'function') {
      throw new Error('antibody-generator-configuration-invalid');
    }
    this.privateKey = privateKey;
    this.sourceNode = sourceNode;
    this.clock = clock;
  }
  generateAntibody(attackVector) {
    const vector = typeof attackVector === 'string' && /^[a-f0-9]{64}$/i.test(attackVector)
      ? attackVector.toLowerCase()
      : sha256(Buffer.isBuffer(attackVector) ? attackVector : Buffer.from(String(attackVector ?? '')));
    const timestamp = this.clock();
    const packet = {
      type: 'ANTIBODY',
      vector,
      timestamp,
      antibodyId: crypto.randomUUID(),
      sourceNode: this.sourceNode,
      attackVectorHash: vector,
      elevatedRateLimit: true,
      blockedSignatures: [vector],
      issuedAt: new Date(timestamp).toISOString()
    };
    return signThreatAntibody(packet, this.privateKey);
  }
}
function generateGossipAntibody(attackVector, privateKey, sourceNode, clock = Date.now) {
  if (attackVector && typeof attackVector === 'object' && !Buffer.isBuffer(attackVector) && privateKey === undefined) {
    const options = attackVector;
    return new AntibodyGenerator({ privateKey: options.privateKey, sourceNode: options.sourceNode, clock: options.clock || Date.now })
      .generateAntibody(options.attackVector);
  }
  return new AntibodyGenerator({ privateKey, sourceNode, clock }).generateAntibody(attackVector);
}
function verifyThreatAntibody(packet, publicKey) {
  if (!packet || typeof packet !== 'object' || typeof packet.sourceNode !== 'string' ||
      !/^[a-zA-Z0-9-]{1,64}$/.test(packet.sourceNode) ||
      packet.type !== 'ANTIBODY' || typeof packet.vector !== 'string' || packet.vector !== packet.attackVectorHash ||
      !/^[a-f0-9]{64}$/.test(packet.vector) || !Number.isSafeInteger(packet.timestamp) ||
  typeof packet.antibodyId !== 'string' || !/^[A-Za-z0-9-]{1,128}$/.test(packet.antibodyId) ||
      typeof packet.attackVectorHash !== 'string' || !/^[a-f0-9]{64}$/.test(packet.attackVectorHash) ||
      packet.elevatedRateLimit !== true || !Array.isArray(packet.blockedSignatures) ||
      packet.blockedSignatures.length > 20 || packet.blockedSignatures.some(value => typeof value !== 'string' || value.length > 128) ||
  typeof packet.issuedAt !== 'string' || !Number.isFinite(Date.parse(packet.issuedAt)) ||
      typeof packet.signature !== 'string') return false;
  const { signature, ...unsigned } = packet;
  return verify(publicKey, stable(unsigned), signature);
}
function decodeBase64Url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('webauthn-encoding-invalid');
  const decodedValue = Buffer.from(value, 'base64url');
  if (decodedValue.toString('base64url') !== value) throw new Error('webauthn-encoding-invalid');
  return decodedValue;
}
function decodeCbor(buffer, offset = 0) {
  if (!Buffer.isBuffer(buffer) || offset >= buffer.length) throw new Error('webauthn-cbor-invalid');
  const initial = buffer[offset++];
  const major = initial >> 5;
  const additional = initial & 31;
  let length;
  if (additional < 24) length = additional;
  else if (additional === 24 && offset + 1 <= buffer.length) length = buffer[offset++];
  else if (additional === 25 && offset + 2 <= buffer.length) { length = buffer.readUInt16BE(offset); offset += 2; }
  else if (additional === 26 && offset + 4 <= buffer.length) { length = buffer.readUInt32BE(offset); offset += 4; }
  else throw new Error('webauthn-cbor-length-invalid');
  if (!Number.isSafeInteger(length) || length > buffer.length) throw new Error('webauthn-cbor-length-invalid');
  if (major === 0) return { value: length, offset };
  if (major === 1) return { value: -1 - length, offset };
  if (major === 2 || major === 3) {
    if (offset + length > buffer.length) throw new Error('webauthn-cbor-truncated');
    const data = buffer.subarray(offset, offset + length);
    return { value: major === 2 ? data : data.toString('utf8'), offset: offset + length };
  }
  if (major === 4) {
    const values = [];
    for (let index = 0; index < length; index++) {
      const next = decodeCbor(buffer, offset);
      values.push(next.value); offset = next.offset;
    }
    return { value: values, offset };
  }
  if (major === 5) {
    const values = {};
    for (let index = 0; index < length; index++) {
      const key = decodeCbor(buffer, offset);
      const next = decodeCbor(buffer, key.offset);
      values[String(key.value)] = next.value; offset = next.offset;
    }
    return { value: values, offset };
  }
  if (major === 7 && additional === 20) return { value: false, offset };
  if (major === 7 && additional === 21) return { value: true, offset };
  if (major === 7 && additional === 22) return { value: null, offset };
  throw new Error('webauthn-cbor-type-unsupported');
}
function verifyWebAuthnAssertion(approval, digest, authorityRecord, { origin, rpId, previousSignCount = 0 } = {}) {
  try {
    if (!approval || approval.algorithm !== 'WebAuthn' || approval.digest !== digest ||
        approval.credentialId !== authorityRecord?.credentialId || typeof authorityRecord?.publicKey !== 'string') return { valid: false };
    const clientDataBytes = decodeBase64Url(approval.clientDataJSON);
    const clientData = JSON.parse(clientDataBytes.toString('utf8'));
    const challengeBytes = decodeBase64Url(clientData.challenge);
    let challengeMatches = challengeBytes.toString('hex') === digest;
    if (!challengeMatches) {
      try {
        const challengeData = JSON.parse(challengeBytes.toString('utf8'));
        challengeMatches = challengeData.digest === digest && typeof challengeData.nonce === 'string' && /^[A-Za-z0-9_-]{43}$/.test(challengeData.nonce);
      } catch { challengeMatches = false; }
    }
    if (clientData.type !== 'webauthn.get' || !challengeMatches ||
        (origin && clientData.origin !== origin) || clientData.crossOrigin === true) return { valid: false };
    const authenticatorData = decodeBase64Url(approval.authenticatorData);
    if (authenticatorData.length < 37 || (authenticatorData[32] & 0x05) !== 0x05) return { valid: false };
    if (rpId && !crypto.timingSafeEqual(authenticatorData.subarray(0, 32), crypto.createHash('sha256').update(rpId).digest())) return { valid: false };
    const signCount = authenticatorData.readUInt32BE(33);
    if (signCount !== 0 && signCount <= previousSignCount) return { valid: false };
    const signed = Buffer.concat([authenticatorData, crypto.createHash('sha256').update(clientDataBytes).digest()]);
    const signature = decodeBase64Url(approval.signature);
    const publicKey = crypto.createPublicKey(authorityRecord.publicKey);
    if (publicKey.asymmetricKeyType !== 'ec' || publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
        !crypto.verify('sha256', signed, publicKey, signature)) return { valid: false };
    return { valid: true, signCount };
  } catch {
    return { valid: false };
  }
}
function parseWebAuthnRegistration(registration, { challenge, origin, rpId } = {}) {
  const clientDataBytes = decodeBase64Url(registration?.clientDataJSON);
  const clientData = JSON.parse(clientDataBytes.toString('utf8'));
  if (clientData.type !== 'webauthn.create' || clientData.challenge !== challenge ||
      clientData.origin !== origin || clientData.crossOrigin === true) throw new Error('webauthn-client-data-invalid');
  const attestation = decodeCbor(decodeBase64Url(registration.attestationObject)).value;
  if (attestation?.fmt !== 'none' || !Buffer.isBuffer(attestation.authData)) throw new Error('webauthn-attestation-format-unsupported');
  const authenticatorData = attestation.authData;
  if (authenticatorData.length < 55 || (authenticatorData[32] & 0x45) !== 0x45 ||
      !crypto.timingSafeEqual(authenticatorData.subarray(0, 32), crypto.createHash('sha256').update(rpId).digest())) {
    throw new Error('webauthn-authenticator-data-invalid');
  }
  const signCount = authenticatorData.readUInt32BE(33);
  const credentialLength = authenticatorData.readUInt16BE(53);
  const credentialStart = 55;
  const credentialEnd = credentialStart + credentialLength;
  if (credentialLength < 1 || credentialEnd >= authenticatorData.length) throw new Error('webauthn-credential-id-invalid');
  const credentialId = authenticatorData.subarray(credentialStart, credentialEnd).toString('base64url');
  if (registration.credentialId !== credentialId) throw new Error('webauthn-credential-id-mismatch');
  const cose = decodeCbor(authenticatorData, credentialEnd);
  const key = cose.value;
  if (!key || key['1'] !== 2 || key['3'] !== -7 || key['-1'] !== 1 ||
      !Buffer.isBuffer(key['-2']) || !Buffer.isBuffer(key['-3']) ||
      key['-2'].length !== 32 || key['-3'].length !== 32) throw new Error('webauthn-cose-key-unsupported');
  const publicKey = crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: key['-2'].toString('base64url'), y: key['-3'].toString('base64url') },
    format: 'jwk'
  });
  return { credentialId, publicKey: publicKey.export({ type: 'spki', format: 'pem' }), signCount };
}
function auditPrivacyLedger(records) {
  const categories = { tokens: 0, secrets: 0, signingMaterial: 0, filesystemPaths: 0 };
  function count(value) {
    if (Array.isArray(value)) { value.forEach(count); return; }
    if (!value || typeof value !== 'object') return;
    for (const [key, nested] of Object.entries(value)) {
      if (/token/i.test(key)) categories.tokens++;
      else if (/secret/i.test(key)) categories.secrets++;
      else if (/private.?key/i.test(key)) categories.signingMaterial++;
      else if (/^(?:source|path|filename|directory)$/i.test(key)) categories.filesystemPaths++;
      count(nested);
    }
  }
  records.forEach(record => count(record.details));
  return { redactedFields: Object.values(categories).reduce((sum, value) => sum + value, 0), categories };
}
function executeDryRunSandbox(candidatePolicy, recentAuditEvents) {
  if (!candidatePolicy || candidatePolicy.kind !== 'policy-update' ||
      !Number.isSafeInteger(candidatePolicy.sequence) || !candidatePolicy.payload ||
      typeof candidatePolicy.payload !== 'object' || Array.isArray(candidatePolicy.payload) ||
      candidatePolicy.payload.enforcement !== 'quarantine-on-integrity-mismatch' ||
      candidatePolicy.payload.requireSignedPolicy !== true ||
      !Array.isArray(candidatePolicy.payload.triggerEvents) ||
      !candidatePolicy.payload.triggerEvents.includes('tamper-detected') ||
      candidatePolicy.payload.triggerEvents.some(type => typeof type !== 'string' || type.length > 64) ||
      !Array.isArray(recentAuditEvents)) throw new Error('sandbox-candidate-or-events-invalid');
  const replayed = recentAuditEvents.slice(-50);
  const protectedTypes = new Set(['tamper-detected', 'quarantine-applied', 'deception-probe', 'threat-antibody-created', 'gossip-inoculated']);
  const benignTypes = new Set(['snapshot-created', 'policy-accepted', 'request-accepted', 'integrity-ok', 'rollback-verified']);
  const triggers = new Set(candidatePolicy.payload.triggerEvents);
  const eventType = event => event?.type || event?.eventType || 'unknown-event';
  const falsePositives = replayed.filter(event => benignTypes.has(eventType(event)) && triggers.has(eventType(event))).length;
  if (falsePositives > 0) throw new Error('sandbox-candidate-false-positive');
  const mitigatedVectors = [...new Set(replayed.filter(event => protectedTypes.has(eventType(event)) && triggers.has(eventType(event))).map(event => eventType(event)))];
  const certificate = {
    candidatePolicy,
    dryRunPassed: true,
    replayedEventsCount: replayed.length,
    falsePositives,
    mitigatedVectors,
    safetyScore: 100
  };
  return { ...certificate, sandboxDigest: sha256(stable(certificate)), replayEventsTested: replayed.length, candidateProposal: candidatePolicy };
}
function approvePolicy(update, authority) {
  const digest = policyDigest(update);
  return { authority: authority.name, digest, signature: sign(authority.privateKey, digest) };
}
function validatePolicyApprovals(update, approvals, trustedAuthorities, quorum, lastSequence = 0, webauthnAuthorities = {}) {
  if (!update || update.kind !== 'policy-update' || !Number.isSafeInteger(update.sequence) || update.sequence <= lastSequence) throw new Error('policy-replay-or-invalid-sequence');
  const digest = policyDigest(update);
  if (!Array.isArray(approvals)) throw new Error(quorum === 2 ? 'policy-needs-two-valid-distinct-approvals' : `policy-needs-${quorum}-valid-distinct-approvals`);
  const seen = new Set();
  for (const approval of approvals) {
    if (!approval || typeof approval.authority !== 'string') throw new Error('policy-invalid-approval');
    if (seen.has(approval.authority)) throw new Error('policy-duplicate-approval');
    seen.add(approval.authority);
    if (approval.algorithm === 'WebAuthn') {
      const authority = webauthnAuthorities[approval.authority];
      const assertion = verifyWebAuthnAssertion(approval, digest, authority, { previousSignCount: authority?.signCount || 0 });
      if (!assertion.valid) throw new Error('policy-invalid-approval');
    } else {
      const key = trustedAuthorities[approval.authority];
      if (!key || approval.digest !== digest || !verify(key, digest, approval.signature)) throw new Error('policy-invalid-approval');
    }
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
    this.antibodyGenerator = new AntibodyGenerator({ privateKey: this.identity.privateKey, sourceNode: name });
    if (!fs.existsSync(this.paths.protected)) writeJsonAtomic(this.paths.protected, { node: name, routing: 'normal', revision: 1 });
    this.state = readJson(this.paths.state, { lastPolicySequence: 0, mode: 'trusted', quarantined: false, decoyState: null, shieldState: 'normal', trustedSnapshot: null, policy: null });
    this.state.decoyState ||= null;
    this.state.shieldState ||= 'normal';
    this.state.blockList ||= [];
    this.state.webauthnAuthorities ||= {};
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
    return validatePolicyApprovals(update, approvals, this.trustedAuthorities, this.quorum, this.state.lastPolicySequence, this.state.webauthnAuthorities);
  }
  registerWebAuthnAuthority(authority, credential) {
    if (!Object.hasOwn(this.trustedAuthorities, authority) || !credential || typeof credential !== 'object' ||
        typeof credential.credentialId !== 'string' || !/^[A-Za-z0-9_-]{1,256}$/.test(credential.credentialId) ||
        typeof credential.publicKey !== 'string' || !Number.isSafeInteger(credential.signCount) || credential.signCount < 0) {
      throw new Error('webauthn-authority-registration-invalid');
    }
    let key;
    try { key = crypto.createPublicKey(credential.publicKey); } catch { throw new Error('webauthn-authority-public-key-invalid'); }
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Error('webauthn-authority-public-key-unsupported');
    const existing = this.state.webauthnAuthorities[authority];
    if (existing) {
      if (existing.credentialId === credential.credentialId && existing.publicKey === credential.publicKey) return { registered: true, unchanged: true };
      throw new Error('webauthn-authority-already-registered');
    }
    this.state.webauthnAuthorities[authority] = credential;
    this.saveState();
    this.appendAudit('webauthn-authority-registered', { authority, credentialIdHash: sha256(credential.credentialId) });
    return { registered: true };
  }
  applyPolicy(update, approvals) {
    if (this.state.quarantined || this.state.mode !== 'trusted') throw new Error('node-not-eligible-while-quarantined');
    const digest = this.validatePolicy(update, approvals);
    for (const approval of approvals) {
      if (approval.algorithm !== 'WebAuthn') continue;
      const authority = this.state.webauthnAuthorities[approval.authority];
      const assertion = verifyWebAuthnAssertion(approval, digest, authority, { previousSignCount: authority.signCount || 0 });
      if (assertion.signCount > 0) authority.signCount = assertion.signCount;
    }
    this.state.lastPolicySequence = update.sequence; this.state.policy = update; this.saveState();
    this.appendAudit('policy-accepted', { sequence: update.sequence, digest, approvers: approvals.map(a => a.authority) });
    return { accepted: true, sequence: update.sequence, digest };
  }
  scanIntegrity() {
    const checked = this.verifySnapshot();
    if (!checked.valid) return this.enterSafeMode(`trusted-snapshot-${checked.reason}`);
    const protectedBytes = fs.readFileSync(this.paths.protected);
    const actual = sha256(protectedBytes);
    if (actual === checked.snapshot.digest) { this.appendAudit('integrity-ok', { digest: actual }); return { clean: true, digest: actual, mode: this.state.mode }; }
    const entropyScore = calculateEntropy(protectedBytes);
    const attackClassification = entropyScore > 7.5 ? 'RANSOMWARE_ENCRYPTION_ATTACK' : 'INTEGRITY_TAMPER';
    const sir = simulateSIR(0.85, 0.4, { population: 3, initialInfected: 1 });
    const predictedBlastRadius = sir.timeToSaturationSeconds ?? sir.horizonSeconds;
    const threatMetrics = {
      entropyScore: Number(entropyScore.toFixed(4)),
      sirBetaValue: sir.beta,
      sirGammaValue: sir.gamma,
      predictedBlastRadius,
      predictedAffectedNodes: sir.predictedBlastRadius,
      timeToImpactSeconds: predictedBlastRadius,
      attackClassification
    };
    this.state.lastThreatMetrics = threatMetrics;
    const evidence = { detectedAt: this.clock(), expected: checked.snapshot.digest, actual, ...threatMetrics, source: this.paths.protected };
    writeJsonAtomic(path.join(this.paths.quarantine, `${Date.now()}-tamper-evidence.json`), evidence);
    this.state.decoyState = 'DECOY_HONEYPOT'; this.state.quarantined = true; this.state.mode = 'quarantined'; this.saveState();
    this.appendAudit('tamper-detected', evidence); this.appendAudit('quarantine-applied', { simulated: true, actual });
    this.appendThreatFingerprint({
      kind: 'threat-fingerprint', fingerprintId: crypto.randomUUID(),
      payloadDigest: actual, commandPattern: attackClassification === 'RANSOMWARE_ENCRYPTION_ATTACK' ? 'ransomware-encryption' : 'integrity-tamper',
      observedAt: this.clock(), durationMs: 0, ...threatMetrics
    });
    this.state.antibodyPacket = this.antibodyGenerator.generateAntibody(actual);
    this.appendAudit('threat-antibody-created', {
      attackVectorHash: actual,
      blockedSignatureCount: 1,
      signatureVerified: verifyThreatAntibody(this.state.antibodyPacket, this.identity.publicKey)
    });
    this.saveState();
    return { clean: false, quarantined: true, expected: evidence.expected, actual, ...threatMetrics };
  }
  appendThreatFingerprint(fingerprint, eventType = 'threat-fingerprint') {
    const fingerprintSignature = sign(this.identity.privateKey, stable(fingerprint));
    const auditRecord = this.appendAudit(eventType, { ...fingerprint, fingerprintSignature });
    const filename = path.join(this.paths.quarantine, 'threat-fingerprint.json');
    const fingerprints = readJson(filename, []);
    fingerprints.push({ ...fingerprint, signature: fingerprintSignature, auditIndex: auditRecord.index });
    writeJsonAtomic(filename, fingerprints.slice(-1000));
    return auditRecord;
  }
  deceptionProbe(payload = {}, decoyResponse) {
    if (!this.state.quarantined || this.state.decoyState !== 'DECOY_HONEYPOT') throw new Error('node-not-in-deception-state');
    const raw = typeof payload.input === 'string' ? payload.input.slice(0, 512) : '';
    const normalized = raw.trim().toLowerCase();
    const commandPattern = /(?:token|secret|password|credential|private.?key)/i.test(raw) ? 'credential-probing'
      : /(?:curl|wget|http|https|connect|socket)/i.test(raw) ? 'network-probing'
        : /(?:cat|type|read|file|path|\/etc)/i.test(raw) ? 'file-probing'
          : /(?:help|status|version|ping)/i.test(normalized) ? 'service-discovery'
            : 'unknown-command';
    const threatMetrics = this.state.lastThreatMetrics || {
      entropyScore: Number(calculateEntropy(Buffer.from(raw)).toFixed(4)),
      sirBetaValue: 0.85,
      sirGammaValue: 0.4,
      predictedBlastRadius: 60,
      predictedAffectedNodes: 1,
      timeToImpactSeconds: 60,
      attackClassification: 'INTEGRITY_TAMPER'
    };
    const fingerprint = {
      kind: 'threat-fingerprint',
      fingerprintId: crypto.randomUUID(),
      payloadDigest: sha256(raw),
      commandPattern,
      observedAt: this.clock(),
      durationMs: Number.isSafeInteger(payload.durationMs) ? Math.max(0, Math.min(payload.durationMs, 60000)) : 0,
      ...threatMetrics
    };
    const record = this.appendThreatFingerprint(fingerprint, 'deception-probe');
    const fingerprintSignature = record.details.fingerprintSignature;
    const response = typeof decoyResponse === 'string' && decoyResponse.length <= 2048 ? decoyResponse : /(?:help|status|version)/i.test(raw)
      ? 'service: edge-router\\nstatus: healthy\\nversion: 4.2.1'
      : 'error: unknown command\\ntry: help';
    return { decoy: true, response, threatFingerprint: { ...fingerprint, signature: fingerprintSignature, digest: sha256(stable(fingerprint)), auditIndex: record.index } };
  }
  inoculate(packet, sourcePublicKey) {
    if (!verifyThreatAntibody(packet, sourcePublicKey)) throw new Error('threat-antibody-invalid');
    this.state.blockList = [...new Set([...(this.state.blockList || []), packet.vector, ...packet.blockedSignatures])].slice(-256);
    this.state.shieldState = 'INOCULATED_SHIELD';
    this.state.shieldAttackVectorHash = packet.vector;
    this.state.rateLimitPosture = 'elevated';
    this.saveState();
    this.appendAudit('gossip-inoculated', {
      sourceNode: packet.sourceNode,
      attackVectorHash: packet.vector,
      signatureVerified: true
    });
    const receipt = {
      receiptId: crypto.randomUUID(),
      node: this.name,
      antibodyId: packet.antibodyId,
      attackVectorHash: packet.vector,
      posture: this.state.shieldState,
      issuedAt: this.clock()
    };
    return { inoculated: true, posture: this.state.shieldState, receipt: { ...receipt, signature: sign(this.identity.privateKey, stable(receipt)), publicKey: this.identity.publicKey } };
  }
  threatAntibody() {
    const deceptionActive = this.state.quarantined || this.state.decoyState === 'DECOY_HONEYPOT';
    if (!this.state.antibodyPacket || !deceptionActive) throw new Error('threat-antibody-unavailable');
    return { packet: this.state.antibodyPacket, sourcePublicKey: this.identity.publicKey };
  }
  executeDryRunSandbox(candidatePolicy) {
    const verification = this.verifyAudit();
    if (!verification.valid) throw new Error('sandbox-audit-unverified');
    if (candidatePolicy?.sequence <= this.state.lastPolicySequence) throw new Error('sandbox-policy-sequence-not-monotonic');
    const result = executeDryRunSandbox(candidatePolicy, this.audit.slice(-50));
    const unsigned = { ...result, signerFingerprint: sha256(this.identity.publicKey) };
    return { ...unsigned, signature: sign(this.identity.privateKey, stable(unsigned)) };
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
      this.state.mode = 'trusted'; this.state.quarantined = false; this.state.decoyState = null; this.saveState(); this.appendAudit('rollback-verified', {
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
      privacyLedger: auditPrivacyLedger(this.audit),
      proof: verification.valid ? { version: 1, node: this.name, publicKey: this.identity.publicKey, entries: records.length, head: previousHash, records } : null
    };
  }
  status() { return { name: this.name, nodePublicKeyFingerprint: sha256(this.identity.publicKey).slice(0, 16), mode: this.state.mode, quarantined: this.state.quarantined, decoyState: this.state.decoyState, shieldState: this.state.shieldState, lastPolicySequence: this.state.lastPolicySequence, trustedSnapshot: this.state.trustedSnapshot, currentDigest: this.digestProtected(), audit: this.verifyAudit() }; }
}

module.exports = { SecurityNode, AntibodyGenerator, generateGossipAntibody, sha256, calculateEntropy, calculateShannonEntropy, simulateSIR, stable, createAuthorities, authorityTrust, makePolicyUpdate, approvePolicy, validatePolicyApprovals, policyDigest, verify, verifyThreatAntibody, verifyWebAuthnAssertion, parseWebAuthnRegistration, executeDryRunSandbox, auditPrivacyLedger, verifySanitizedAuditEvidence, verifySanitizedAuditEvidenceWithTrust, verifySnapshotArtifact, readJson, writeJsonAtomic, SNAPSHOT_VERSION };
