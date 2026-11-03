#!/usr/bin/env node
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { sha256, verifySanitizedAuditEvidenceWithTrust, verifySnapshotArtifact } = require('./core');

function eventId(node, event) {
  return `${node}:${event.index}`;
}

function createRecoveryVerificationReport(report, {
  trustedPublicKey,
  trustAnchorStatus,
  snapshotBytes,
  snapshotArtifactError
} = {}) {
  const node = typeof report?.node === 'string' ? report.node : 'unknown';
  const auditResult = verifySanitizedAuditEvidenceWithTrust(report, trustedPublicKey);
  const trustStatus = auditResult.valid ? 'trusted' :
    auditResult.reason === 'trusted-key-fingerprint-mismatch' ? 'fingerprint-mismatch' :
      trustAnchorStatus || (trustedPublicKey ? 'invalid' : 'missing');
  const events = auditResult.valid ? report.events : [];
  const attempts = events.map((event, index) => ({ event, index }))
    .filter(item => item.event.type === 'recovery-attempted');
  const attempt = attempts.at(-1);
  const later = attempt ? events.map((event, index) => ({ event, index })).filter(item => item.index > attempt.index) : [];
  const recovery = later.find(item => item.event.type === 'rollback-verified' &&
    item.event.evidence?.id === attempt.event.evidence?.snapshotId);
  const failure = later.find(item => item.event.type === 'safe-mode-entered');
  const postCheck = recovery && later.find(item => item.index > recovery.index && item.event.type === 'integrity-ok');
  const before = attempt && events.slice(0, attempt.index).map((event, index) => ({ event, index })).reverse()
    .find(item => item.event.type === 'tamper-detected' || item.event.type === 'integrity-ok');
  const snapshotId = recovery?.event.evidence?.id || attempt?.event.evidence?.snapshotId || null;
  const snapshotCreated = snapshotId && events.slice(0, recovery?.index ?? attempt?.index ?? events.length)
    .map((event, index) => ({ event, index }))
    .reverse()
    .find(item => item.event.type === 'snapshot-created' && item.event.evidence?.id === snapshotId);
  const artifactRecord = snapshotCreated?.event.evidence;
  const postCheckValid = Boolean(postCheck &&
    /^[a-f0-9]{64}$/.test(recovery?.event.evidence?.restored || '') &&
    /^[a-f0-9]{64}$/.test(postCheck.event.evidence?.digest || '') &&
    postCheck.event.evidence?.digest === recovery.event.evidence.restored);
  const hasArtifactTrustRecord = Boolean(artifactRecord &&
    /^[a-f0-9]{64}$/.test(artifactRecord.artifactDigest || '') &&
    /^[a-f0-9]{64}$/.test(artifactRecord.signerFingerprint || '') &&
    artifactRecord.signatureAlgorithm === 'Ed25519' &&
    artifactRecord.snapshotSignatureVerified === true &&
    artifactRecord.snapshotContentDigestVerified === true &&
    artifactRecord.snapshotArtifactDigestVerified === true);
  const recoveryRecordConsistent = Boolean(recovery && hasArtifactTrustRecord &&
    recovery.event.evidence?.artifactDigest === artifactRecord.artifactDigest &&
    recovery.event.evidence?.signerFingerprint === artifactRecord.signerFingerprint &&
    recovery.event.evidence?.signatureAlgorithm === artifactRecord.signatureAlgorithm &&
    recovery.event.evidence?.snapshotSignatureVerified === true &&
    recovery.event.evidence?.snapshotContentDigestVerified === true &&
    recovery.event.evidence?.snapshotArtifactDigestVerified === true);
  const auditOnlyValid = auditResult.valid && (!attempt || Boolean(recovery && postCheckValid));
  const snapshotSupplied = Buffer.isBuffer(snapshotBytes) || Boolean(snapshotArtifactError);
  const verificationMode = snapshotSupplied ? 'full-recovery' : 'audit-only';
  let snapshotResult = {
    status: 'not-verified-artifact-not-supplied',
    artifactSupplied: false,
    snapshotId,
    expectedArtifactDigest: artifactRecord?.artifactDigest || null
  };
  if (snapshotSupplied) {
    if (!Buffer.isBuffer(snapshotBytes)) {
      snapshotResult = { status: 'failed', artifactSupplied: false, snapshotId, reason: snapshotArtifactError || 'snapshot-artifact-unavailable' };
    } else if (!auditResult.valid) {
      snapshotResult = { status: 'not-verified-audit-evidence-invalid', artifactSupplied: true, snapshotId };
    } else if (!attempt || !recovery || !hasArtifactTrustRecord) {
      snapshotResult = { status: 'failed', artifactSupplied: true, snapshotId, reason: 'recovery-snapshot-record-not-found' };
    } else if (!recoveryRecordConsistent) {
      snapshotResult = { status: 'failed', artifactSupplied: true, snapshotId, reason: 'snapshot-audit-metadata-mismatch' };
    } else {
      const checkedSnapshot = verifySnapshotArtifact(snapshotBytes, {
        nodeName: node,
        snapshotId,
        expectedArtifactDigest: artifactRecord.artifactDigest,
        trustedPublicKey
      });
      snapshotResult = {
        status: checkedSnapshot.valid ? 'verified' : 'failed',
        artifactSupplied: true,
        ...checkedSnapshot,
        auditSignerFingerprint: artifactRecord.signerFingerprint || null
      };
      if (checkedSnapshot.valid &&
          (checkedSnapshot.signerFingerprint !== artifactRecord.signerFingerprint ||
           checkedSnapshot.signatureAlgorithm !== artifactRecord.signatureAlgorithm ||
           checkedSnapshot.contentDigest !== artifactRecord.digest ||
           recovery.event.evidence?.restored !== checkedSnapshot.contentDigest ||
           recovery.event.evidence?.snapshotSignatureVerified !== true ||
           recovery.event.evidence?.snapshotContentDigestVerified !== true ||
           recovery.event.evidence?.snapshotArtifactDigestVerified !== true)) {
        snapshotResult.status = 'failed';
        snapshotResult.valid = false;
        snapshotResult.reason = 'snapshot-recovery-evidence-mismatch';
      }
    }
  }
  const fullRecoveryValid = verificationMode === 'full-recovery' && auditOnlyValid &&
    snapshotResult.status === 'verified' && postCheckValid && recoveryRecordConsistent;
  const incompleteChecks = [];
  if (trustStatus !== 'trusted') incompleteChecks.push(`Independent public-key trust anchor status: ${trustStatus}.`);
  if (!auditResult.valid) incompleteChecks.push(`Audit evidence verification failed: ${auditResult.reason || 'unverified'}.`);
  if (!attempt) incompleteChecks.push('No recovery attempt is recorded in the trusted audit evidence.');
  if (attempt && !before) incompleteChecks.push('No pre-recovery integrity result is recorded before the recovery attempt.');
  if (attempt && !recovery && !failure) incompleteChecks.push('The recovery attempt has no recorded success or failure outcome.');
  if (recovery && !recoveryRecordConsistent) incompleteChecks.push('Recovery and snapshot-creation records do not agree on artifact digest and signer metadata.');
  if (recovery && !hasArtifactTrustRecord) incompleteChecks.push('Legacy snapshot audit metadata does not record a raw artifact digest and signer key fingerprint.');
  if (recovery && !postCheck) incompleteChecks.push('No post-recovery integrity-ok event follows the recorded recovery.');
  else if (postCheck && !postCheckValid) incompleteChecks.push('The post-recovery integrity digest does not match the recorded restored digest.');
  if (!snapshotSupplied) incompleteChecks.push('The original snapshot artifact was not supplied; its raw-byte digest and signature were not independently verified.');
  else if (snapshotResult.status !== 'verified') incompleteChecks.push(`Snapshot authenticity verification failed or was unavailable: ${snapshotResult.reason || snapshotResult.status}.`);

  const recoverySucceeded = Boolean(recovery && postCheckValid);
  let finalTrustState = 'unknown';
  if (recoverySucceeded) {
    const transitionAfterPost = events.slice(postCheck.index + 1).reverse().find(event =>
      ['tamper-detected', 'quarantine-applied', 'safe-mode-entered', 'rollback-verified', 'integrity-ok'].includes(event.type));
    if (!transitionAfterPost || ['rollback-verified', 'integrity-ok'].includes(transitionAfterPost.type)) finalTrustState = 'trusted-at-event-time';
    else if (transitionAfterPost.type === 'safe-mode-entered') finalTrustState = 'safe-mode-at-event-time';
    else finalTrustState = 'quarantined-at-event-time';
  } else if (failure) finalTrustState = 'safe-mode-at-event-time';
  return {
    reportVersion: 2,
    node,
    verificationMode,
    trustAnchor: {
      status: trustStatus,
      algorithm: trustStatus === 'trusted' ? 'Ed25519' : null,
      fingerprint: auditResult.signerFingerprint || auditResult.trustedFingerprint || null
    },
    auditVerification: {
      status: auditResult.valid ? 'verified' : 'failed',
      valid: auditResult.valid,
      ...(auditResult.valid ? { entries: auditResult.entries, head: auditResult.head } :
        { reason: auditResult.reason, index: auditResult.index })
    },
    snapshotAuthenticity: snapshotResult,
    recoveryOperation: {
      status: recovery ? 'succeeded' : failure ? 'failed' : attempt ? 'outcome-not-recorded' : 'not-attempted',
      snapshotAuditMetadataConsistent: recovery ? recoveryRecordConsistent : null,
      attemptEventId: attempt ? eventId(node, attempt.event) : null,
      outcomeEventId: recovery ? eventId(node, recovery.event) : failure ? eventId(node, failure.event) : null,
      snapshotId,
      restoredDigest: recovery?.event.evidence?.restored || null,
      failureReason: failure?.event.evidence?.reason || null
    },
    preRecoveryIntegrity: {
      status: before ? before.event.type === 'tamper-detected' ? 'mismatch-detected' : 'clean' : 'not-established',
      eventId: before ? eventId(node, before.event) : null
    },
    postRecoveryIntegrity: {
      status: !attempt ? 'not-applicable' : !postCheck ? 'not-verified' : postCheckValid ? 'verified-clean' : 'failed',
      valid: attempt ? postCheckValid : null,
      eventId: postCheck ? eventId(node, postCheck.event) : null,
      digest: postCheck?.event.evidence?.digest || null,
      expectedDigest: recovery?.event.evidence?.restored || null
    },
    finalTrustState,
    auditOnlyValid,
    fullRecoveryValid,
    complete: verificationMode === 'full-recovery' ? fullRecoveryValid : auditOnlyValid,
    incompleteChecks
  };
}

function parseArguments(args) {
  const positional = [];
  const options = {};
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--help' || arg === '-h') return { help: true };
    if (['--node', '--trusted-key', '--snapshot', '--certificate'].includes(arg)) {
      if (options[arg] || !args[index + 1] || args[index + 1].startsWith('--')) throw new Error(`invalid-${arg}-argument`);
      options[arg] = args[++index];
    } else if (arg.startsWith('--')) {
      throw new Error('unknown-option');
    } else positional.push(arg);
  }
  if (options['--certificate'] && positional.length > 0) throw new Error('certificate-conflicts-with-audit-export');
  if (options['--certificate']) {
    return { certificatePath: options['--certificate'], trustedKeyPath: options['--trusted-key'], snapshotPath: options['--snapshot'] };
  }
  if (positional.length !== 1) throw new Error('audit-export-required');
  return { filename: positional[0], node: options['--node'], trustedKeyPath: options['--trusted-key'], snapshotPath: options['--snapshot'] };
}

function loadTrustedKey(filename, expectedNode) {
  if (!filename) return { status: 'missing' };
  try {
    const trustRecord = JSON.parse(fs.readFileSync(path.resolve(filename), 'utf8'));
    if (!trustRecord || trustRecord.format !== 'danms-node-trust-v1' ||
        typeof trustRecord.node !== 'string' || typeof trustRecord.publicKey !== 'string' ||
        typeof trustRecord.fingerprint !== 'string') return { status: 'invalid-trust-record' };
    if (trustRecord.node !== expectedNode) return { status: 'node-identity-mismatch' };
    if (trustRecord.algorithm !== 'Ed25519') return { status: 'unsupported-algorithm' };
    const pem = `${trustRecord.publicKey.trim().replace(/\r\n/g, '\n')}\n`;
    const parsed = crypto.createPublicKey(pem);
    if (parsed.asymmetricKeyType !== 'ed25519') return { status: 'unsupported-algorithm' };
    const fingerprint = sha256(pem);
    if (trustRecord.fingerprint !== fingerprint) return { status: 'fingerprint-mismatch', fingerprint };
    return { status: 'available', publicKey: pem, fingerprint };
  } catch {
    return { status: 'unavailable-or-invalid' };
  }
}

function usage() {
  return 'Usage: npm run verify-recovery -- <sanitized-audit-export.json> --node <node-name> --trusted-key <independent-node-trust.json> [--snapshot <original-snapshot.json>]\n   or: npm run verify-recovery -- --certificate <recovery-certificate.json> [--trusted-key <independent-node-trust.json>] [--snapshot <original-snapshot.json>]';
}

// Independently verifies a portable recovery certificate. Audit-only mode by
// default; supplying --trusted-key and --snapshot upgrades to full recovery
// proof. Exit 0 only when the requested proof level verifies.
function verifyCertificateFile(options) {
  // Lazy require: recovery-certificate depends on this module's report builder.
  const { verifyRecoveryCertificate, CERTIFICATE_FORMAT } = require('./recovery-certificate');
  let certificate;
  try { certificate = JSON.parse(fs.readFileSync(path.resolve(options.certificatePath), 'utf8')); }
  catch { console.error('certificate verification failed: invalid or unreadable certificate file'); return 1; }
  if (certificate?.format !== CERTIFICATE_FORMAT) {
    console.error('certificate verification failed: not an aegis recovery certificate');
    return 1;
  }
  const trust = loadTrustedKey(options.trustedKeyPath, certificate.node);
  let snapshotBytes;
  let snapshotArtifactError;
  if (options.snapshotPath) {
    try { snapshotBytes = fs.readFileSync(path.resolve(options.snapshotPath)); }
    catch { snapshotArtifactError = 'snapshot-artifact-missing-or-unreadable'; }
  }
  const result = verifyRecoveryCertificate(certificate, { trustedPublicKey: trust.publicKey, snapshotBytes });
  const verification = { ...result.verification };
  if (snapshotArtifactError) verification.snapshotArtifact = `failed-${snapshotArtifactError}`;
  if (snapshotArtifactError) verification.completeRecoveryProof = 'not-verified';
  process.stdout.write(`${JSON.stringify({ certificateVerification: { node: result.node, consistent: result.consistent, ...verification } })}\n`);
  const fullRequested = Boolean(options.snapshotPath);
  const valid = fullRequested
    ? verification.completeRecoveryProof === 'verified'
    : verification.auditOnlyProof === 'verified';
  return valid ? 0 : 1;
}

function main(args) {
  let options;
  try { options = parseArguments(args); }
  catch (error) {
    console.error(`${usage()}\nVerification failed: ${error.message}`);
    return 2;
  }
  if (options.help) {
    console.log(usage());
    return 0;
  }
  if (options.certificatePath) return verifyCertificateFile(options);
  try {
    const exported = JSON.parse(fs.readFileSync(path.resolve(options.filename), 'utf8'));
    const reports = Array.isArray(exported.nodes) ? exported.nodes : [exported];
    let selected = reports;
    if (options.node) selected = reports.filter(report => report?.node === options.node);
    else if (reports.length !== 1) throw new Error('select-one-node-with---node');
    if (selected.length !== 1) throw new Error('selected-node-not-found-or-ambiguous');
    const trust = loadTrustedKey(options.trustedKeyPath, selected[0]?.node);
    let snapshotBytes;
    let snapshotArtifactError;
    if (options.snapshotPath) {
      try { snapshotBytes = fs.readFileSync(path.resolve(options.snapshotPath)); }
      catch { snapshotArtifactError = 'snapshot-artifact-missing-or-unreadable'; }
    }
    const result = createRecoveryVerificationReport(selected[0], {
      trustedPublicKey: trust.publicKey,
      trustAnchorStatus: trust.status,
      snapshotBytes,
      snapshotArtifactError
    });
    process.stdout.write(`${JSON.stringify({ reports: [result] })}\n`);
    const valid = result.verificationMode === 'full-recovery' ? result.fullRecoveryValid : result.auditOnlyValid;
    return valid ? 0 : 1;
  } catch {
    console.error('recovery verification failed: invalid or unreadable sanitized audit export');
    return 1;
  }
}

module.exports = { createRecoveryVerificationReport, main, parseArguments };
if (require.main === module) process.exitCode = main(process.argv.slice(2));
