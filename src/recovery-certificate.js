'use strict';
// Proof-carrying recovery — AegisQuorum's signature differentiator.
//
// A recovery certificate bundles the signed incident evidence for one node's
// completed tamper -> quarantine -> restore -> post-recovery-integrity cycle
// into a portable JSON document. The builder records exactly which
// verification classes were completed AT ISSUANCE and never upgrades a check
// that was not performed. The verifier recomputes every claim from the
// embedded sanitized audit evidence and fails closed on any mismatch,
// overclaim, or missing mandatory artifact.
//
// Verification boundaries stay explicit:
//   audit-only proof        = independent-trust-anchored hash chain + Ed25519
//                             record signatures + recorded recovery transition
//                             + post-recovery integrity. Requires an
//                             independent node trust record.
//   complete recovery proof = audit-only proof + original snapshot artifact
//                             bytes verified against the recorded digest and
//                             snapshot signature.
// A self-asserted embedded public key is never treated as an independent
// trust anchor; chain self-consistency is labelled 'verified-self-asserted',
// never 'verified'.
const { sha256, stable, verifySanitizedAuditEvidence } = require('./core');

const CERTIFICATE_FORMAT = 'aegis-recovery-certificate-v1';

function eventsOfType(events, type) {
  return (Array.isArray(events) ? events : []).map((event, index) => ({ event, index }))
    .filter(item => item.event?.type === type);
}
function eventId(node, event) { return `${node}:${event?.index}`; }
function hexDigest(value) { return typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value) ? value.toLowerCase() : null; }

// Locates the latest complete recovery cycle in a node's audit events:
// tamper-detected -> quarantine -> recovery-attempted -> rollback-verified
// -> integrity-ok (digest must match the recorded restored digest).
function extractRecoveryCycle(events) {
  const attempts = eventsOfType(events, 'recovery-attempted');
  const attempt = attempts.at(-1) || null;
  const later = attempt ? events.map((event, i) => ({ event, i })).filter(item => item.i > attempt.index) : [];
  const restore = attempt
    ? later.find(item => item.event.type === 'rollback-verified' && item.event.evidence?.id === attempt.event.evidence?.snapshotId) || null
    : null;
  const failure = attempt ? later.find(item => item.event.type === 'safe-mode-entered') || null : null;
  const postCheck = restore
    ? later.find(item => item.i > restore.i && item.event.type === 'integrity-ok' &&
        hexDigest(item.event.evidence?.digest) && item.event.evidence.digest === restore.event.evidence?.restored) || null
    : null;
  const beforeAttempt = attempt ? events.map((event, i) => ({ event, i })).filter(item => item.i < attempt.index).reverse() : [];
  const tamper = beforeAttempt.find(item => item.event.type === 'tamper-detected') || eventsOfType(events, 'tamper-detected').at(-1) || null;
  const fingerprint = tamper
    ? eventsOfType(events, 'threat-fingerprint').filter(item => item.index >= tamper.i && (!attempt || item.index < attempt.index)).at(-1) || null
    : null;
  const quarantine = tamper
    ? eventsOfType(events, 'quarantine-applied').filter(item => item.index >= tamper.i && (!attempt || item.index < attempt.index)).at(0) || null
    : null;
  const snapshotId = restore?.event.evidence?.id || attempt?.event.evidence?.snapshotId || null;
  const snapshotCreated = snapshotId
    ? eventsOfType(events, 'snapshot-created').filter(item => item.event.evidence?.id === snapshotId && (!restore || item.index < restore.i)).at(-1) || null
    : null;
  return { attempt, restore, failure, postCheck, tamper, fingerprint, quarantine, snapshotCreated, snapshotId };
}

// Build a certificate from a sanitized node audit report (GET /api/audit node
// shape: { node, nodePublicKeyFingerprint, verification, events, proof }).
// aiProvenance is optional: { at, providerMode, modelsInvoked, referencesValidated, verifiedEventIds }.
// The issuer has no independent node trust record or snapshot artifact, so
// issuance classifications are exactly: chain self-consistency, recorded
// recovery outcome, and recorded post-recovery integrity.
function buildRecoveryCertificate(report, { aiProvenance } = {}) {
  if (!report || typeof report.node !== 'string' || !Array.isArray(report.events) || !report.proof) {
    throw new Error('sanitized-node-report-required');
  }
  const node = report.node;
  const events = report.events;
  const cycle = extractRecoveryCycle(events);
  const chain = verifySanitizedAuditEvidence(report);
  const policyAccepted = eventsOfType(events, 'policy-accepted').at(-1) || null;

  const evidenceRefs = [cycle.tamper, cycle.fingerprint, cycle.quarantine, cycle.snapshotCreated, cycle.attempt, cycle.restore, cycle.postCheck]
    .filter(Boolean).map(item => eventId(node, item.event));
  const recoverySucceeded = Boolean(cycle.restore && cycle.postCheck);
  const postCheckMismatched = Boolean(cycle.restore && !cycle.postCheck &&
    eventsOfType(events, 'integrity-ok').some(item => item.index > cycle.restore.index));

  const governance = policyAccepted ? {
    policyEventId: eventId(node, policyAccepted.event),
    sequence: policyAccepted.event.evidence?.sequence ?? null,
    proposalDigest: hexDigest(policyAccepted.event.evidence?.digest),
    approvers: Array.isArray(policyAccepted.event.evidence?.approvers) ? policyAccepted.event.evidence.approvers : [],
    quorumNote: 'Approver identities and the proposal digest are recorded in the signed audit chain. Independent signature re-verification additionally requires the original approval payloads and an authority trust store.'
  } : null;

  const unsigned = {
    format: CERTIFICATE_FORMAT,
    issuedAt: new Date().toISOString(),
    node,
    nodePublicKeyFingerprint: report.nodePublicKeyFingerprint || null,
    claims: {
      tamperEvent: cycle.tamper ? {
        eventId: eventId(node, cycle.tamper.event), at: cycle.tamper.event.at,
        expectedDigest: hexDigest(cycle.tamper.event.evidence?.expected),
        actualDigest: hexDigest(cycle.tamper.event.evidence?.actual),
        attackClassification: cycle.tamper.event.evidence?.attackClassification || null
      } : null,
      threatFingerprint: cycle.fingerprint ? {
        eventId: eventId(node, cycle.fingerprint.event),
        digest: hexDigest(cycle.fingerprint.event.evidence?.payloadDigest),
        commandPattern: cycle.fingerprint.event.evidence?.commandPattern || null
      } : null,
      quarantineEvent: cycle.quarantine ? { eventId: eventId(node, cycle.quarantine.event), at: cycle.quarantine.event.at } : null,
      recoveryAttemptEvent: cycle.attempt ? { eventId: eventId(node, cycle.attempt.event), at: cycle.attempt.event.at } : null,
      snapshot: cycle.snapshotId ? {
        snapshotId: cycle.snapshotId,
        artifactDigest: hexDigest(cycle.snapshotCreated?.event.evidence?.artifactDigest),
        contentDigest: hexDigest(cycle.snapshotCreated?.event.evidence?.digest)
      } : null,
      restoreEvent: cycle.restore ? {
        eventId: eventId(node, cycle.restore.event), at: cycle.restore.event.at,
        restoredDigest: hexDigest(cycle.restore.event.evidence?.restored)
      } : null,
      postRecoveryEvent: cycle.postCheck ? {
        eventId: eventId(node, cycle.postCheck.event), at: cycle.postCheck.event.at,
        digest: hexDigest(cycle.postCheck.event.evidence?.digest)
      } : null,
      recoverySucceeded,
      evidenceRefs
    },
    governance,
    aiProvenance: aiProvenance ? {
      at: aiProvenance.at || null,
      providerMode: aiProvenance.providerMode || 'Deterministic Fallback',
      modelsInvoked: Array.isArray(aiProvenance.modelsInvoked) ? aiProvenance.modelsInvoked : [],
      referencesValidated: aiProvenance.referencesValidated === true,
      verifiedEventIds: Array.isArray(aiProvenance.verifiedEventIds) ? aiProvenance.verifiedEventIds : [],
      boundary: 'AI output is advisory only; it never authorized, signed, or executed any administrative action.'
    } : null,
    verification: {
      mode: 'audit-only',
      auditChain: chain.valid ? 'verified-self-asserted' : 'failed',
      auditSignatures: chain.valid ? 'verified-self-asserted' : 'failed',
      externalNodeIdentity: 'not-verified-no-independent-trust-record',
      snapshotArtifact: 'not-verified-artifact-not-supplied',
      approvalSignatures: governance ? 'audit-recorded-not-independently-reverified' : 'not-applicable',
      recoveryOperation: cycle.restore ? 'succeeded' : cycle.failure ? 'failed' : cycle.attempt ? 'outcome-not-recorded' : 'not-attempted',
      postRecoveryIntegrity: cycle.postCheck ? 'verified-clean' : cycle.restore ? (postCheckMismatched ? 'failed' : 'not-verified') : 'not-applicable',
      auditOnlyProof: 'not-verified',
      completeRecoveryProof: 'not-verified',
      proofNote: 'Independent proof requires offline verification with an independent node trust record (audit-only) plus the original snapshot artifact (complete). Use: npm run verify-recovery -- --certificate <this-file> --trusted-key <independent-node-trust.json> [--snapshot <original-snapshot.json>]'
    },
    evidence: { report }
  };
  return { ...unsigned, certificateDigest: sha256(stable(unsigned)) };
}

// Recompute and check every claim. Options:
//   trustedPublicKey — independently provisioned node trust record public key (PEM)
//   snapshotBytes    — original snapshot artifact bytes (Buffer)
// 'verified' is reserved for checks that pass against independent material;
// chain self-consistency without a trust anchor is 'verified-self-asserted'.
function verifyRecoveryCertificate(certificate, { trustedPublicKey, snapshotBytes } = {}) {
  const { createRecoveryVerificationReport } = require('./verify-recovery');
  const failedResult = (reason, node) => ({
    format: CERTIFICATE_FORMAT, node: node || 'unknown', consistent: false,
    verification: {
      mode: Buffer.isBuffer(snapshotBytes) ? 'full-recovery' : 'audit-only',
      auditChain: 'failed', auditSignatures: 'failed',
      externalNodeIdentity: 'not-verified', snapshotArtifact: 'not-verified',
      approvalSignatures: 'not-verified', recoveryOperation: 'not-verified',
      postRecoveryIntegrity: 'not-verified',
      auditOnlyProof: 'not-verified', completeRecoveryProof: 'not-verified',
      failureReason: reason
    }
  });
  if (!certificate || certificate.format !== CERTIFICATE_FORMAT || typeof certificate.node !== 'string') {
    return failedResult('certificate-format-invalid');
  }
  const report = certificate.evidence?.report;
  if (!report || report.node !== certificate.node || !Array.isArray(report.events) || !report.proof) {
    return failedResult('certificate-evidence-missing', certificate.node);
  }
  const { certificateDigest, ...unsignedCertificate } = certificate;
  if (certificateDigest !== sha256(stable(unsignedCertificate))) {
    return failedResult('certificate-digest-mismatch', certificate.node);
  }

  const verification = createRecoveryVerificationReport(report, { trustedPublicKey, snapshotBytes });
  const selfCheck = verifySanitizedAuditEvidence(report);
  // Claim consistency is computed against the recorded events directly; the
  // trust-gated report only decides the trust/artifact/full classifications.
  const cycle = extractRecoveryCycle(report.events);
  const events = report.events;
  const claims = certificate.claims || {};
  const eventById = id => {
    const [node, index] = String(id || '').split(':');
    return node === certificate.node && /^\d+$/.test(index) ? events[Number(index)] : undefined;
  };
  const consistency = [];
  const claimEvent = (label, ref, type) => {
    const event = ref?.eventId ? eventById(ref.eventId) : undefined;
    consistency.push({ label, ok: Boolean(event && event.type === type), eventId: ref?.eventId || null, expectedType: type, actualType: event?.type || null });
  };
  claimEvent('tamperEvent', claims.tamperEvent, 'tamper-detected');
  claimEvent('threatFingerprint', claims.threatFingerprint, 'threat-fingerprint');
  claimEvent('quarantineEvent', claims.quarantineEvent, 'quarantine-applied');
  claimEvent('recoveryAttemptEvent', claims.recoveryAttemptEvent, 'recovery-attempted');
  claimEvent('restoreEvent', claims.restoreEvent, 'rollback-verified');
  claimEvent('postRecoveryEvent', claims.postRecoveryEvent, 'integrity-ok');
  if (claims.snapshot?.snapshotId) {
    consistency.push({
      label: 'snapshot', ok: claims.snapshot.snapshotId === cycle.snapshotId,
      eventId: null, expectedType: claims.snapshot.snapshotId, actualType: cycle.snapshotId || 'missing'
    });
  }
  for (const ref of claims.evidenceRefs || []) {
    const event = eventById(ref);
    consistency.push({ label: 'evidenceRef', ok: Boolean(event), eventId: ref, expectedType: 'any-recorded-event', actualType: event?.type || 'missing' });
  }
  const recordedSuccess = Boolean(cycle.restore && cycle.postCheck);
  if (Boolean(claims.recoverySucceeded) !== recordedSuccess) {
    consistency.push({ label: 'recoverySucceeded', ok: false, eventId: null, expectedType: String(recordedSuccess), actualType: String(claims.recoverySucceeded) });
  }
  const consistent = consistency.every(item => item.ok);

  const trustedAudit = verification.auditVerification.valid === true;
  const auditChainStatus = trustedAudit ? 'verified' : selfCheck.valid ? 'verified-self-asserted' : 'failed';
  const approvalSignatures = certificate.governance
    ? 'audit-recorded-not-independently-reverified'
    : 'not-applicable';
  const overclaimed = (certificate.verification?.completeRecoveryProof === 'verified' && verification.fullRecoveryValid !== true)
    || certificate.verification?.auditOnlyProof === 'verified';
  const snapshotStatus = verification.snapshotAuthenticity.status === 'verified'
    ? 'verified'
    : verification.snapshotAuthenticity.status.startsWith('not-verified') ? verification.snapshotAuthenticity.status : 'failed';

  // 'verified' is reserved for independent-trust-anchored results.
  const auditOnlyProof = consistent && !overclaimed && trustedAudit && recordedSuccess;
  const completeProof = auditOnlyProof &&
    verification.trustAnchor.status === 'trusted' &&
    verification.snapshotAuthenticity.status === 'verified' &&
    verification.fullRecoveryValid === true;

  return {
    format: CERTIFICATE_FORMAT,
    node: certificate.node,
    certificateDigest: certificate.certificateDigest,
    consistent: consistent && !overclaimed,
    consistency,
    verification: {
      mode: verification.verificationMode,
      auditChain: auditChainStatus,
      auditSignatures: auditChainStatus,
      externalNodeIdentity: verification.trustAnchor.status === 'trusted' ? 'trusted' : `not-verified-${verification.trustAnchor.status}`,
      snapshotArtifact: snapshotStatus,
      approvalSignatures,
      recoveryOperation: cycle.restore ? 'succeeded' : cycle.failure ? 'failed' : cycle.attempt ? 'outcome-not-recorded' : 'not-attempted',
      postRecoveryIntegrity: cycle.postCheck ? 'verified-clean' : cycle.restore ? 'not-verified' : 'not-applicable',
      auditOnlyProof: auditOnlyProof ? 'verified' : 'not-verified',
      completeRecoveryProof: completeProof ? 'verified' : 'not-verified',
      ...(overclaimed ? { overclaim: 'certificate-claims-a-proof-level-the-evidence-does-not-support' } : {}),
      incompleteChecks: verification.incompleteChecks
    }
  };
}

module.exports = { CERTIFICATE_FORMAT, buildRecoveryCertificate, verifyRecoveryCertificate };
