const { boundedEvidence } = require('./ai-analyst');

const CATEGORIES = {
  'snapshot-created': 'snapshot',
  'policy-accepted': 'policy',
  'request-accepted': 'request',
  'integrity-ok': 'integrity',
  'tamper-detected': 'integrity',
  'quarantine-applied': 'quarantine',
  'recovery-attempted': 'recovery',
  'rollback-verified': 'recovery',
  'safe-mode-entered': 'trust',
  'tamper-simulated': 'demo'
};

function createTimeline(statuses, reports) {
  const evidence = boundedEvidence(statuses, reports);
  const events = [];
  const incomplete = [];
  const seenNodes = new Set();
  const seenEvents = new Set();

  for (const node of evidence.nodes) {
    if (seenNodes.has(node.node)) {
      incomplete.push({ node: node.node, reason: 'duplicate-node-report' });
      continue;
    }
    seenNodes.add(node.node);
    if (!node.auditVerified) {
      incomplete.push({ node: node.node, reason: 'audit-evidence-unverified' });
      continue;
    }
    if (node.omittedEventCount > 0) incomplete.push({ node: node.node, reason: 'older-events-omitted', count: node.omittedEventCount });
    for (const event of node.events) {
      if (seenEvents.has(event.id)) {
        incomplete.push({ node: node.node, reason: 'duplicate-event-id', eventId: event.id });
        continue;
      }
      seenEvents.add(event.id);
      const timestampValid = typeof event.timestamp === 'string' && Number.isFinite(Date.parse(event.timestamp));
      events.push({
        id: event.id,
        timestamp: timestampValid ? event.timestamp : null,
        timestampStatus: timestampValid ? 'verified' : 'missing-or-invalid',
        node: node.node,
        category: CATEGORIES[event.type] || 'audit',
        type: event.type,
        outcome: event.outcome,
        evidenceRef: event.id,
        evidence: event.evidence
      });
    }
  }

  for (const status of Array.isArray(statuses) ? statuses : []) {
    if (!seenNodes.has(status.name)) incomplete.push({ node: status.name, reason: 'audit-report-missing' });
    if (status.mode === 'offline') incomplete.push({ node: status.name, reason: 'node-unavailable' });
  }

  events.sort((left, right) => {
    if (left.timestamp && right.timestamp) return left.timestamp.localeCompare(right.timestamp) || left.node.localeCompare(right.node) || left.id.localeCompare(right.id);
    if (left.timestamp) return -1;
    if (right.timestamp) return 1;
    return left.node.localeCompare(right.node) || left.id.localeCompare(right.id);
  });

  return {
    events,
    incomplete,
    limitations: [
      'Dashboard authentication and policy rejections are counters, not events in the node audit chain, so they are not listed as timeline events.',
      'Only independently verified sanitized audit reports are included; node-held signing keys and self-asserted public-key trust retain their documented limitations.'
    ]
  };
}

module.exports = { createTimeline };
