const { verifyThreatAntibody } = require('./core');
const { TECHNIQUES } = require('./mitre');

// Read-only STIX 2.1-style export of signed threat antibodies. It only reads
// sanitized audit reports already produced by the nodes; it never modifies
// audit records, signed objects, or node state, and never exposes secrets,
// private keys, filesystem paths, or tokens.

function stixIdentity() {
  return {
    type: 'identity', spec_version: '2.1',
    id: 'identity--aegis-quorum',
    created: '2026-01-01T00:00:00.000Z', modified: '2026-01-01T00:00:00.000Z',
    name: 'AegisQuorum', identity_class: 'system'
  };
}

function antibodyToIndicator(node, event) {
  const vector = event?.evidence?.attackVectorHash;
  if (typeof vector !== 'string' || !/^[a-f0-9]{64}$/i.test(vector)) return null;
  return {
    type: 'indicator', spec_version: '2.1',
    id: `indicator--${vector.slice(0, 32)}`,
    created: event.at, modified: event.at,
    name: `AegisQuorum threat antibody (${node})`,
    description: 'Signed threat antibody gossiped by an AegisQuorum node after verified tamper detection.',
    pattern: `[file:hashes.'SHA-256' = '${vector.toLowerCase()}']`,
    pattern_type: 'stix',
    valid_from: event.at,
    labels: ['malicious-activity'],
    // The antibody packet is Ed25519-signed by the source node; the signature
    // is carried as an external reference marker, not embedded key material.
    external_references: [{ source_name: 'aegis-quorum-antibody', description: `signed-antibody:${node}` }]
  };
}

function attackPatternObjects() {
  return Object.values(TECHNIQUES).map(technique => ({
    type: 'attack-pattern', spec_version: '2.1',
    id: `attack-pattern--${technique.id.replace(/\./g, '-')}`,
    created: '2026-01-01T00:00:00.000Z', modified: '2026-01-01T00:00:00.000Z',
    name: technique.name,
    external_references: [{ source_name: 'mitre-attack', external_id: technique.id, url: technique.url }]
  }));
}

// reports: sanitized audit reports from the dashboard's auditReports().
// Returns a STIX 2.1-style bundle object (a fresh copy; inputs are not mutated).
function exportStix(reports) {
  const objects = [stixIdentity(), ...attackPatternObjects()];
  for (const report of Array.isArray(reports) ? reports : []) {
    const node = typeof report?.node === 'string' ? report.node : 'unknown';
    for (const event of Array.isArray(report?.events) ? report.events : []) {
      if (event.type !== 'threat-antibody-created') continue;
      const indicator = antibodyToIndicator(node, event);
      if (indicator) objects.push(indicator);
    }
  }
  return { type: 'bundle', id: 'bundle--aegis-quorum-threat-intel', objects };
}

module.exports = { exportStix };
