// Static, truthful MITRE ATT&CK mappings for AegisQuorum defense events.
//
// Each mapping is attached AFTER validation, as a copy, from this file only.
// The AI analyst never executes actions and never emits these tags itself;
// they are appended to a copy of its output so signed/hashed audit objects
// are never modified. Only mappings with a defensible, literal relationship
// between the observed defense event and the ATT&CK technique are included.

const TECHNIQUES = {
  'T1565.001': {
    id: 'T1565.001',
    name: 'Data Manipulation: Stored Data Manipulation',
    tactic: 'Impact',
    url: 'https://attack.mitre.org/techniques/T1565/001/',
    // A protected-file integrity mismatch (tamper-detected) is literally an
    // adversary modifying stored data; the node detects the resulting digest change.
    rationale: 'Protected-file content tampering alters stored data, which the integrity scan detects as a digest mismatch.'
  },
    T1550: {
    id: 'T1550',
    name: 'Use Alternate Authentication Material',
    tactic: 'Defense Evasion, Lateral Movement',
    url: 'https://attack.mitre.org/techniques/T1550/',
    // A replayed request re-uses a previously valid request ID/timestamp,
    // i.e. re-presenting alternate/replayed authentication material.
    rationale: 'Replaying a previously authenticated request re-presents stale request credentials, matching reuse of alternate authentication material.'
  },
  T1078: {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Defense Evasion, Persistence, Privilege Escalation, Initial Access',
    url: 'https://attack.mitre.org/techniques/T1078/',
    // Supplying a wrong/forged admin token is an attempt to operate under a
    // valid account's authority without holding the real credential.
    rationale: 'Presenting an incorrect administrator token is an attempt to act under a valid account without the legitimate credential.'
  },
  M1053: {
    id: 'M1053',
    name: 'Data Backup',
    tactic: 'Mitigation',
    url: 'https://attack.mitre.org/mitigations/M1053/',
    // Verified rollback restores the protected file from a signed trusted
    // snapshot, which is the defensive data-backup/restore mitigation.
    rationale: 'Verified rollback restores protected state from a signed trusted snapshot, the defensive backup-and-restore mitigation.'
  }
};

// Maps an internal audit event type to the ATT&CK technique it truthfully
// corresponds to. Only events with a direct mapping are present.
const EVENT_TECHNIQUES = {
  'tamper-detected': ['T1565.001'],
  'replayed-request': ['T1550'],
  'stale-request': ['T1550'],
  'auth-failure': ['T1078'],
  'rollback-verified': ['M1053']
};

function technique(id) {
  return TECHNIQUES[id] || null;
}

// Returns a NEW array of technique objects for the given audit event type.
// Never mutates the source; returns an empty array when there is no mapping.
function techniquesForEvent(eventType) {
  const ids = EVENT_TECHNIQUES[eventType] || [];
  return ids.map(id => ({ ...TECHNIQUES[id] }));
}

// Attaches attackTechniques to a COPY of a timeline event. The input event
// object is not modified and no signed/hashed field is touched.
function withEventTechniques(event) {
  if (!event || typeof event !== 'object') return event;
  const attackTechniques = techniquesForEvent(event.type);
  if (!attackTechniques.length) return { ...event };
  return { ...event, attackTechniques };
}

// Attaches attackTechniques to a COPY of an analyst response, derived from the
// verified event types present in its cited evidence. Input is not modified.
function withAnalystTechniques(response, eventTypes = []) {
  if (!response || typeof response !== 'object') return response;
  const seen = new Set();
  for (const type of eventTypes) for (const id of EVENT_TECHNIQUES[type] || []) seen.add(id);
  const attackTechniques = [...seen].map(id => ({ ...TECHNIQUES[id] }));
  if (!attackTechniques.length) return { ...response };
  return { ...response, attackTechniques };
}

module.exports = { TECHNIQUES, EVENT_TECHNIQUES, technique, techniquesForEvent, withEventTechniques, withAnalystTechniques };
