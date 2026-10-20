# Architecture

## Components

```text
Browser
  |
Dashboard :7000
  | authenticated admin operations + service token
Private Compose network
  +-----+-----+-----+
  |           |     |
Node A      Node B Node C
  |           |     |
Independent identity, protected file, snapshot, policy state, audit chain
```

Each node independently validates policy approvals, sequence numbers, trusted snapshots, and its own audit chain. The dashboard coordinates requests and reports live status; it is not the sole policy enforcement point.

The optional incident analyst runs inside the dashboard process. It independently verifies sanitized node audit exports, projects only bounded status and event fields, and submits that projection server-to-server to the Meta Model API. Its output is schema-validated and every evidence reference must resolve to a supplied event ID. The analyst has no operation or authorization interface.

## Policy and request protocol

1. The dashboard creates an unsigned proposal with the next observed monotonic sequence.
2. Separate authority keyholders sign the exact update digest with `npm run approve-policy`; the dashboard loads public trust keys and never creates approvals.
3. The dashboard validates the configured quorum and rejects stale proposals; each node independently validates distinct signatures and rejects stale or replayed sequences.
4. Quarantined or safe-mode nodes cannot apply sensitive policies.
5. Administrative mutations require `x-request-id` and `x-request-timestamp`; missing, stale, and duplicate requests are rejected by bounded replay caches at the dashboard and node services.
6. Dashboard mutations require a server-validated admin or separate operator token. Demonstration tampering requires the admin credential; client-supplied role headers are not trusted.
7. The dashboard serializes policy submissions and does not re-sequence signed proposals. Each node persists its accepted sequence, policy, and signed audit decision. Serialization is process-local, not distributed consensus.

## Integrity and recovery

Trusted snapshots bind node name and identity fingerprint to signed content metadata. Integrity scans compare the protected file digest with the current trusted snapshot. Confirmed changes produce sanitized evidence, quarantine the node at the application layer, and emit audit events. Rollback verifies the snapshot before replacement and verifies the restored digest afterward.

The dashboard exposes administrator-only, replay-protected incident actions (`scan`, `verify-snapshot`, and `recover`). Recovery is accepted only for a quarantined node with a valid trusted snapshot; the dashboard performs a separate post-restore integrity scan and reports success only if that check is clean. These actions require explicit operator confirmation in the dashboard. The recommendation text produced by the analyst is never executed.

`GET /api/timeline` builds a chronological view only from independently verified sanitized audit reports. Missing, duplicate, unavailable, or unverified data is reported as incomplete rather than inferred. Dashboard-side authorization and policy rejections are counters rather than node audit entries and therefore are not represented as timeline events.

## Audit and observability

Audit entries contain timestamps, event types, details, previous hashes, record hashes, and node signatures. The state file stores an audit witness that detects deletion. `GET /api/audit?download=1` includes a signed chain over the sanitized event projection; `npm run verify-audit -- <export.json>` independently verifies that downloaded evidence, while `npm run verify-audit -- <node-data-directory>` verifies the persisted node audit chain. Exported public keys are self-asserted unless their fingerprints are checked against an independently trusted identity. A hash chain alone does not guarantee immutability, and a node holding its signing key can rewrite and re-sign local history.

`npm run verify-recovery -- <sanitized-export.json> --node <node-name> --trusted-key <node-trust.json>` verifies the sanitized event chain against an independently provisioned node-bound Ed25519 trust record and checks the recorded restore/post-check relationship. This audit-only mode explicitly reports the snapshot artifact as unverified. Add `--snapshot <original-snapshot.json>` for full recovery verification: it compares the exact artifact-byte digest recorded in the signed `snapshot-created` event, verifies the existing canonical-object Ed25519 signature, binds the signer and node identity to the trust record, and separately checks the post-recovery digest. Snapshot bytes remain excluded from sanitized exports. See [recovery-verification.md](recovery-verification.md) for the format, trust provisioning, commands, and output guarantees.

`POST /api/incident-analysis` requires administrator authentication, fresh replay-protection headers, and a dedicated rate limit. `src/ai-analyst.js` excludes unverified reports, strips audit proof material and unknown fields, bounds evidence size, marks event data as untrusted in its prompt, validates structured output locally, and rejects references to nonexistent events. The API key is only read by the dashboard server from `MODEL_API_KEY`; local node child processes have dashboard and model credentials removed from their environment, and no key or raw audit proof is sent to the browser. Missing credentials and provider failures produce a deterministic fallback with explicit source and provider status. The Meta API receives the sanitized event projection outside the local service boundary; only enable this for evidence permitted by the deployment's data-handling policy.

## Deployment boundaries

Nodes bind only to the private Compose network and are not published to the host. The dashboard is published to loopback by default. Services run as the non-root Node user, drop Linux capabilities, set `no-new-privileges`, use read-only filesystems, and receive health checks. Dashboard code reads the public trust file, not authority identity files; however, the current Compose read-only volume mount still makes those private files accessible to a compromised dashboard process. The local demo stores generated signer keys in shared runtime state, so independent key custody and separation from dashboard operators remain operational requirements, not enforced by this MVP.

## Known limitations

The current transport uses a shared service token rather than mTLS. Quarantine is not host or firewall isolation. There is no external immutable audit sink, HSM, certificate lifecycle, Prometheus exposition endpoint, or automatic alert delivery.

The AI analyst is advisory: it can return incorrect or misleading conclusions, and structured output/evidence references do not establish factual correctness. Audit signing keys and the public-key trust model retain their existing limitations. Automated tests mock the Meta API boundary; live account access, model availability, provider terms, and live API behavior require separate operator verification.

For an end-to-end exercise isolated from runtime volumes and external model services, run `npm run demo-security`. It creates temporary credentials and node state, exercises signed quorum approval, replay rejection, tamper detection, quarantine, fallback analysis, confirmed recovery, post-recovery checks, and both independent evidence verifiers, then removes its temporary directory.
