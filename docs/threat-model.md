# Threat model

## Assets

- Authority public keys and private signing keys.
- Per-node identity keys and protected configuration.
- Trusted snapshots, policy sequence state, and audit chains.
- Admin and node-service credentials.
- Sanitized audit evidence and operational status.

## Trust boundaries

1. The administrator browser is outside the dashboard process and may be compromised.
2. The dashboard is the coordinator, but every node independently validates policy signatures and sequence numbers.
3. Node services share a private Compose network; current transport authentication is a shared service token, not mTLS.
4. The runtime volume is persistent but not immutable. Host administrators and storage compromise remain in scope.
5. The Docker host, kernel, and orchestration control plane are trusted by this MVP.

## Attack scenarios and mitigations

| Scenario | Mitigation | Residual risk |
|---|---|---|
| One authority is compromised | Configurable quorum, defaulting to two distinct Ed25519 approvals | Quorum compromise can still authorize a policy |
| Dashboard or node filesystem compromise | Policy API requires independent signatures and service code reads public trust for validation | Compose shares the runtime volume containing all authority private keys with node containers and mounts it read-only in the dashboard; host/process compromise can expose all signers |
| Old policy is replayed | Durable per-node sequence validation | Full state rollback can reset anti-replay state |
| Administrative request replay | Mutations require unique request IDs and bounded timestamps; dashboard and nodes reject stale or reused IDs | Caches are process-local, not a distributed consensus log; durable policy sequence checks independently reject old policies |
| Unauthorized dashboard mutation | Separate server-validated admin/operator credentials; role headers are ignored | Token theft remains a local administrative compromise |
| Quarantined node approves policy | Sensitive policy application rejects non-trusted nodes | Application isolation is not network isolation |
| Protected file tampering | Snapshot digest comparison and forensic evidence | A node-host attacker can modify local state and keys |
| Invalid recovery artifact | Signed metadata, identity binding, content digest, exact serialized artifact digest in the signed audit event, external-key snapshot verification, and post-write verification | Key compromise defeats signature assurance; historical exports without artifact digests cannot support full verification |
| Audit deletion or reordering | Hash-linked signed records plus state witness; recovery CLI verifies exports using an independently provisioned, node-bound Ed25519 trust record | Local deletion is only tamper-evident; external retention is required for immutability, and the verifier trust store must be provisioned and protected independently |
| Node outage | Dashboard reports offline state and returns partial-operation failure | No automatic quorum failover or cross-node consensus is implemented |
| Unauthorized or unsafe incident response | `scan`, `verify-snapshot`, and `recover` require administrator auth and replay protection; recovery is limited to a quarantined node, a valid snapshot, and a clean post-recovery scan | A compromised administrator token can authorize these operations; quarantine remains application-level |
| Incomplete or misleading event history | Timeline includes only independently verified sanitized exports and explicitly reports unavailable or incomplete evidence | Dashboard authentication/policy rejections are not node audit events; event-time ordering does not prove causal ordering across nodes |
| Corrupted recovery evidence | Independent recovery CLI separates audit-only and full modes; full mode requires the original artifact, its signed audit digest, Ed25519 signature validation under a separately trusted key, and a matching post-recovery integrity event | Sanitized exports intentionally omit snapshot content; without a separately supplied artifact, snapshot authenticity is explicitly unverified. Trust depends on independently provisioned fingerprints and key custody |
| Credential leakage | Ignored runtime secrets, redacted audit exports, no secret metrics | Environment and host protections remain necessary |
| Malicious or prompt-injected audit values | Analyst uses only independently verified, bounded event projections; event values are explicitly treated as untrusted; output citations are checked against event IDs | Model interpretation can still be wrong; this is advisory and must not authorize operations |
| Model credential exposure or external evidence disclosure | API key remains server-side; API requests require admin auth, replay protection, and a dedicated rate limit; only sanitized audit events/status are sent | Model provider receives operational evidence; deployment operators must assess data-handling terms, account controls, and incident sensitivity |
| Container breakout | Non-root user, dropped capabilities, read-only filesystems, no-new-privileges | Host or kernel compromise remains out of scope |

## Residual risks and non-claims

This project does not implement mTLS, certificate rotation, HSM-backed keys, external immutable logging, firewall-enforced quarantine, Prometheus exposition, automated alert delivery, or production-grade multi-node consensus. Hash chaining provides tamper evidence, not automatic immutability. A successful test run is not a production-readiness claim.

The Meta Model API analyst is not a source of truth. It cannot prove attribution or intent, and a schema-valid response may still be inaccurate. Provider timeout, missing credentials, and other errors are surfaced as deterministic fallback statuses; no live API access is assumed by the test suite.

`npm run demo-security` exercises the end-to-end control flow using temporary directories, random in-memory request credentials, and no external model call. It is an integration demonstration, not a substitute for deployment-specific failure testing or immutable evidence retention.
