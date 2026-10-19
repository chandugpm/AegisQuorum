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
| Invalid recovery artifact | Signed metadata, identity binding, digest, and post-write verification | Key compromise defeats signature assurance |
| Audit deletion or reordering | Hash-linked signed records plus state witness; sanitized exports carry an independently verifiable signed projection | Local deletion is only tamper-evident; external retention is required for immutability, and exported public keys require separate identity pinning |
| Node outage | Dashboard reports offline state and returns partial-operation failure | No automatic quorum failover or cross-node consensus is implemented |
| Credential leakage | Ignored runtime secrets, redacted audit exports, no secret metrics | Environment and host protections remain necessary |
| Container breakout | Non-root user, dropped capabilities, read-only filesystems, no-new-privileges | Host or kernel compromise remains out of scope |

## Residual risks and non-claims

This project does not implement mTLS, certificate rotation, HSM-backed keys, external immutable logging, firewall-enforced quarantine, Prometheus exposition, automated alert delivery, or production-grade multi-node consensus. Hash chaining provides tamper evidence, not automatic immutability. A successful test run is not a production-readiness claim.
