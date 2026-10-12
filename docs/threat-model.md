# Threat model

| Threat | Control in this MVP | Residual risk |
|---|---|---|
| One compromised policy approver | 2-of-3 distinct Ed25519 approvals | Two compromised authorities can authorize a policy. |
| Replayed old valid policy | Per-node durable monotonic sequence | State rollback can reset sequence without storage anti-rollback hardware. |
| Modified policy/approval in transit | Canonical payload digest plus signature verification | No mTLS between containers; Compose network boundary is assumed. |
| Protected file tampering | SHA-256 monitoring plus signed baseline | An attacker controlling node private key/state can rewrite evidence. |
| Malicious rollback artifact | SHA-256 content check plus signed snapshot verification | Key compromise defeats signature assurance. |
| Audit deletion/modification/reordering | Previous-hash chain and per-entry node signature | Full state deletion is detectable only with external retained checkpoints. |
| Public admin takeover | Loopback-only binds, no published node port, token checks | Loopback malware/local users with token remain in scope. |
| Secret leakage | Ignored runtime directory, no default production secrets | Environment variables and local disk still need host protections. |
| Host/network impact | Simulated quarantine only | This does not contain a real host compromise. |

Out of scope: physical access, kernel/root compromise, DDoS, HSM/key custody, certificate lifecycle, SIEM transport, multi-region consensus, and production authorization integration.
