# Advanced implementation status

## Implemented controls

- Per-node independently validated configurable quorum policy enforcement, defaulting to 2-of-3 Ed25519 approvals.
- Durable monotonic policy sequence validation.
- Quarantine enforcement that rejects sensitive policy changes.
- Request IDs, bounded timestamps, and replay-cache rejection for administrative requests when security headers are supplied.
- Server-side administrator/operator role checks using separate credentials; client-supplied role headers are ignored.
- Node and dashboard operational counters at `/metrics`.
- Normalized URL routing so query strings do not bypass endpoint handling.
- Graceful local shutdown forwarding signals to child node processes.
- Independent audit verification command: `npm run verify-audit -- <node-data-directory>`.
- Container non-root execution, dropped capabilities, `no-new-privileges`, read-only service filesystems, health checks, and private node networking.
- Regression tests for replay protection, role primitives, quarantine enforcement, and metrics.

## Deliberately incomplete controls

- Mutual TLS and certificate rotation are not implemented. Current node authentication uses a shared service token over the Compose private network.
- Quarantine is application-level only. It changes node authorization state; it does not claim to enforce host, firewall, or orchestrator network isolation.
- Credential rotation and revocation APIs are not implemented. Rotation requires controlled environment update and coordinated restart.
- No external immutable audit sink, SIEM, HSM, or anti-rollback hardware is present.
- Metrics are JSON counters rather than a Prometheus exposition endpoint.
- Alerting is not automated; rule counters and audit events are available for integration.
- The dashboard has no complete pagination or filtering UI for historical audit records.

These boundaries are intentional. They prevent the project from claiming controls that are not present in the implementation.
