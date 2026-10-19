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

## Policy and request protocol

1. The dashboard creates a canonical policy update with a monotonic sequence.
2. The configured quorum, defaulting to 2 of 3, distinct authority keys sign its digest.
3. Each node validates the configured number of signatures independently and rejects stale or replayed sequences.
4. Quarantined or safe-mode nodes cannot apply sensitive policies.
5. Administrative HTTP requests may include `x-request-id` and `x-request-timestamp`; stale and duplicate requests are rejected by a bounded replay cache.
6. Dashboard mutations require a server-validated admin or separate operator token. Demonstration tampering requires the admin credential; client-supplied role headers are not trusted.

## Integrity and recovery

Trusted snapshots bind node name and identity fingerprint to signed content metadata. Integrity scans compare the protected file digest with the current trusted snapshot. Confirmed changes produce sanitized evidence, quarantine the node at the application layer, and emit audit events. Rollback verifies the snapshot before replacement and verifies the restored digest afterward.

## Audit and observability

Audit entries contain timestamps, event types, details, previous hashes, record hashes, and node signatures. The state file stores an audit witness that detects deletion. `GET /metrics` exposes numeric operational counters without payloads or credentials. `npm run verify-audit -- <node-data-directory>` verifies a persisted node audit chain independently of the running service.

## Deployment boundaries

Nodes bind only to the private Compose network and are not published to the host. The dashboard is published to loopback by default. Services run as the non-root Node user, drop Linux capabilities, set `no-new-privileges`, use read-only filesystems, and receive health checks. Runtime keys and tokens live in the ignored persistent volume or deployment secret manager; private keys must never be committed.

## Known limitations

The current transport uses a shared service token rather than mTLS. Quarantine is not host or firewall isolation. There is no external immutable audit sink, HSM, certificate lifecycle, Prometheus exposition endpoint, or automatic alert delivery.
