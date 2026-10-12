# Architecture

## Components

```text
Browser (local administrator + token)
        |
Dashboard :7000 (127.0.0.1 only)
        | signed control requests + service token, private network
  +-----+-----+-----+
  |           |     |
Node A :7101 Node B :7102 Node C :7103
  |           |     |
data/node-a  data/node-b  data/node-c
identity, policy, protected config, signed snapshots, audit chain, quarantine
```

Every `node-service.js` process instantiates exactly one `SecurityNode`, loaded from a distinct directory. Nodes do not share private keys, policy replay state, snapshot files, or audit chains. The dashboard only submits the same signed payload to all three; each node independently verifies the policy signatures and sequence.

## Policy protocol

1. The dashboard canonicalizes `{kind, sequence, issuedAt, payload}` using deterministic JSON.
2. Two of `authority-1..3` sign its SHA-256 digest with separate Ed25519 private keys.
3. A node rejects a request unless the digest matches, both approvers are distinct trusted names, both signatures verify, and `sequence` is greater than its stored `lastPolicySequence`.
4. The accepted update and sequence are atomically persisted before an audit entry is appended.

The three authority keys are only a local-development trust model. Nodes are provisioned with authority *public* keys. The coordinator's authority private keys are never sent to nodes and must never be committed.

## Integrity and recovery state machine

`trusted -> tampered -> quarantined -> recovered`

An integrity scan hashes `protected/config.json`. On mismatch it writes a forensic copy in `quarantine/`, marks the node quarantined, and emits audit events. Rollback verifies both the snapshot content hash and its Ed25519 signature before replacing the target. Invalid/missing recovery evidence puts the node in `safe-mode`; it never silently writes an unverified snapshot.

## Persistence and access boundaries

All state writes use write-to-temporary-file then rename. Node endpoints bind to loopback by default. In Compose, nodes are not published to the host; the dashboard alone is published to the host loopback. State-changing node requests require a shared, non-default service token. State-changing dashboard requests require a separate admin token. Tokens are environment-provided in containers and locally generated under ignored `.runtime/secrets` for development.
