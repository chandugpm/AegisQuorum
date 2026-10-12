# Decentralized Autonomous Network Management and Security System (MVP)

This is a local, testable security MVP—not a production network security appliance. It runs three independent Node.js node processes and a loopback-only dashboard.

## Security capabilities demonstrated

- Ed25519 node identities and independently persisted state.
- Canonically serialized, signed policy updates, accepted only with two distinct approvals from a three-member authority set.
- Per-node monotonic policy sequence replay protection.
- SHA-256 integrity scans of each node's protected configuration.
- Signed trusted snapshots, simulated quarantine, verified rollback, and safe mode when recovery evidence is invalid.
- Signed, hash-chained audit records; verification detects record modification, removal, reordering, or a bad signature.
- Dashboard actions require a local admin token. All listening sockets bind to `127.0.0.1`; Docker publishes only the dashboard to localhost.

## Quick start

Requires Node.js 20+ (tested with the host's Node.js 24 runtime).

```powershell
npm test
npm start
```

Open `http://127.0.0.1:7000`. The start command creates development identities and tokens under `.runtime/`, which is ignored by Git. Its terminal output shows the local dashboard token. Use **Run demo** to change the protected file, detect it, quarantine it, and roll it back.

## Docker

```powershell
Copy-Item .env.example .env
# Set DASHBOARD_ADMIN_TOKEN and NODE_SERVICE_TOKEN to unique 32+ character values.
docker compose up --build
```

The dashboard is deliberately published as `127.0.0.1:7000:7000`; node ports are internal to the Compose network and no node administration port is published.

## Limits and non-goals

- “Quarantine” is an application-level simulation; it does not alter host networking, firewall rules, processes, or files outside its per-node data directory.
- Private keys are development files. A real deployment needs a secret manager/HSM, key rotation, mTLS, durable encrypted storage, external monitoring, authorization integration, and independent review.
- The service intentionally has no internet-facing administration endpoint. Configure a private authenticated access layer before any remote use.
- Render configuration is included as a **private-preview scaffold** only. Do not deploy it without persistent storage and externally managed secrets; free/ephemeral service storage defeats safe recovery.

See [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md), and [docs/implementation-plan.md](docs/implementation-plan.md).
