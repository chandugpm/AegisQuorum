# Decentralized Network Security MVP

A local three-node security management MVP built with Node.js. It demonstrates signed policy updates, threshold approvals, integrity monitoring, tamper detection, quarantine, verified rollback, audit chains, and a dashboard.

## Requirements

- Node.js 20 or newer
- Docker and Docker Compose, for containerized execution

## Install

```bash
npm ci
```

## Run locally

Start the dashboard and three local node services:

```bash
npm start
```

The dashboard listens on `http://127.0.0.1:7000` by default. Development tokens are generated under `.runtime/secrets/` when environment variables are not provided.

To configure tokens explicitly, create a `.env` file or export:

```bash
DASHBOARD_ADMIN_TOKEN=replace-with-a-long-random-token
DASHBOARD_OPERATOR_TOKEN=replace-with-a-long-random-operator-token
NODE_SERVICE_TOKEN=replace-with-a-different-long-random-token
```

Tokens must contain at least 32 non-whitespace characters. Do not commit real tokens.

## Test

Run the complete test suite:

```bash
npm test
```

The tests cover:

- SHA-256 integrity verification
- Signed snapshot validation
- Tamper detection and quarantine
- Verified rollback and safe mode
- Audit-chain tampering detection
- Two-of-three policy approval
- HTTP authentication and rate limiting
- Runtime token handling
- Three-node integration behavior

## Docker Compose

Copy the example environment file and replace both values with separate random secrets:

```bash
Copy-Item .env.example .env
```

Build and start the stack:

```bash
docker compose up --build --pull always
```

The dashboard is exposed only on the local host at:

```text
http://127.0.0.1:7000
```

Stop the stack:

```bash
docker compose down
```

The `security-state` volume stores authority identities, trust material, node state, snapshots, quarantine evidence, and audit records.

## Docker image

Build the image directly:

```bash
docker build -t decentralized-network-security-mvp .
```

The image runs the local launcher by default:

```bash
docker run --rm \
  -p 127.0.0.1:7000:7000 \
  -e DASHBOARD_ADMIN_TOKEN=replace-with-a-long-random-token \
  -e NODE_SERVICE_TOKEN=replace-with-a-different-long-random-token \
  decentralized-network-security-mvp
```

For persistent state, mount a volume at `/app/.runtime`.

## Dashboard workflow

The dashboard provides:

- Read-only status for all three nodes
- Authenticated two-of-three policy submission
- A tamper, detection, quarantine, rollback, and post-recovery verification workflow
- Sanitized audit evidence download

Administrative actions require the dashboard administrator token entered in the browser. The token is kept in browser memory and is not persisted by the application.

The value entered in the dashboard must match `DASHBOARD_ADMIN_TOKEN` configured for the running dashboard. Docker Compose reads it from `.env`; Render does not receive the local `.env` file, so set `DASHBOARD_ADMIN_TOKEN` in the environment settings for the Render service using the same secret value. Do not substitute `NODE_SERVICE_TOKEN` or a development token generated under `.runtime/secrets/`. After changing a Render secret, redeploy/restart the service. The dashboard sends the entered value in the `x-dashboard-admin-token` request header.

## HTTP endpoints

### Dashboard

- `GET /` serves the dashboard.
- `GET /api/status` returns sanitized node status.
- `GET /api/audit` returns sanitized audit evidence.
- `POST /api/policy` submits a signed policy update.
- `POST /api/demo` runs the complete tamper-recovery workflow.

Authenticated dashboard requests require:

```text
x-dashboard-admin-token: <DASHBOARD_ADMIN_TOKEN>
# Or use the separate operator credential for policy operations:
x-dashboard-operator-token: <DASHBOARD_OPERATOR_TOKEN>
```

### Node services

- `GET /health` returns a health response.
- `GET /status` returns node status.
- `GET /audit` returns sanitized audit data.
- `GET /snapshot` verifies the current trusted snapshot.
- `POST /policy` applies an approved policy update.
- `POST /scan` scans protected content.
- `POST /rollback` restores the current trusted snapshot.
- `POST /simulate-tamper` modifies protected content for demonstration purposes.

Administrative node requests require:

```text
x-node-service-token: <NODE_SERVICE_TOKEN>
```

## Advanced security controls

The current implementation includes independently verified 2-of-3 policy approvals, durable sequence checks, application-level quarantine enforcement, request replay protection, server-side dashboard roles, numeric operational metrics, independent audit verification, and graceful local shutdown.

Administrative mutations can include:

```text
x-request-id: unique-request-id
x-request-timestamp: <Unix milliseconds>
x-dashboard-admin-token: <DASHBOARD_ADMIN_TOKEN>
x-dashboard-operator-token: <DASHBOARD_OPERATOR_TOKEN>
```

Requests with both replay-protection headers must use a fresh timestamp and unique request ID. Operators authenticated with the separate operator token may submit policies; only administrators authenticated with the admin token may run the destructive demonstration workflow. A client-supplied role header is never trusted.

Node and dashboard metrics are available at `GET /metrics`. They contain counters only and do not include credentials or request payloads.

Verify an audit chain independently:

```bash
npm run verify-audit -- .runtime/nodes/node-a
```

See [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md), and [docs/implementation-plan.md](docs/implementation-plan.md) for trust boundaries, residual risks, and incomplete controls.

## Security model

- Authority approvals use Ed25519 signatures.
- Policy updates require two distinct valid authority approvals.
- Policy sequence numbers prevent replay.
- Trusted snapshots contain signed metadata and SHA-256 content digests.
- Audit entries form a hash chain and are individually signed.
- Tampered content is quarantined and cannot be restored without snapshot verification.
- Failed verification or recovery enters safe mode.
- Dashboard audit responses remove local filesystem paths and private identity material.
- Administrative endpoints use token authentication and request rate limiting.

This project is an MVP and should not be treated as a production security control without additional operational review, key-management design, network hardening, monitoring, and failure testing. It does not claim mTLS, certificate rotation, external immutable logging, firewall-enforced quarantine, HSM-backed keys, or production multi-node consensus.

## Project layout

```text
src/
  core.js             Security nodes, snapshots, signatures, audit chains
  dashboard.js        Dashboard HTTP service and orchestration
  http-utils.js       Request parsing and rate limiting
  initialize.js       Authority trust initialization
  launch-local.js     Local three-node launcher
  node-service.js     Node HTTP service
  runtime-config.js   Token and authority configuration
public/
  index.html          Dashboard interface
test/
  *.test.js           Unit, integration, and hardening tests
Dockerfile             Container image definition
docker-compose.yml     Multi-service local deployment
```
