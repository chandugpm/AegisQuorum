# Decentralized Network Security MVP

A local three-node security management MVP built with Node.js. It demonstrates signed policy updates, threshold approvals, integrity monitoring, tamper detection, quarantine, verified rollback, audit chains, an evidence-grounded Meta Model API incident analyst, and a dashboard.

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

The tests use temporary directories, test keys, and mocked node/model API boundaries; they do not access production runtime volumes or call the live Meta API.

The tests cover:

- SHA-256 integrity verification
- Signed snapshot validation
- Tamper detection and quarantine
- Verified rollback and safe mode
- Audit-chain tampering detection
- Two-of-three policy approval
- HTTP authentication and rate limiting
- Meta analyst evidence sanitization, structured-output/reference validation, and provider-failure fallbacks
- Admin-only incident-analysis authentication, replay protection, and rate limiting
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
- Authenticated policy submission with independently signed two-of-three authority approvals
- A tamper, detection, quarantine, rollback, and post-recovery verification workflow
- Sanitized audit evidence download

Administrative actions require the dashboard administrator token entered in the browser. The token is kept in browser memory and is not persisted by the application.

The value entered in the dashboard must match `DASHBOARD_ADMIN_TOKEN` configured for the running dashboard. Docker Compose reads it from `.env`; Render does not receive the local `.env` file, so set `DASHBOARD_ADMIN_TOKEN` in the environment settings for the Render service using the same secret value. Do not substitute `NODE_SERVICE_TOKEN` or a development token generated under `.runtime/secrets/`. After changing a Render secret, redeploy/restart the service. The dashboard sends the entered value in the `x-dashboard-admin-token` request header.

### Evidence-grounded incident analysis

The dashboard's **Analyze incident** action sends an authenticated, replay-protected request to `POST /api/incident-analysis`. The dashboard independently verifies each sanitized audit export, then sends only a bounded projection of verified events and sanitized node status to the Meta Model API. Raw audit proofs, filesystem paths, private keys, service credentials, and the dashboard token are not included in the model request. Event values are untrusted data; the analyst cannot authorize or execute operations. The dashboard requires an administrator token for this endpoint and applies a separate request rate limit.

To enable live analysis, configure `MODEL_API_KEY` as a server-side secret and optionally set `META_MODEL_ID` (default `muse-spark-1.3`). Docker Compose reads these from `.env`; both Render manifests declare `MODEL_API_KEY` as a secret to be entered in the Render dashboard. Never put a real key in browser code, a committed file, or a client request. Without a key or when the provider is unavailable, the server returns a deterministic evidence-based fallback and reports its source/provider status in the UI. The live service status and analysis status are separate so that a provider error is not presented as live model output.

The model service receives sanitized incident evidence outside the deployment boundary. Review Meta's current API, data handling, account, and rate-limit terms before enabling it for operational incidents. Results are advisory, nondeterministic, and not a substitute for evidence verification or operator judgment. A valid schema and evidence references do not prove the model's conclusions are correct. No live Meta API call is part of the automated tests; tests use a local mocked API boundary.

Reproducible isolated demo:

1. Run the local stack with locally generated development credentials and no model key: `npm start`.
2. Enter the configured dashboard administrator token, then use **Run real tamper → recover workflow** to create local demo events.
3. Select **Analyze incident**. With no `MODEL_API_KEY`, the UI must identify its result as a deterministic fallback and show evidence references.
4. For live-provider validation, configure a real key only in the server environment, restart, and repeat. Verify the visible source says **Live Meta Model API**; do not treat the fallback as a live result.

### Independently approving a policy

Click **Create policy proposal**, save the displayed `update` object as `policy-proposal.json`, and have each authority holder sign that exact proposal with their protected identity file:

```powershell
npm run approve-policy -- .runtime\authorities\authority-1\identity.json .\policy-proposal.json
npm run approve-policy -- .runtime\authorities\authority-2\identity.json .\policy-proposal.json
```

Each command prints one approval object. Combine the required, distinct approvals into a JSON array, paste it into the dashboard approval box, and click **Apply approved policy**. With a quorum of 3, obtain all three approvals. The dashboard and each node validate signatures against public trust keys; stale proposals are rejected instead of being re-sequenced after signing. In real operations, authority identity files must be controlled independently and not shared with dashboard operators. The local MVP stores generated keys in its runtime state; although dashboard code loads only public trust keys, its current read-only Compose mount still exposes the shared runtime volume to that process. OS-level key custody is not enforced by this demo.

## HTTP endpoints

### Dashboard

- `GET /` serves the dashboard.
- `GET /api/status` returns sanitized node status.
- `GET /api/policy/proposal` creates the next unsigned proposal.
- `GET /api/audit` returns sanitized audit evidence.
- `POST /api/incident-analysis` returns a live or deterministic evidence-referenced incident analysis.
- `POST /api/policy` submits an update with independent authority approvals.
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

The current implementation includes independently signed and verified configurable 2-of-3 policy approvals, durable sequence checks, application-level quarantine enforcement, request replay protection, server-side dashboard roles, numeric operational metrics, independent audit verification, and graceful local shutdown.

Every administrative mutation must include fresh replay-protection headers:

```text
x-request-id: unique-request-id
x-request-timestamp: <Unix milliseconds>
x-dashboard-admin-token: <DASHBOARD_ADMIN_TOKEN>
x-dashboard-operator-token: <DASHBOARD_OPERATOR_TOKEN>
```

Requests use a fresh timestamp and unique request ID; missing, stale, or replayed headers are rejected. The dashboard forwards distinct stage IDs to the node services for the demo workflow. Operators authenticated with the separate operator token may submit policies; only administrators authenticated with the admin token may run the destructive demonstration workflow. A client-supplied role header is never trusted. Policy requests are serialized at the dashboard coordinator; if concurrent submissions use the same signed sequence, the stale proposal is rejected and must be re-approved.

Node and dashboard metrics are available at `GET /metrics`. They contain counters only and do not include credentials or request payloads.

Verify an audit chain independently:

```bash
npm run verify-audit -- .runtime/nodes/node-a
```

Verify a sanitized audit export downloaded from `GET /api/audit?download=1`:

```bash
npm run verify-audit -- .\audit-evidence.json
```

The exported evidence includes a signed chain over its sanitized event projection and detects edits, omissions, reordering, and appended records. Its embedded public key is self-asserted; for identity assurance, compare its fingerprint against a separately trusted node identity. Hash chains and node-held signing keys do not provide external immutability or protect against a compromised node that can rewrite and re-sign its own records.

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
  approve-policy.js   Offline authority approval CLI
  dashboard.js        Dashboard HTTP service and orchestration
  ai-analyst.js       Sanitized evidence projection and Meta API adapter
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
