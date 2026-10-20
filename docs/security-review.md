# Security review (MVP)

## Dependencies

The application uses Node.js standard-library modules only (`crypto`, `http`, `fs`, `path`); there are no npm runtime dependencies, external AI APIs, or hosted AI runtimes. Keep the Node runtime patched. `npm audit` has no package dependency tree to examine.

## Authentication and authorization

- Dashboard mutations require `X-Dashboard-Admin-Token` and node mutations require a different `X-Node-Service-Token`.
- Equality checks use `timingSafeEqual` after length validation.
- Tokens are never rendered into the page or an API response.
- Policy proposals require distinct authority signatures; dashboard code loads only public trust keys and rejects unsigned, duplicate, invalid, and stale approvals.
- The dashboard has no user/account/RBAC system; this is a local administrator model, not multi-user authorization.

## Secrets and keys

- Generated local development identities and tokens live in `.runtime/`, which `.gitignore` excludes.
- Docker reads tokens from an untracked `.env`; production must inject them from its secret manager.
- Node identity keys are private disk files in this MVP. They need OS ACLs and production replacement with HSM/KMS-backed non-exportable keys and rotation/revocation procedures.
- The demo keeps generated authority identities in one runtime volume. Dashboard code reads public trust only, but its Compose mount still exposes the shared volume, and node containers also mount it. A compromised service with filesystem access could therefore read all authority private keys. Real deployments must separate signer keys from dashboard/node hosts and enforce independent custody.

## Persistence and recovery

- JSON persistence uses a sibling temporary file and rename; it is not a transactional database and is not protected from host-level rollback.
- Snapshot verification checks a content SHA-256 and node Ed25519 signature before writing. Bad evidence triggers safe mode.
- The audit log is signed and hash chained. Retain periodic signed audit-head checkpoints off-node to detect full log replacement/deletion.

## Network exposure

- Local launcher binds all services to `127.0.0.1`.
- Compose publishes only the dashboard on `127.0.0.1:7000`; node ports are on an internal network only.
- There is no TLS/mTLS in this local container MVP. Do not expose it through a public reverse proxy; use a private network plus authenticated TLS terminator and mTLS between components for a real deployment.
