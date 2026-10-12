# Implementation plan and status

1. **Repository assessment and design** — complete: this document, architecture, threat model, and file layout.
2. **Independent nodes** — complete: `src/node-service.js` starts one node per process with a separate data directory.
3. **Trust protocol** — complete: Ed25519 identities, canonical signed updates, 2-of-3 approval verification, persisted sequence replay guard.
4. **Integrity and recovery** — complete: SHA-256, signed snapshots, simulated quarantine, verified rollback, safe mode, signed hash-chain audit.
5. **Dashboard** — complete: live polling and a real end-to-end demonstration action.
6. **Tests** — complete: unit/negative/failure-injection tests and a three-node HTTP integration test.
7. **Verification** — run `npm test` after implementation; results are reported only after execution.
8. **Security review** — documented in `docs/security-review.md`.
9. **Docker Compose** — complete: private network and localhost dashboard publishing.
10. **GitHub and Render config** — complete as safe configuration scaffolds.
11–12. **Deployment/remote verification** — intentionally not attempted until a Git repository, credentials, and non-ephemeral deployment environment are supplied.

## File layout

```text
src/core.js              security primitives and durable node state
src/node-service.js      one independent node HTTP process
src/dashboard.js         loopback dashboard coordinator
src/launch-local.js      local three-node launcher
public/index.html        dashboard interface
test/*.test.js           unit and integration/negative/failure tests
docker-compose.yml       four-service local stack
render.yaml              intentionally non-auto-deploy private-preview blueprint
```

## Capability verification isolation

`test/core-capabilities.test.js` creates a new `fs.mkdtempSync(path.join(os.tmpdir(), 'danms-capability-'))` directory for every test, creates throwaway Ed25519 authorities in that directory, and uses a synthetic protected configuration. Every temporary tree is registered for deletion with the Node test runner. It never opens `.runtime/`, uses real node identities, binds a network listener, or changes host configuration.

The focused tests cover SHA-256 mismatch detection, valid/modified/invalid/corrupted/missing snapshots, verified restore content and post-recovery scan, an actual filesystem restore failure, and signed audit-chain tampering. Run them with `node --test test/core-capabilities.test.js`; run the complete suite with `npm test`.
