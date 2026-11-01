# Meta Global AI Developer Hackathon Submission

## Decentralized Network Security MVP

This submission extends a three-node security-management scaffold with auditable AI-assisted deception, policy synthesis, passkey quorum approvals, multimodal privacy handling, peer threat inoculation, and a unified audit view. It is designed to demonstrate security properties locally without requiring external backend packages or live model credentials.

## Rule 4: New Work Only

| Pre-Existing Base MVP Scaffold | Newly Engineered During Meta Hackathon (Oct 26 - Nov 4) |
| --- | --- |
| Three-node Node.js service and dashboard | Chameleon decoy honeypot with signed threat fingerprints and model-aware synthetic responses |
| Ed25519 2-of-3 policy approvals, SHA-256 integrity monitoring, signed snapshots, quarantine, and verified rollback | Verified-event policy synthesis with an Ed25519-signed 50-event dry-run certificate |
| Replay-protected APIs and signed, sanitized audit chains | WebAuthn passkey registration/assertion paths for authority approvals |
| Deterministic analyst fallback and Meta API incident analysis | Visual/voice privacy forensics, verified-event correlation, cross-node gossip antibodies/receipts, and the 360-degree audit endpoint |
|  | **Feature 6: Bio-Digital Predictive Engine (SIR + Entropy)** with Shannon entropy classification, a bounded three-node SIR projection, verified-event Muse Spark predictions, automatically gossiped Ed25519 antibodies, 30-second replay freshness, and quorum-gated containment proposals |

The structured version is available at `GET /api/hackathon-manifest`.

## Demonstration Flow

1. Start the local service with `npm start`; no external API key is required.
2. Trigger a controlled tamper event and integrity scan. The node enters quarantine and activates `DECOY_HONEYPOT`.
3. Send a deception probe to `POST /api/deception/simulate`; inspect the signed threat fingerprint in node audit evidence.
4. Broadcast the generated antibody with `POST /api/gossip/broadcast`; verify signed receipts and peer `INOCULATED_SHIELD` posture.
5. Request `POST /api/policy/synthesize`; inspect the monotonic candidate policy and signed dry-run certificate.
6. Submit canvas/image and optional voice evidence to `POST /api/visual-forensics`; verify the redaction proof hash and event IDs against the signed node audit exports.
7. Inspect `GET /api/audit/360` and `GET /api/hackathon-manifest` for unified evidence and Rule-4 separation.
8. Use the Aegis pre-cog panel to inspect the entropy score, SIR infection/recovery curves, predicted peer paths, and impact time. Any remediation remains advisory until a distinct WebAuthn quorum approves the security policy; generated code is never executed.

All mutating dashboard endpoints require the existing admin/operator tokens and replay-protection headers. The WebAuthn ceremony uses challenge, origin, relying-party, signature, and authenticator-counter checks; the existing offline `npm run approve-policy` CLI remains supported.

## AI Provider Modes

- `MODEL_API_KEY` enables the existing Meta Model API path; `META_MODEL_ID` defaults to `muse-spark-1.3`.
- `BASETEN_API_KEY` enables Baseten Open-Weights inference. Chameleon deception invokes `meta-models/muse-spark-open-1026`; optional voice and SAM calls use `muse-voice-transcribe` and `sam-3.1`.
- Without provider credentials, or when live output cannot be bounded and validated, the system uses a deterministic evidence-grounded fallback.
- Every AI response includes `providerMode`, `modelsInvoked`, and `verifiedEventIds`. AI output is advisory and never authorizes or executes a security operation.

Live providers receive bounded, untrusted evidence outside the local deployment boundary. Operators must review provider data-handling and account terms before enabling them with real incident material. The automated test suite uses mocked provider boundaries and does not make live model calls.

## Verification

```bash
npm test
npm run demo-security
```

The tests use temporary state and keys. The backend adds no external package dependencies. The deployment remains an MVP: application quarantine is not network isolation, local signatures do not provide external immutability, and production deployments still need independently provisioned trust anchors, hardened key custody, network controls, and operational review.
