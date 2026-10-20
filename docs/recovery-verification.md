# Independent recovery verification

`npm run verify-recovery` supports two distinct verification modes. It never treats the public key embedded in an audit export as a trust anchor.

## Trust anchor

The verifier requires a separate public-only trust record for the selected node:

```json
{
  "format": "danms-node-trust-v1",
  "node": "node-a",
  "algorithm": "Ed25519",
  "fingerprint": "<64 lowercase hexadecimal characters>",
  "publicKey": "<SPKI PEM public key>"
}
```

Provision this record through the node enrollment or another independently trusted key-distribution process. Confirm the fingerprint through a separate trusted channel before placing the record in the verifier's protected trust store. The project fingerprints the normalized PEM string: convert CRLF to LF, trim surrounding whitespace, add one final LF, then compute SHA-256 over its UTF-8 bytes. The trust record must name the selected node, declare Ed25519, and contain a fingerprint matching its public key. The verifier also requires the export's public-key fingerprint to match this independent record.

Do not copy `proof.publicKey` from the evidence export into a trust record and call that independent trust. A trust record copied from unverified evidence provides no identity assurance. Protect the trust store and expected fingerprints using the verifier operator's normal key-custody procedures. The file itself is a trust root; this CLI does not provide a remote certificate authority, hardware key store, or key-revocation service.

## Audit-only mode

Given an audit export containing a single node:

```bash
npm run verify-recovery -- ./audit-evidence.json --node node-a --trusted-key ./trust/node-a.json
```

For a multi-node export, `--node` is required. Audit-only mode independently checks:

- The sanitized event list and its signed/hash-linked proof records.
- The Ed25519 signatures against the public key in the independent trust record.
- For a recorded recovery, a matching `rollback-verified` event and a later `integrity-ok` event whose digest equals the recorded restored digest.

The result identifies `verificationMode: "audit-only"`, the trust-anchor and audit statuses, and the separate post-recovery integrity status. Snapshot authenticity is `not-verified-artifact-not-supplied`. Exit code is zero only when the trusted audit proof is valid and any recorded recovery has a consistent successful restore and post-check. A valid audit-only result does not prove the original snapshot was authentic.

## Full recovery mode

Obtain the exact original snapshot artifact from the node's local snapshot store or a separately retained recovery artifact. Do not reconstruct it from the sanitized export. The snapshot file is named `<snapshotId>.json`; use the ID reported by the audit events:

```bash
npm run verify-recovery -- ./audit-evidence.json --node node-a --trusted-key ./trust/node-a.json --snapshot ./node-a-snapshot.json
```

Full mode additionally verifies:

1. The SHA-256 digest of the exact supplied file bytes equals `artifactDigest` in the trusted `snapshot-created` event.
2. The supported snapshot format, node identity, Ed25519 signer fingerprint, content encoding, and SHA-256 digest of the decoded protected content.
3. The snapshot signature using the independently trusted Ed25519 public key.
4. Agreement between snapshot creation metadata, the signed restore event, and the recorded post-recovery integrity digest.

The CLI exits nonzero when any required full-mode check fails or is unavailable. Its JSON output keeps `auditVerification`, `snapshotAuthenticity`, and `postRecoveryIntegrity` separate; `fullRecoveryValid` is true only when all required checks pass.

## Snapshot signature format

New snapshots use format version 3. The Ed25519 signature covers the stable canonical JSON representation of the snapshot object with the `signature` field excluded. That signed object contains the base64 snapshot content, its content SHA-256 digest, node name, node-key fingerprint, creation time, reason, and `signatureAlgorithm: "Ed25519"`. The signature is not over the raw JSON file bytes.

After writing the JSON artifact, the node re-reads and verifies it, hashes the exact file bytes (including serialization whitespace and trailing newline), and records that digest, snapshot ID, signature algorithm, signer fingerprint, and explicit signature/content/artifact verification results in its signed audit event. The restore event records the same artifact digest and signer metadata and the verification results before recovery is reported. This separates raw artifact identity from the existing canonical-object signature without changing the snapshot signing algorithm. Version 2 snapshots remain readable by the node and can be independently signature-checked when matching audit metadata exists. Historical exports created before raw artifact hashes and verification results were recorded can still support audit-only verification, but cannot establish full artifact verification.

Neither verification mode proves that the node's own signing key was uncompromised when it created the events. A compromised node can create misleading events; a hash chain alone does not provide immutable storage. Full verification proves that the supplied artifact matches the signed audit digest and that its canonical snapshot signature verifies under the independently provisioned node key. It does not prove the safety or correctness of the snapshot's configuration.

## Result interpretation

| Result | Meaning |
|---|---|
| `auditVerification.status: "verified"` | Exported audit records and signatures validate under the external trust record. |
| `snapshotAuthenticity.status: "not-verified-artifact-not-supplied"` | Audit-only result; the original artifact's raw bytes and signature were not checked by the verifier. |
| `snapshotAuthenticity.status: "verified"` | Supplied artifact matches its signed audit digest and verifies as a supported snapshot under the trusted Ed25519 key. |
| `postRecoveryIntegrity.status: "verified-clean"` | A later signed integrity event reports the same digest as the restore event. |
| `fullRecoveryValid: true` | All audit, trust, artifact, signature, restore-association, and post-check requirements passed. |

Audit records authenticate what the node recorded; they are not a substitute for external immutable retention or independent operational observations.

## Validation record

On 2026-10-20, `npm test` completed with **67 passing tests and 0 failures**. The recovery tests exercise both CLI modes and rejection of tampered audit records, altered/missing snapshot artifacts, invalid snapshot signatures, absent or mismatched trust anchors, unsupported algorithms, and failed post-recovery integrity. `npm run demo-security` also completed successfully using temporary keys, state, and a supplied original snapshot; it made no live model API call.
