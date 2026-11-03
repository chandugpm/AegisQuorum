# 2-Minute Demo Video Script

A timestamped, click-by-click script for the AegisQuorum hackathon submission video. Total runtime: ~2:00. Record at 1080p; the built-in tour (`Start 3-Min Video Tour` with "Record screen") covers the same beats in 2:50 if a longer cut is needed.

## Setup (before recording)

```bash
npm ci
npm start
```

Open `http://127.0.0.1:7000`. Have the dashboard maximized, dark theme visible.

## Script

| Time | Action | Narration |
| --- | --- | --- |
| 0:00-0:10 | Show the command-center dashboard; hover over the three-node mesh. | "AegisQuorum is an autonomous bio-digital immune system for a three-node edge cluster — signed quorum policies, integrity monitoring, and a hash-chained audit ledger." |
| 0:10-0:20 | Click **1-Click Load Dev Admin Token**. | "One click starts a local HttpOnly admin session. The token is never exposed to the page." |
| 0:20-0:30 | Click **⚡ 01 · TAMPER**. Watch Node-A turn red. | "We inject controlled tampering into Node-A's protected configuration." |
| 0:30-0:40 | Click **🦎 02 · CHAMELEON**. Show the decoy terminal response. | "The integrity scan detects the digest mismatch in milliseconds, quarantines the node, and turns it into a Chameleon decoy honeypot that fingerprints the attacker." |
| 0:40-0:55 | Click **🛡 03 · GOSSIP**. Show the inoculation receipts for Nodes B and C. | "The infected node signs a threat antibody with Ed25519 and gossips it to its peers, which raise an inoculated shield and block the attack vector." |
| 0:55-1:10 | Click **🧪 05 · SYNTHESIZE**, then **🔐 06 · QUORUM**. | "Verified audit evidence drives a candidate healing policy and a signed fifty-event dry-run certificate. Nothing applies without a human two-of-three passkey quorum — the AI is advisory only." |
| 1:10-1:25 | Click **♻ 07 · RECOVERY**. | "Recovery restores the signed trusted snapshot and only reports success after a clean post-rollback integrity scan." |
| 1:25-1:40 | Scroll to the **⚔ Red vs Blue** panel. Click **▶ Run Red Team**. | "Five attacks — tamper, replay, one-of-three approval, wrong token, and a decoy probe — are fired at isolated temporary nodes. The blue team blocks all five; every block links to signed audit event IDs." |
| 1:40-1:50 | Show the **Benchmarks** card (run `npm run benchmark` beforehand). | "MTTD and MTTR in the low milliseconds, sub-linear audit-chain verification, zero false positives over fifty clean scans." |
| 1:50-2:00 | Open the **Rule-4 Inspector** modal; close on the audit vault. | "Every claim is backed by an independently verifiable, Ed25519-signed audit chain. AegisQuorum — autonomous defense, human-gated healing." |

## Notes

- All clicks work without any cloud account or model API key; the analyst runs in deterministic fallback and says so on screen.
- The Red-vs-Blue run uses temporary directories and test keys only; live node state is never touched.
- If the passkey prompt cannot be shown on camera, use the offline CLI approval flow (`npm run approve-policy`) as the quorum beat — never fabricate a biometric approval.
