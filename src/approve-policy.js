#!/usr/bin/env node
const { approvePolicy, readJson, verify } = require('./core');

const [identityFile, proposalFile, ...extra] = process.argv.slice(2);
if (!identityFile || !proposalFile || extra.length || identityFile === '--help' || identityFile === '-h') {
  console.log('Usage: npm run approve-policy -- <authority-identity.json> <policy-proposal.json>');
  process.exitCode = identityFile && (identityFile === '--help' || identityFile === '-h') ? 0 : 2;
} else {
  try {
    const identity = readJson(identityFile, null);
    const proposal = readJson(proposalFile, null);
    const update = proposal?.update || proposal;
    if (!identity || !/^authority-[1-3]$/.test(identity.name) ||
        typeof identity.publicKey !== 'string' || typeof identity.privateKey !== 'string' ||
        !update || update.kind !== 'policy-update' || !Number.isSafeInteger(update.sequence) || update.sequence < 1 ||
        !update.payload || typeof update.payload !== 'object' || Array.isArray(update.payload)) {
      throw new Error('invalid authority identity or policy proposal');
    }
    const approval = approvePolicy(update, identity);
    if (!verify(identity.publicKey, approval.digest, approval.signature)) throw new Error('authority signing key does not match its public key');
    process.stdout.write(`${JSON.stringify(approval)}\n`);
  } catch {
    console.error('policy approval failed: invalid identity, signing key, or proposal');
    process.exitCode = 1;
  }
}
