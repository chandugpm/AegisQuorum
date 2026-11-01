const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  SecurityNode, createAuthorities, authorityTrust, makePolicyUpdate, approvePolicy,
  parseWebAuthnRegistration, verifyWebAuthnAssertion
} = require('../src/core');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function b64url(value) { return Buffer.from(value).toString('base64url'); }
function cborHead(major, length) {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 256) return Buffer.from([(major << 5) | 24, length]);
  const result = Buffer.alloc(3); result[0] = (major << 5) | 25; result.writeUInt16BE(length, 1); return result;
}
function encodeCbor(value) {
  if (Buffer.isBuffer(value)) return Buffer.concat([cborHead(2, value.length), value]);
  if (typeof value === 'string') { const bytes = Buffer.from(value); return Buffer.concat([cborHead(3, bytes.length), bytes]); }
  if (typeof value === 'number') return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  if (value instanceof Map) {
    const entries = [...value.entries()];
    return Buffer.concat([cborHead(5, entries.length), ...entries.flatMap(([key, nested]) => [encodeCbor(key), encodeCbor(nested)])]);
  }
  throw new Error('unsupported-cbor-test-value');
}
function authData(rpId, flags, count) {
  const data = Buffer.alloc(37);
  crypto.createHash('sha256').update(rpId).digest().copy(data, 0);
  data[32] = flags;
  data.writeUInt32BE(count, 33);
  return data;
}
function makeApproval(update, authority, privateKey, credentialId, signCount = 1) {
  const digest = require('../src/core').policyDigest(update);
  const challenge = Buffer.from(digest, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://security.example' }));
  const authenticatorData = authData('security.example', 0x05, signCount);
  const signed = Buffer.concat([authenticatorData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  return {
    algorithm: 'WebAuthn', authority, digest, credentialId,
    authenticatorData: b64url(authenticatorData),
    clientDataJSON: b64url(clientDataJSON),
    signature: b64url(crypto.sign('sha256', signed, privateKey))
  };
}

test('registration parser binds a none-attestation P-256 key to challenge, origin, RP ID, and credential ID', () => {
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const cose = new Map([
    [1, 2], [3, -7], [-1, 1],
    [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]
  ]);
  const credentialId = Buffer.from('credential-fixture');
  const attested = Buffer.concat([
    authData('security.example', 0x45, 0),
    Buffer.alloc(16),
    Buffer.from([credentialId.length >> 8, credentialId.length]),
    credentialId,
    encodeCbor(cose)
  ]);
  const registration = {
    credentialId: b64url(credentialId),
    clientDataJSON: b64url(Buffer.from(JSON.stringify({
      type: 'webauthn.create', challenge: 'challenge-value', origin: 'https://security.example'
    }))),
    attestationObject: b64url(encodeCbor(new Map([
      ['fmt', 'none'], ['attStmt', new Map()], ['authData', attested]
    ])))
  };
  const credential = parseWebAuthnRegistration(registration, {
    challenge: 'challenge-value', origin: 'https://security.example', rpId: 'security.example'
  });
  assert.equal(credential.credentialId, registration.credentialId);
  assert.equal(crypto.createPublicKey(credential.publicKey).asymmetricKeyType, 'ec');
  assert.throws(() => parseWebAuthnRegistration(registration, {
    challenge: 'wrong-challenge', origin: 'https://security.example', rpId: 'security.example'
  }), /client-data-invalid/);
});

test('passkey assertions verify and can satisfy policy quorum alongside existing CLI approvals', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-webauthn-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities'));
  const node = new SecurityNode({ directory: path.join(root, 'node'), name: 'node-a', trustedAuthorities: authorityTrust(authorities) });
  const credential = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKey = credential.publicKey.export({ type: 'spki', format: 'pem' });
  node.registerWebAuthnAuthority(authorities[0].name, { credentialId: 'credential-1', publicKey, signCount: 0 });
  const update = makePolicyUpdate(1, { enforcement: 'observe-only' });
  const passkeyApproval = makeApproval(update, authorities[0].name, credential.privateKey, 'credential-1');
  const proof = verifyWebAuthnAssertion(passkeyApproval, passkeyApproval.digest, {
    credentialId: 'credential-1', publicKey, signCount: 0
  }, { origin: 'https://security.example', rpId: 'security.example' });
  assert.equal(proof.valid, true);
  const result = node.applyPolicy(update, [passkeyApproval, approvePolicy(update, authorities[1])]);
  assert.equal(result.accepted, true);
  assert.equal(node.state.webauthnAuthorities[authorities[0].name].signCount, 1);
});

test('assertion verification rejects invalid origin, replayed counters, and changed proposal digests', () => {
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' });
  const update = makePolicyUpdate(3, { enforcement: 'observe-only' });
  const approval = makeApproval(update, 'authority-1', pair.privateKey, 'credential-1');
  const record = { credentialId: 'credential-1', publicKey, signCount: 1 };
  assert.equal(verifyWebAuthnAssertion(approval, approval.digest, record, { origin: 'https://evil.example', rpId: 'security.example', previousSignCount: 0 }).valid, false);
  assert.equal(verifyWebAuthnAssertion(approval, approval.digest, record, { origin: 'https://security.example', rpId: 'security.example', previousSignCount: 1 }).valid, false);
  assert.equal(verifyWebAuthnAssertion(approval, '0'.repeat(64), record, { origin: 'https://security.example', rpId: 'security.example', previousSignCount: 0 }).valid, false);
});
