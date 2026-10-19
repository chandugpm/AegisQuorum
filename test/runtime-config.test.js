const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { announceAdminToken, initializeAuthorityTrust, resolveRuntimeTokens } = require('../src/runtime-config');
const { readJson, writeJsonAtomic } = require('../src/core');
const { resolveDashboardPort } = require('../src/launch-local');

const adminEnvironmentToken = 'a'.repeat(32);
const serviceEnvironmentToken = 'b'.repeat(32);
const adminFileToken = 'c'.repeat(32);
const serviceFileToken = 'd'.repeat(32);

function temporaryRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-runtime-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
function writeDevelopmentTokens(root) {
  const directory = path.join(root, 'secrets');
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'dashboard-admin.token'), `${adminFileToken}\n`, { mode: 0o600 });
  fs.writeFileSync(path.join(directory, 'node-service.token'), `${serviceFileToken}\n`, { mode: 0o600 });
}

test('configured environment tokens take precedence over persisted development tokens without rewriting them', t => {
  const root = temporaryRoot(t); writeDevelopmentTokens(root);
  const result = resolveRuntimeTokens({ root, environment: { DASHBOARD_ADMIN_TOKEN: adminEnvironmentToken, NODE_SERVICE_TOKEN: serviceEnvironmentToken } });
  assert.equal(result.adminToken, adminEnvironmentToken);
  assert.equal(result.serviceToken, serviceEnvironmentToken);
  assert.equal(fs.readFileSync(path.join(root, 'secrets', 'dashboard-admin.token'), 'utf8').trim(), adminFileToken);
  assert.equal(fs.readFileSync(path.join(root, 'secrets', 'node-service.token'), 'utf8').trim(), serviceFileToken);
});

test('development generates persisted strong tokens only when environment tokens are absent', t => {
  const root = temporaryRoot(t);
  const result = resolveRuntimeTokens({ root, environment: {} });
  assert.match(result.adminToken, /^[A-Za-z0-9_-]{32,}$/);
  assert.match(result.serviceToken, /^[A-Za-z0-9_-]{32,}$/);
  assert.equal(fs.readFileSync(path.join(root, 'secrets', 'dashboard-admin.token'), 'utf8').trim(), result.adminToken);
  assert.equal(fs.readFileSync(path.join(root, 'secrets', 'node-service.token'), 'utf8').trim(), result.serviceToken);
});

test('production ignores persisted development tokens and fails closed when either required token is missing or weak', t => {
  const root = temporaryRoot(t); writeDevelopmentTokens(root);
  assert.throws(() => resolveRuntimeTokens({ root, environment: { NODE_ENV: 'production' } }), /DASHBOARD_ADMIN_TOKEN is required/);
  assert.throws(() => resolveRuntimeTokens({ root, environment: { NODE_ENV: 'production', DASHBOARD_ADMIN_TOKEN: adminEnvironmentToken } }), /NODE_SERVICE_TOKEN is required/);
  assert.throws(() => resolveRuntimeTokens({ root, environment: { NODE_ENV: 'production', DASHBOARD_ADMIN_TOKEN: 'too-short', NODE_SERVICE_TOKEN: serviceEnvironmentToken } }), /DASHBOARD_ADMIN_TOKEN must be/);
  assert.throws(() => resolveRuntimeTokens({ root, environment: { NODE_ENV: 'production', DASHBOARD_ADMIN_TOKEN: adminEnvironmentToken, NODE_SERVICE_TOKEN: 'has a space but is long enough 123456789' } }), /NODE_SERVICE_TOKEN must be/);
});

test('production startup announcement never logs the administrator token', () => {
  const messages = [];
  announceAdminToken({ environment: { NODE_ENV: 'production' }, adminToken: adminEnvironmentToken, logger: { log: message => messages.push(message) } });
  assert.deepEqual(messages, []);
});

test('development startup announcement confirms configuration without logging the administrator token', () => {
  const messages = [];
  announceAdminToken({ environment: {}, adminToken: adminEnvironmentToken, logger: { log: message => messages.push(message) } });
  assert.equal(messages.length, 1);
  assert.equal(messages[0].includes(adminEnvironmentToken), false);
  assert.match(messages[0], /value withheld/);
});

test('existing authority identities and matching trust are validated without overwriting trust material', t => {
  const root = temporaryRoot(t); const authorityDirectory = path.join(root, 'authorities'); const trustFile = path.join(root, 'authority-trust.json');
  const first = initializeAuthorityTrust({ authorityDirectory, trustFile, environment: { NODE_ENV: 'production' } });
  assert.equal(first.initialized, true);
  const trust = readJson(trustFile);
  const preservedEncoding = `${JSON.stringify(trust)}\n\n`;
  fs.writeFileSync(trustFile, preservedEncoding, { mode: 0o600 });
  const second = initializeAuthorityTrust({ authorityDirectory, trustFile, environment: { NODE_ENV: 'production' } });
  assert.equal(second.initialized, false);
  assert.equal(fs.readFileSync(trustFile, 'utf8'), preservedEncoding, 'matching production trust file was not rewritten');
});

test('partial or mismatched authority state fails closed and is not overwritten', t => {
  const root = temporaryRoot(t); const authorityDirectory = path.join(root, 'authorities'); const trustFile = path.join(root, 'authority-trust.json');
  initializeAuthorityTrust({ authorityDirectory, trustFile, environment: { NODE_ENV: 'production' } });
  const mismatch = readJson(trustFile); mismatch['authority-1'] = 'untrusted-replacement'; writeJsonAtomic(trustFile, mismatch);
  const mismatchedRaw = fs.readFileSync(trustFile, 'utf8');
  assert.throws(() => initializeAuthorityTrust({ authorityDirectory, trustFile, environment: { NODE_ENV: 'production' } }), /does not match/);
  assert.equal(fs.readFileSync(trustFile, 'utf8'), mismatchedRaw);

  const partialRoot = path.join(root, 'partial'); const partialAuthorities = path.join(partialRoot, 'authorities'); const partialTrust = path.join(partialRoot, 'authority-trust.json');
  initializeAuthorityTrust({ authorityDirectory: partialAuthorities, trustFile: partialTrust, environment: {} });
  fs.rmSync(path.join(partialAuthorities, 'authority-3', 'identity.json'));
  assert.throws(() => initializeAuthorityTrust({ authorityDirectory: partialAuthorities, trustFile: partialTrust, environment: { NODE_ENV: 'production' } }), /incomplete/);
});

test('Render-provided dashboard port is honored and invalid ports fail before startup', () => {
  assert.equal(resolveDashboardPort({ PORT: '18765' }), 18765);
  assert.equal(resolveDashboardPort({}), 7000);
  assert.throws(() => resolveDashboardPort({ PORT: '0' }), /PORT must be/);
  assert.throws(() => resolveDashboardPort({ PORT: 'not-a-port' }), /PORT must be/);
});
