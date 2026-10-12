const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { authorityTrust, createAuthorities, readJson, stable, writeJsonAtomic } = require('./core');

const MINIMUM_TOKEN_LENGTH = 32;
const AUTHORITY_NAMES = ['authority-1', 'authority-2', 'authority-3'];

function isProduction(environment = process.env) { return environment.NODE_ENV === 'production'; }

function validToken(token) {
  return typeof token === 'string' && token.length >= MINIMUM_TOKEN_LENGTH && token === token.trim() && !/\s/.test(token);
}

function requireStrongToken(name, token) {
  if (!validToken(token)) throw new Error(`${name} must be a non-whitespace token of at least ${MINIMUM_TOKEN_LENGTH} characters`);
  return token;
}

function resolveToken({ environment, root, environmentName, filename }) {
  const configured = environment[environmentName];
  if (configured !== undefined) return requireStrongToken(environmentName, configured);
  if (isProduction(environment)) throw new Error(`${environmentName} is required when NODE_ENV=production`);

  const file = path.join(root, 'secrets', filename);
  if (fs.existsSync(file)) return requireStrongToken(`${environmentName} development token file`, fs.readFileSync(file, 'utf8').trim());
  const generated = crypto.randomBytes(32).toString('base64url');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${generated}\n`, { mode: 0o600 });
  return generated;
}

function resolveRuntimeTokens({ environment = process.env, root }) {
  return {
    adminToken: resolveToken({ environment, root, environmentName: 'DASHBOARD_ADMIN_TOKEN', filename: 'dashboard-admin.token' }),
    serviceToken: resolveToken({ environment, root, environmentName: 'NODE_SERVICE_TOKEN', filename: 'node-service.token' })
  };
}

function readAuthorityIdentity(filename, expectedName) {
  const identity = readJson(filename, null);
  if (!identity || typeof identity.name !== 'string' || typeof identity.publicKey !== 'string' || typeof identity.privateKey !== 'string') throw new Error(`authority identity is invalid: ${filename}`);
  if (identity.name !== expectedName) throw new Error(`authority identity name does not match its trusted slot: ${filename}`);
  return identity;
}

function initializeAuthorityTrust({ authorityDirectory, trustFile, environment = process.env }) {
  const identityFiles = AUTHORITY_NAMES.map(name => path.join(authorityDirectory, name, 'identity.json'));
  const existingIdentities = identityFiles.filter(fs.existsSync).length;
  const trustExists = fs.existsSync(trustFile);

  if (existingIdentities === 0 && !trustExists) {
    const authorities = createAuthorities(authorityDirectory);
    const trust = authorityTrust(authorities);
    writeJsonAtomic(trustFile, trust);
    return { authorities, trust, initialized: true };
  }
  if (existingIdentities !== AUTHORITY_NAMES.length) throw new Error('authority identity state is incomplete; refusing to regenerate or replace trust material');
  if (!trustExists) {
    if (isProduction(environment)) throw new Error('authority trust file is missing; refusing to recreate production trust material');
    const authorities = identityFiles.map((filename, index) => readAuthorityIdentity(filename, AUTHORITY_NAMES[index]));
    const trust = authorityTrust(authorities);
    writeJsonAtomic(trustFile, trust);
    return { authorities, trust, initialized: true };
  }

  const authorities = identityFiles.map((filename, index) => readAuthorityIdentity(filename, AUTHORITY_NAMES[index]));
  let persistedTrust;
  try { persistedTrust = readJson(trustFile, null); } catch { throw new Error('authority trust file is unreadable'); }
  const derivedTrust = authorityTrust(authorities);
  if (!persistedTrust || stable(persistedTrust) !== stable(derivedTrust)) throw new Error('authority trust does not match persisted authority identities; refusing to overwrite it');
  return { authorities, trust: persistedTrust, initialized: false };
}

function announceAdminToken({ environment = process.env, adminToken, logger = console }) {
  if (!isProduction(environment)) logger.log(`Local development dashboard administrator token: ${adminToken}`);
}

module.exports = { MINIMUM_TOKEN_LENGTH, validToken, resolveRuntimeTokens, initializeAuthorityTrust, announceAdminToken, isProduction };
