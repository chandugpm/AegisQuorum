const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { fork } = require('node:child_process');
const { readJson, writeJsonAtomic } = require('./core');
const { startDashboard } = require('./dashboard');
const { createVirtualNodes } = require('./virtual-node');
const { announceAdminToken, initializeAuthorityTrust, loadEnvironmentFile, resolveRuntimeTokens } = require('./runtime-config');

function resolveDashboardPort(environment) {
  const port = Number(environment.PORT || 7000);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be an integer between 1 and 65535');
  return port;
}

function createNodeEnvironment(environment, overrides) {
  const childEnvironment = { ...environment, ...overrides };
  for (const name of ['DASHBOARD_ADMIN_TOKEN', 'DASHBOARD_OPERATOR_TOKEN', 'MODEL_API_KEY', 'META_MODEL_ID']) delete childEnvironment[name];
  return childEnvironment;
}

// Trust-on-first-use provisioning: freeze each node's persisted Ed25519 public
// key as an independent danms-node-trust-v1 record, separate from the node's
// live state, so recovery-certificate verification can anchor to material the
// incident response itself never modifies. Re-provisioned only when missing
// or after a node identity rotation. Never logs or returns secret material.
async function provisionNodeTrustRecords({ root, names, logger = console } = {}) {
  const trustDirectory = path.join(root, 'node-trust');
  for (const name of names) {
    const identityFile = path.join(root, 'nodes', name, 'identity.json');
    let identity = readJson(identityFile, null);
    for (let attempt = 0; attempt < 100 && (!identity || typeof identity.publicKey !== 'string'); attempt++) {
      await new Promise(resolve => setTimeout(resolve, 100));
      identity = readJson(identityFile, null);
    }
    if (!identity || typeof identity.publicKey !== 'string') { logger.warn?.(`node trust record not provisioned for ${name}: node identity unavailable`); continue; }
    const publicKey = `${identity.publicKey.trim().replace(/\r\n/g, '\n')}\n`;
    const fingerprint = crypto.createHash('sha256').update(publicKey).digest('hex');
    const file = path.join(trustDirectory, `${name}-trust.json`);
    const existing = readJson(file, null);
    if (existing && existing.format === 'danms-node-trust-v1' && existing.node === name && existing.fingerprint === fingerprint) continue;
    fs.mkdirSync(trustDirectory, { recursive: true });
    writeJsonAtomic(file, { format: 'danms-node-trust-v1', node: name, algorithm: 'Ed25519', fingerprint, publicKey, provisionedAt: new Date().toISOString(), source: 'launch-local-trust-on-first-use' });
    logger.log?.(`Independent node trust record ${existing ? 're-provisioned after identity rotation' : 'provisioned'} for ${name}.`);
  }
}

function launchLocal({ environment = process.env, logger = console } = {}) {
  loadEnvironmentFile({ environment });
  const root = environment.RUNTIME_DIRECTORY || path.join(process.cwd(), '.runtime');
  const authorityDirectory = path.join(root, 'authorities'); const trustFile = path.join(root, 'authority-trust.json');
  const { serviceToken, adminToken } = resolveRuntimeTokens({ environment, root });
  initializeAuthorityTrust({ authorityDirectory, trustFile, environment });
  const names = ['node-a', 'node-b', 'node-c'];
  const virtualize = Boolean(environment.RENDER);
  const ports = [7101, 7102, 7103]; const urls = ports.map(port => `http://127.0.0.1:${port}`);
  const children = virtualize ? [] : names.map((name, i) => fork(path.join(__dirname, 'node-service.js'), [], { env: createNodeEnvironment(environment, { NODE_DATA_DIR: path.join(root, 'nodes', name), NODE_NAME: name, AUTHORITY_FILE: trustFile, PORT: String(ports[i]), HOST: '127.0.0.1', NODE_SERVICE_TOKEN: serviceToken, PEER_NODE_URLS: urls.filter((_, peerIndex) => peerIndex !== i).join(',') }) }));
  const virtualNodes = virtualize ? createVirtualNodes({ root, names, authorityFile: trustFile, quorum: Number(environment.POLICY_QUORUM || 2) }) : null;
  if (virtualize) logger.log?.('RENDER environment detected: nodes virtualized in-process; inter-node traffic is routed internally.');
  void provisionNodeTrustRecords({ root, names, logger }).catch(error => logger.warn?.(`node trust provisioning skipped: ${error?.message || error}`));
  const dashboard = startDashboard({ port: resolveDashboardPort(environment), nodeUrls: urls, authorityDirectory, authorityTrustFile: trustFile, serviceToken, adminToken, operatorToken: environment.DASHBOARD_OPERATOR_TOKEN || undefined, quorum: Number(environment.POLICY_QUORUM || 2), host: environment.DASHBOARD_HOST || '127.0.0.1', nodeTransport: virtualNodes ? (index, route, options) => virtualNodes.handleRequest(index, route, options) : undefined });
  let stopping = false;
  const stop = () => { if (stopping) return; stopping = true; dashboard.close(); for (const child of children) child.kill('SIGTERM'); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  announceAdminToken({ environment, adminToken, logger });
  return { dashboard, root, children, virtualNodes, stop };
}

if (require.main === module) launchLocal();
module.exports = { launchLocal, resolveDashboardPort, createNodeEnvironment };
