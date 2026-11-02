const path = require('node:path');
const { fork } = require('node:child_process');
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
  const dashboard = startDashboard({ port: resolveDashboardPort(environment), nodeUrls: urls, authorityDirectory, authorityTrustFile: trustFile, serviceToken, adminToken, operatorToken: environment.DASHBOARD_OPERATOR_TOKEN || undefined, quorum: Number(environment.POLICY_QUORUM || 2), host: environment.DASHBOARD_HOST || '127.0.0.1', nodeTransport: virtualNodes ? (index, route, options) => virtualNodes.handleRequest(index, route, options) : undefined });
  let stopping = false;
  const stop = () => { if (stopping) return; stopping = true; dashboard.close(); for (const child of children) child.kill('SIGTERM'); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  announceAdminToken({ environment, adminToken, logger });
  return { dashboard, root, children, virtualNodes, stop };
}

if (require.main === module) launchLocal();
module.exports = { launchLocal, resolveDashboardPort, createNodeEnvironment };
