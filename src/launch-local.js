const path = require('node:path');
const { fork } = require('node:child_process');
const { startDashboard } = require('./dashboard');
const { announceAdminToken, initializeAuthorityTrust, resolveRuntimeTokens } = require('./runtime-config');

function resolveDashboardPort(environment) {
  const port = Number(environment.PORT || 7000);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be an integer between 1 and 65535');
  return port;
}

function launchLocal({ environment = process.env, logger = console } = {}) {
  const root = environment.RUNTIME_DIRECTORY || path.join(process.cwd(), '.runtime');
  const authorityDirectory = path.join(root, 'authorities'); const trustFile = path.join(root, 'authority-trust.json');
  const { serviceToken, adminToken } = resolveRuntimeTokens({ environment, root });
  initializeAuthorityTrust({ authorityDirectory, trustFile, environment });
  const ports = [7101, 7102, 7103]; const names = ['node-a', 'node-b', 'node-c']; const urls = ports.map(port => `http://127.0.0.1:${port}`);
  const children = names.map((name, i) => fork(path.join(__dirname, 'node-service.js'), [], { env: { ...environment, NODE_DATA_DIR: path.join(root, 'nodes', name), NODE_NAME: name, AUTHORITY_FILE: trustFile, PORT: String(ports[i]), HOST: '127.0.0.1', NODE_SERVICE_TOKEN: serviceToken } }));
  const dashboard = startDashboard({ port: resolveDashboardPort(environment), nodeUrls: urls, authorityDirectory, serviceToken, adminToken, operatorToken: environment.DASHBOARD_OPERATOR_TOKEN, host: environment.DASHBOARD_HOST || '127.0.0.1' });
  let stopping = false;
  const stop = () => { if (stopping) return; stopping = true; dashboard.close(); for (const child of children) child.kill('SIGTERM'); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  announceAdminToken({ environment, adminToken, logger });
  return { dashboard, root, children, stop };
}

if (require.main === module) launchLocal();
module.exports = { launchLocal, resolveDashboardPort };
