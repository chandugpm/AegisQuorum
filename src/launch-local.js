const path = require('node:path');
const { fork } = require('node:child_process');
const { startDashboard } = require('./dashboard');
const { announceAdminToken, initializeAuthorityTrust, resolveRuntimeTokens } = require('./runtime-config');

function launchLocal({ environment = process.env, logger = console } = {}) {
  const root = environment.RUNTIME_DIRECTORY || path.join(process.cwd(), '.runtime');
  const authorityDirectory = path.join(root, 'authorities'); const trustFile = path.join(root, 'authority-trust.json');
  const { serviceToken, adminToken } = resolveRuntimeTokens({ environment, root });
  initializeAuthorityTrust({ authorityDirectory, trustFile, environment });
  const ports = [7101, 7102, 7103]; const names = ['node-a', 'node-b', 'node-c']; const urls = ports.map(port => `http://127.0.0.1:${port}`);
  names.forEach((name, i) => fork(path.join(__dirname, 'node-service.js'), [], { env: { ...environment, NODE_DATA_DIR: path.join(root, 'nodes', name), NODE_NAME: name, AUTHORITY_FILE: trustFile, PORT: String(ports[i]), HOST: '127.0.0.1', NODE_SERVICE_TOKEN: serviceToken } }));
  const dashboard = startDashboard({ port: Number(environment.PORT || 7000), nodeUrls: urls, authorityDirectory, serviceToken, adminToken, host: environment.DASHBOARD_HOST || '127.0.0.1' });
  announceAdminToken({ environment, adminToken, logger });
  return { dashboard, root };
}

if (require.main === module) launchLocal();
module.exports = { launchLocal };
