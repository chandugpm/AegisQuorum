const path = require('node:path');
const crypto = require('node:crypto');
const { fork } = require('node:child_process');
const { createAuthorities, authorityTrust, writeJsonAtomic } = require('./core');
const { startNode } = require('./node-service');
const { startDashboard } = require('./dashboard');

const root = process.env.RUNTIME_DIRECTORY || path.join(process.cwd(), '.runtime'); const secrets = path.join(root, 'secrets');
const authorityDirectory = path.join(root, 'authorities'); const trustFile = path.join(root, 'authority-trust.json');
const authorities = createAuthorities(authorityDirectory); writeJsonAtomic(trustFile, authorityTrust(authorities));
function token(name) { const file = path.join(secrets, name); const existing = require('node:fs').existsSync(file) ? require('node:fs').readFileSync(file, 'utf8').trim() : null; if (existing) return existing; const value = crypto.randomBytes(32).toString('base64url'); require('node:fs').mkdirSync(secrets, { recursive: true }); require('node:fs').writeFileSync(file, `${value}\n`, { mode: 0o600 }); return value; }
const serviceToken = token('node-service.token'); const adminToken = token('dashboard-admin.token');
const ports = [7101, 7102, 7103]; const names = ['node-a', 'node-b', 'node-c']; const urls = ports.map(port => `http://127.0.0.1:${port}`);
names.forEach((name, i) => fork(path.join(__dirname, 'node-service.js'), [], { env: { ...process.env, NODE_DATA_DIR: path.join(root, 'nodes', name), NODE_NAME: name, AUTHORITY_FILE: trustFile, PORT: String(ports[i]), HOST: '127.0.0.1', NODE_SERVICE_TOKEN: serviceToken } }));
startDashboard({ nodeUrls: urls, authorityDirectory, serviceToken, adminToken, host: process.env.DASHBOARD_HOST || '127.0.0.1' });
console.log(`Local dashboard administrator token: ${adminToken}`);
