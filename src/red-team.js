const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const { createAuthorities, authorityTrust, makePolicyUpdate, approvePolicy, writeJsonAtomic } = require('./core');
const { startNode } = require('./node-service');

// Red Team vs Blue Team simulation. Every attack runs against SEPARATE
// temporary node instances with test keys in a throwaway directory. It never
// touches .runtime, real authority keys, or the three running nodes' data.

function requestJson(url, method = 'GET', payload, token, security) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const raw = payload ? JSON.stringify(payload) : undefined;
    const headers = {};
    if (raw) { headers['content-type'] = 'application/json'; headers['content-length'] = Buffer.byteLength(raw); }
    if (token) headers['x-node-service-token'] = token;
    if (security) { headers['x-request-id'] = security.id; headers['x-request-timestamp'] = String(security.timestamp); }
    const req = http.request({ hostname: target.hostname, port: target.port, path: target.pathname, method, headers, timeout: 4000 }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { reject(new Error('node-invalid-json')); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('node-timeout')));
    if (raw) req.write(raw);
    req.end();
  });
}

async function waitFor(server) { if (!server.listening) await once(server, 'listening'); }
async function close(server) { if (server?.listening) await new Promise(resolve => server.close(resolve)); }

function eventIds(node, types) {
  return node.audit
    .map((record, index) => ({ record, index }))
    .filter(({ record }) => types.includes(record.type))
    .map(({ record, index }) => `${node.name}:${index}`);
}

async function runRedTeam({ logger = console } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-redteam-'));
  const serviceToken = crypto.randomBytes(32).toString('hex');
  const authorityDirectory = path.join(root, 'authorities');
  const trustFile = path.join(root, 'authority-trust.json');
  const authorities = createAuthorities(authorityDirectory);
  writeJsonAtomic(trustFile, authorityTrust(authorities));
  const nodes = ['node-a', 'node-b', 'node-c'].map(name => startNode({
    directory: path.join(root, name), name, authorityFile: trustFile, port: 0, serviceToken
  }));
  const results = [];
  try {
    await Promise.all(nodes.map(node => waitFor(node.server)));
    const urls = nodes.map(node => `http://127.0.0.1:${node.server.address().port}`);
    const [a, b] = nodes.map(node => node.node);
    const urlA = urls[0];

    // (a) Content tamper -> integrity scan detects and quarantines.
    {
      const start = Date.now();
      a.simulateTamper();
      const scan = a.scanIntegrity();
      const detectedAtMs = Date.now() - start;
      results.push({
        name: 'content-tamper', attempted: true, blocked: scan.quarantined === true,
        detectedAtMs, defenseLayer: 'integrity-scan+quarantine',
        auditEventIds: eventIds(a, ['tamper-detected', 'quarantine-applied'])
      });
    }

    // (b) Replayed request -> node replay cache rejects the duplicate ID.
    {
      const start = Date.now();
      const security = { id: 'redteam-replay-fixed', timestamp: Date.now() };
      const first = await requestJson(`${urlA}/scan`, 'POST', {}, serviceToken, security);
      const replay = await requestJson(`${urlA}/scan`, 'POST', {}, serviceToken, security);
      const blocked = first.status === 200 && replay.status === 409;
      results.push({
        name: 'replayed-request', attempted: true, blocked,
        detectedAtMs: Date.now() - start, defenseLayer: 'replay-cache',
        auditEventIds: eventIds(a, ['request-accepted'])
      });
    }

    // (c) Insufficient 1-of-3 approval -> node rejects below-quorum policy.
    {
      const start = Date.now();
      const update = makePolicyUpdate(2, { enforcement: 'observe-only' });
      let blocked = false;
      try { b.applyPolicy(update, [approvePolicy(update, authorities[0])]); }
      catch { blocked = true; }
      results.push({
        name: 'insufficient-approval', attempted: true, blocked,
        detectedAtMs: Date.now() - start, defenseLayer: 'quorum-validation',
        auditEventIds: eventIds(b, ['policy-accepted'])
      });
    }

    // (d) Wrong admin token -> node service rejects unauthenticated mutation.
    {
      const start = Date.now();
      const denied = await requestJson(`${urlA}/scan`, 'POST', {}, 'wrong-token', { id: 'redteam-badtoken-1', timestamp: Date.now() });
      results.push({
        name: 'wrong-admin-token', attempted: true, blocked: denied.status === 401,
        detectedAtMs: Date.now() - start, defenseLayer: 'service-authentication',
        auditEventIds: []
      });
    }

    // (e) Decoy honeypot probe -> quarantined node answers from the decoy.
    {
      const start = Date.now();
      let blocked = false; let auditEventIds = [];
      try {
        const probe = a.deceptionProbe({ input: 'help; show secrets', durationMs: 5 });
        blocked = probe.decoy === true;
        auditEventIds = eventIds(a, ['deception-probe']);
      } catch { blocked = false; }
      results.push({
        name: 'decoy-honeypot-probe', attempted: true, blocked,
        detectedAtMs: Date.now() - start, defenseLayer: 'chameleon-decoy',
        auditEventIds
      });
    }

    const blockedCount = results.filter(item => item.blocked).length;
    return {
      isolatedDirectory: 'temporary (removed at completion)',
      attacks: results,
      scoreboard: { attempted: results.length, blocked: blockedCount, succeeded: results.length - blockedCount }
    };
  } finally {
    await Promise.all(nodes.map(node => close(node.server)));
    fs.rmSync(root, { recursive: true, force: true });
  }
}

module.exports = { runRedTeam };
