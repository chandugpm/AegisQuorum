#!/usr/bin/env node
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { once } = require('node:events');
const { createAuthorities, authorityTrust, makePolicyUpdate, approvePolicy, writeJsonAtomic } = require('./core');
const { startNode } = require('./node-service');
const { startDashboard } = require('./dashboard');
const { createIncidentAnalyst } = require('./ai-analyst');

let sequence = 0;

function requestJson(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const raw = body === undefined ? undefined : JSON.stringify(body);
    const request = http.request({
      hostname: target.hostname,
      port: target.port,
      path: `${target.pathname}${target.search}`,
      method,
      headers: {
        ...(method === 'POST' ? { 'x-request-id': `security-demo-${++sequence}`, 'x-request-timestamp': String(Date.now()) } : {}),
        ...headers,
        ...(raw === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) })
      }
    }, response => {
      let data = '';
      response.on('data', chunk => { data += chunk; });
      response.on('end', () => {
        try { resolve({ status: response.statusCode, body: JSON.parse(data) }); }
        catch { reject(new Error('demo-received-invalid-json')); }
      });
    });
    request.on('error', reject);
    if (raw !== undefined) request.write(raw);
    request.end();
  });
}

async function waitFor(server) {
  if (!server.listening) await once(server, 'listening');
}

async function close(server) {
  if (server?.listening) await new Promise(resolve => server.close(resolve));
}

async function runDemo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-full-demo-'));
  const serviceToken = crypto.randomBytes(32).toString('hex');
  const adminToken = crypto.randomBytes(32).toString('hex');
  const authorityDirectory = path.join(root, 'authorities');
  const trustFile = path.join(root, 'authority-trust.json');
  const authorities = createAuthorities(authorityDirectory);
  writeJsonAtomic(trustFile, authorityTrust(authorities));
  const nodes = ['node-a', 'node-b', 'node-c'].map(name => startNode({
    directory: path.join(root, name),
    name,
    authorityFile: trustFile,
    port: 0,
    serviceToken
  }));
  let dashboard;

  try {
    await Promise.all(nodes.map(node => waitFor(node.server)));
    const nodeUrls = nodes.map(node => `http://127.0.0.1:${node.server.address().port}`);
    dashboard = startDashboard({
      port: 0,
      authorityDirectory,
      authorityTrustFile: trustFile,
      nodeUrls,
      serviceToken,
      adminToken,
      operatorToken: undefined,
      incidentAnalyst: createIncidentAnalyst({ apiKey: '' })
    });
    await waitFor(dashboard);
    const base = `http://127.0.0.1:${dashboard.address().port}`;
    const adminHeaders = { 'x-dashboard-admin-token': adminToken };

    const baseline = await requestJson(`${base}/api/status`);
    if (baseline.status !== 200 || baseline.body.nodes.some(node => node.mode !== 'trusted' || !node.audit.valid)) throw new Error('baseline-node-check-failed');

    const proposalResponse = await requestJson(`${base}/api/policy/proposal`);
    const update = proposalResponse.body.update;
    const approvals = authorities.slice(0, 2).map(authority => approvePolicy(update, authority));
    const policyHeaders = { ...adminHeaders, 'x-request-id': 'demo-policy-apply', 'x-request-timestamp': String(Date.now()) };
    const accepted = await requestJson(`${base}/api/policy`, { method: 'POST', headers: policyHeaders, body: { update, approvals } });
    const replayed = await requestJson(`${base}/api/policy`, { method: 'POST', headers: policyHeaders, body: { update, approvals } });
    if (accepted.status !== 200 || replayed.status !== 409) throw new Error('policy-or-replay-check-failed');

    nodes[0].node.simulateTamper();
    const scan = await requestJson(`${base}/api/incident-response`, { method: 'POST', headers: adminHeaders, body: { node: 'node-a', action: 'scan' } });
    if (scan.status !== 200 || scan.body.operationStatus !== 'quarantined') throw new Error(`tamper-detection-or-quarantine-failed:${scan.status}:${scan.body.operationStatus || scan.body.error || 'unknown'}`);

    const analysis = await requestJson(`${base}/api/incident-analysis`, { method: 'POST', headers: adminHeaders, body: {} });
    if (analysis.status !== 200 || analysis.body.analysisStatus !== 'fallback') throw new Error('deterministic-ai-fallback-failed');

    const recovery = await requestJson(`${base}/api/incident-response`, { method: 'POST', headers: adminHeaders, body: { node: 'node-a', action: 'recover' } });
    if (recovery.status !== 200 || recovery.body.operationStatus !== 'verified' || recovery.body.postRecoveryVerified !== true) throw new Error('post-recovery-verification-failed');

    const exported = await requestJson(`${base}/api/audit?download=1`);
    if (exported.status !== 200 || exported.body.nodes.some(report => !report.verification.valid)) throw new Error('audit-export-invalid');
    const evidenceFile = path.join(root, 'sanitized-audit-evidence.json');
    fs.writeFileSync(evidenceFile, JSON.stringify(exported.body));
    const trustedKeyFile = path.join(root, 'node-a-trust.json');
    const trustedPublicKey = nodes[0].node.identity.publicKey;
    fs.writeFileSync(trustedKeyFile, JSON.stringify({
      format: 'danms-node-trust-v1',
      node: 'node-a',
      algorithm: 'Ed25519',
      fingerprint: crypto.createHash('sha256').update(trustedPublicKey).digest('hex'),
      publicKey: trustedPublicKey
    }));
    const snapshotFile = path.join(nodes[0].node.paths.snapshots, `${nodes[0].node.status().trustedSnapshot}.json`);
    const auditVerification = spawnSync(process.execPath, [path.join(__dirname, 'verify-audit.js'), evidenceFile], { encoding: 'utf8' });
    const recoveryVerification = spawnSync(process.execPath, [
      path.join(__dirname, 'verify-recovery.js'), evidenceFile, '--node', 'node-a',
      '--trusted-key', trustedKeyFile, '--snapshot', snapshotFile
    ], { encoding: 'utf8' });
    if (auditVerification.status !== 0 || recoveryVerification.status !== 0) throw new Error('independent-verification-failed');
    const recoveryReports = JSON.parse(recoveryVerification.stdout).reports;
    if (!recoveryReports.find(report => report.node === 'node-a')?.fullRecoveryValid) throw new Error('recovery-report-incomplete');

    const timeline = await requestJson(`${base}/api/timeline`);
    const finalStatus = await requestJson(`${base}/api/status`);
    if (timeline.status !== 200 || finalStatus.body.nodes[0].mode !== 'trusted') throw new Error('final-evidence-check-failed');
    return {
      isolatedDirectory: 'temporary (removed at completion)',
      baseline: '3 trusted nodes; audit chains valid',
      policy: '2-of-3 signatures accepted',
      replay: 'duplicate policy request rejected',
      controlledTampering: 'detected; node-a quarantined',
      analyst: 'deterministic fallback; no live model call was made',
      humanApprovedRecovery: recovery.body.operationStatus,
      postRecoveryIntegrity: recovery.body.postRecoveryVerified ? 'verified clean' : 'failed',
      auditExportVerification: 'passed independently',
      recoveryReport: 'passed independently',
      timelineEvents: timeline.body.events.length,
      finalNodeAState: finalStatus.body.nodes[0].mode
    };
  } finally {
    await close(dashboard);
    await Promise.all(nodes.map(node => close(node.server)));
    fs.rmSync(root, { recursive: true, force: true });
  }
}

if (require.main === module) {
  runDemo().then(result => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)).catch(error => {
    console.error(`security demo failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { runDemo };
