#!/usr/bin/env node
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createAuthorities, authorityTrust, makePolicyUpdate, approvePolicy, writeJsonAtomic } = require('../src/core');
const { startNode } = require('../src/node-service');
const { once } = require('node:events');

// Performance benchmark. Uses temporary directories and test keys only; it
// never touches .runtime, real authority keys, or the running nodes' data.
// Writes benchmark-results.json (no secrets) and prints a markdown table.

async function waitFor(server) { if (!server.listening) await once(server, 'listening'); }
async function close(server) { if (server?.listening) await new Promise(resolve => server.close(resolve)); }

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

async function runBenchmark({ outputFile = path.join(process.cwd(), 'benchmark-results.json'), logger = console } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-benchmark-'));
  const serviceToken = 'b'.repeat(32);
  const authorityDirectory = path.join(root, 'authorities');
  const trustFile = path.join(root, 'authority-trust.json');
  const authorities = createAuthorities(authorityDirectory);
  writeJsonAtomic(trustFile, authorityTrust(authorities));
  const node = startNode({ directory: path.join(root, 'node-a'), name: 'node-a', authorityFile: trustFile, port: 0, serviceToken });
  try {
    await waitFor(node.server);
    const target = node.node;

    // MTTD: tamper -> detection.
    const mttdSamples = [];
    for (let i = 0; i < 5; i++) {
      target.simulateTamper();
      const start = Date.now();
      target.scanIntegrity();
      mttdSamples.push(Date.now() - start);
      target.rollback();
    }

    // MTTR: quarantined -> verified recovery.
    const mttrSamples = [];
    for (let i = 0; i < 5; i++) {
      target.simulateTamper();
      target.scanIntegrity();
      const start = Date.now();
      target.rollback();
      mttrSamples.push(Date.now() - start);
    }

    // Approval verification time.
    const approvalSamples = [];
    for (let sequence = 1; sequence <= 5; sequence++) {
      const update = makePolicyUpdate(sequence, { enforcement: 'observe-only' });
      const approvals = [approvePolicy(update, authorities[0]), approvePolicy(update, authorities[1])];
      const start = Date.now();
      target.applyPolicy(update, approvals);
      approvalSamples.push(Date.now() - start);
    }

    // Audit-chain verification for 100 and 1000 events.
    const auditVerification = {};
    for (const count of [100, 1000]) {
      while (target.audit.length < count) target.appendAudit('integrity-ok', { digest: 'a'.repeat(64) });
      const start = Date.now();
      target.verifyAudit();
      auditVerification[`events${count}`] = Date.now() - start;
    }

    // False positives over 50+ clean scans.
    let falsePositives = 0;
    const cleanScans = 50;
    for (let i = 0; i < cleanScans; i++) {
      const result = target.scanIntegrity();
      if (result.clean !== true) falsePositives++;
    }

    const results = {
      generatedAt: new Date().toISOString(),
      isolatedDirectory: 'temporary (removed at completion)',
      metrics: {
        mttdMs: median(mttdSamples),
        mttrMs: median(mttrSamples),
        approvalVerificationMs: median(approvalSamples),
        auditChainVerificationMs: auditVerification,
        falsePositivesOverCleanScans: { falsePositives, cleanScans }
      }
    };
    fs.writeFileSync(outputFile, JSON.stringify(results, null, 2));
    logger.log('| Metric | Value |');
    logger.log('| --- | --- |');
    logger.log(`| MTTD (tamper → detect) | ${results.metrics.mttdMs} ms |`);
    logger.log(`| MTTR (quarantine → verified recovery) | ${results.metrics.mttrMs} ms |`);
    logger.log(`| Approval verification (2-of-3) | ${results.metrics.approvalVerificationMs} ms |`);
    logger.log(`| Audit-chain verification (100 events) | ${auditVerification.events100} ms |`);
    logger.log(`| Audit-chain verification (1000 events) | ${auditVerification.events1000} ms |`);
    logger.log(`| False positives over ${cleanScans} clean scans | ${falsePositives} |`);
    return results;
  } finally {
    await close(node.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
}

if (require.main === module) {
  runBenchmark().catch(error => { console.error(`benchmark failed: ${error.message}`); process.exitCode = 1; });
}

module.exports = { runBenchmark };
