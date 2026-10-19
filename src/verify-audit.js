#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const { SecurityNode, readJson, verifySanitizedAuditEvidence } = require('./core');

const target = process.argv[2];
if (!target || target === '--help' || target === '-h') { console.log('Usage: npm run verify-audit -- <node-data-directory|sanitized-audit.json>'); process.exitCode = target ? 0 : 2; }
else {
  try {
    const resolved = path.resolve(target);
    if (fs.statSync(resolved).isFile()) {
      const exported = JSON.parse(fs.readFileSync(resolved, 'utf8'));
      const reports = Array.isArray(exported.nodes) ? exported.nodes : [exported];
      const results = reports.map(report => ({ node: report.node, ...verifySanitizedAuditEvidence(report) }));
      process.stdout.write(`${JSON.stringify({ nodes: results })}\n`);
      if (results.length === 0 || results.some(result => !result.valid)) process.exitCode = 1;
    } else {
      const state = readJson(path.join(resolved, 'state.json'), {});
      const identity = readJson(path.join(resolved, 'identity.json'), null);
      if (!identity?.name || !identity.publicKey) throw new Error('node identity missing');
      const node = Object.create(SecurityNode.prototype);
      node.directory = resolved; node.name = identity.name; node.identity = identity; node.state = state;
      node.paths = { audit: path.join(resolved, 'audit.json') };
      node.audit = readJson(node.paths.audit, []);
      const result = node.verifyAudit();
      process.stdout.write(`${JSON.stringify({ node: identity.name, ...result })}\n`);
      if (!result.valid) process.exitCode = 1;
    }
  } catch (error) { console.error(`audit verification failed: ${error.message}`); process.exitCode = 1; }
}
