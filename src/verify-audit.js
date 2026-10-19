#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const { SecurityNode, readJson } = require('./core');

const directory = process.argv[2];
if (!directory || directory === '--help' || directory === '-h') { console.log('Usage: npm run verify-audit -- <node-data-directory>'); process.exitCode = directory ? 0 : 2; }
else {
  try {
    const state = readJson(path.join(directory, 'state.json'), {});
    const identity = readJson(path.join(directory, 'identity.json'), null);
    if (!identity?.name || !identity.publicKey) throw new Error('node identity missing');
    const node = Object.create(SecurityNode.prototype);
    node.directory = directory; node.name = identity.name; node.identity = identity; node.state = state;
    node.paths = { audit: path.join(directory, 'audit.json') };
    node.audit = readJson(node.paths.audit, []);
    const result = node.verifyAudit();
    process.stdout.write(`${JSON.stringify({ node: identity.name, ...result })}\n`);
    if (!result.valid) process.exitCode = 1;
  } catch (error) { console.error(`audit verification failed: ${error.message}`); process.exitCode = 1; }
}
