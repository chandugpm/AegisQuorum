const path = require('node:path');
const { createAuthorities, authorityTrust, writeJsonAtomic } = require('./core');

const root = process.env.RUNTIME_DIRECTORY || path.join(process.cwd(), '.runtime');
const authorityDirectory = path.join(root, 'authorities');
const trustFile = path.join(root, 'authority-trust.json');
const authorities = createAuthorities(authorityDirectory);
writeJsonAtomic(trustFile, authorityTrust(authorities));
console.log(`Initialized development authority trust at ${trustFile}`);
