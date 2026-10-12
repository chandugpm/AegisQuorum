const path = require('node:path');
const { initializeAuthorityTrust } = require('./runtime-config');

const root = process.env.RUNTIME_DIRECTORY || path.join(process.cwd(), '.runtime');
const authorityDirectory = path.join(root, 'authorities');
const trustFile = path.join(root, 'authority-trust.json');
const result = initializeAuthorityTrust({ authorityDirectory, trustFile });
console.log(`${result.initialized ? 'Initialized' : 'Validated'} authority trust at ${trustFile}`);
