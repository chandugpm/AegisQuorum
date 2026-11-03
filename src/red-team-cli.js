#!/usr/bin/env node
const { runRedTeam } = require('./red-team');

// CLI wrapper for the Red Team vs Blue Team simulation. Runs against
// temporary nodes and prints a scoreboard; no secrets or live state are used.
runRedTeam().then(result => {
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}).catch(error => {
  console.error(`red-team failed: ${error.message}`);
  process.exitCode = 1;
});
