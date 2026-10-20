const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { SecurityNode, createAuthorities, authorityTrust } = require('../src/core');
const { createTimeline } = require('../src/timeline');

function fixture(t, name, clock) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'danms-timeline-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorities = createAuthorities(path.join(root, 'authorities'));
  const initialTime = clock();
  const node = new SecurityNode({
    directory: path.join(root, name),
    name,
    trustedAuthorities: authorityTrust(authorities),
    clock: () => initialTime
  });
  node.clock = clock;
  node.appendAudit('integrity-ok', { digest: 'a'.repeat(64) });
  return node.auditReport();
}

test('timeline orders verified events by recorded time and preserves node and evidence identity', t => {
  const a = fixture(t, 'node-a', () => '2026-10-20T10:00:00.000Z');
  const b = fixture(t, 'node-b', () => '2026-10-20T10:00:01.000Z');
  const timeline = createTimeline([
    { name: 'node-a', mode: 'trusted' },
    { name: 'node-b', mode: 'trusted' }
  ], [b, a]);

  assert.deepEqual(timeline.events.map(event => event.timestamp), [
    '2026-10-20T10:00:00.000Z',
    '2026-10-20T10:00:00.000Z',
    '2026-10-20T10:00:01.000Z',
    '2026-10-20T10:00:01.000Z'
  ]);
  assert.ok(timeline.events.every(event => event.evidenceRef === event.id));
  assert.ok(timeline.events.filter(event => event.node === 'node-a').length === 2);
  assert.equal(timeline.events.at(-1).node, 'node-b');
  assert.equal(timeline.events[0].category, 'snapshot');
});

test('timeline records missing timestamps and reports duplicate or missing sources without fabricating events', t => {
  let clockCalls = 0;
  const missingTime = fixture(t, 'node-a', () =>
    clockCalls++ === 0 ? '2026-10-20T10:00:00.000Z' : 'not-a-timestamp');
  const duplicate = JSON.parse(JSON.stringify(missingTime));
  const timeline = createTimeline([
    { name: 'node-a', mode: 'trusted' },
    { name: 'node-c', mode: 'offline' }
  ], [missingTime, duplicate]);

  assert.equal(timeline.events.length, 2);
  assert.equal(timeline.events[0].timestamp, '2026-10-20T10:00:00.000Z');
  assert.equal(timeline.events[1].timestamp, null);
  assert.equal(timeline.events[1].timestampStatus, 'missing-or-invalid');
  assert.ok(timeline.incomplete.some(item => item.reason === 'duplicate-node-report'));
  assert.ok(timeline.incomplete.some(item => item.reason === 'audit-report-missing' && item.node === 'node-c'));
  assert.ok(timeline.incomplete.some(item => item.reason === 'node-unavailable' && item.node === 'node-c'));
  assert.equal(timeline.events.some(event => event.node === 'node-c'), false);
});

test('timeline excludes events from modified sanitized audit evidence', t => {
  const report = fixture(t, 'node-a', () => '2026-10-20T10:00:00.000Z');
  report.events[0].outcome = 'success';
  const timeline = createTimeline([{ name: 'node-a', mode: 'trusted' }], [report]);

  assert.equal(timeline.events.length, 0);
  assert.ok(timeline.incomplete.some(item => item.reason === 'audit-evidence-unverified'));
});
