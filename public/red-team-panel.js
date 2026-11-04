// Red vs Blue panel. Renders itself into #redteam-root. Self-contained; it
// reuses the dashboard's in-memory admin token via the global API helper when
// available, and never touches existing markup or scripts.
(() => {
  'use strict';
  const root = document.getElementById('redteam-root');
  if (!root) return;

  const STAGES = ['detect', 'quarantine', 'decoy', 'gossip', 'recover'];

  root.innerHTML = `
    <div class="rt-card">
      <div class="rt-head">
        <div>
          <h2 class="rt-title">⚔ Red vs Blue</h2>
          <p class="rt-sub">Five simulated attacks against isolated temporary nodes. Nothing touches live state.</p>
        </div>
        <div class="rt-controls">
          <input class="rt-token" id="rtToken" type="password" autocomplete="off" placeholder="Admin token (or use dev session)">
          <button class="rt-run" id="rtRun">▶ Run Red Team</button>
        </div>
      </div>
      <div class="rt-timeline" id="rtTimeline">
        ${STAGES.map(stage => `<div class="rt-step" data-stage="${stage}">${stage}</div>`).join('')}
      </div>
      <div class="rt-score" id="rtScore" hidden>
        <div>Attempted<b class="rt-amber" id="rtAttempted">0</b></div>
        <div>Blocked<b class="rt-green" id="rtBlocked">0</b></div>
        <div>Succeeded<b class="rt-red" id="rtSucceeded">0</b></div>
      </div>
      <table id="rtTable" hidden>
        <thead><tr><th>Attack</th><th>Result</th><th>Detect (ms)</th><th>Defense layer</th><th>Audit events</th></tr></thead>
        <tbody id="rtBody"></tbody>
      </table>
      <div class="rt-status" id="rtStatus">Idle. Run the red team to test the blue team's defenses.</div>
    </div>
    <div class="rt-card rt-bench">
      <div class="rt-head">
        <div>
          <h2 class="rt-title">⏱ Benchmarks</h2>
          <p class="rt-sub">Latest <code>npm run benchmark</code> results served from benchmark-results.json.</p>
        </div>
        <button class="rt-run rt-refresh" id="rtBenchRefresh">↻ Refresh</button>
      </div>
      <table id="rtBenchTable" hidden>
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody id="rtBenchBody"></tbody>
      </table>
      <div class="rt-status" id="rtBenchStatus">Loading…</div>
    </div>`;

  const $ = selector => root.querySelector(selector);
  const status = text => { $('#rtStatus').textContent = text; };

  function setStage(active) {
    const index = STAGES.indexOf(active);
    root.querySelectorAll('.rt-step').forEach((el, i) => {
      el.classList.toggle('done', index === -1 ? false : i < index);
      el.classList.toggle('active', i === index);
    });
    if (index === -1) root.querySelectorAll('.rt-step').forEach(el => el.classList.remove('done', 'active'));
  }

  function completeAll() {
    root.querySelectorAll('.rt-step').forEach(el => { el.classList.add('done'); el.classList.remove('active'); });
  }

  function render(result) {
    $('#rtScore').hidden = false;
    $('#rtAttempted').textContent = result.scoreboard.attempted;
    $('#rtBlocked').textContent = result.scoreboard.blocked;
    $('#rtSucceeded').textContent = result.scoreboard.succeeded;
    $('#rtTable').hidden = false;
    $('#rtBody').innerHTML = result.attacks.map(attack => `
      <tr>
        <td>${attack.name}</td>
        <td class="${attack.blocked ? 'rt-blocked' : 'rt-passed'}">${attack.blocked ? 'BLOCKED' : 'PASSED'}</td>
        <td>${attack.detectedAtMs}</td>
        <td>${attack.defenseLayer}</td>
        <td class="rt-ids">${(attack.auditEventIds || []).join(', ') || '—'}</td>
      </tr>`).join('');
  }

  async function run() {
    const button = $('#rtRun');
    button.disabled = true;
    setStage('detect');
    status('Running attacks against isolated temporary nodes…');
    const stageTimer = [setTimeout(() => setStage('quarantine'), 400), setTimeout(() => setStage('decoy'), 800),
      setTimeout(() => setStage('gossip'), 1200), setTimeout(() => setStage('recover'), 1600)];
    try {
      const headers = { 'content-type': 'application/json', 'x-request-id': `redteam-${crypto.randomUUID()}`, 'x-request-timestamp': String(Date.now()) };
      const token = $('#rtToken').value.trim();
      if (token) headers['x-dashboard-admin-token'] = token;
      const response = await fetch('/api/red-team/run', { method: 'POST', headers, body: '{}' });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || `http-${response.status}`);
      completeAll();
      render(body);
      status(`Complete. ${body.scoreboard.blocked}/${body.scoreboard.attempted} attacks blocked by the blue team.`);
    } catch (error) {
      setStage(null);
      status(`Red team run failed: ${error.message}. Unlock the admin role first.`);
    } finally {
      stageTimer.forEach(clearTimeout);
      button.disabled = false;
    }
  }

  async function loadBenchmarks() {
    const statusEl = $('#rtBenchStatus');
    statusEl.textContent = 'Loading…';
    try {
      const response = await fetch('/api/benchmarks');
      if (response.status === 404) { statusEl.textContent = 'No benchmark results yet. Run `npm run benchmark` to generate them.'; return; }
      if (!response.ok) throw new Error(`http-${response.status}`);
      const body = await response.json();
      const m = body.metrics || {};
      const rows = [
        ['MTTD (tamper → detect)', `${m.mttdMs} ms`],
        ['MTTR (quarantine → verified recovery)', `${m.mttrMs} ms`],
        ['Approval verification (2-of-3)', `${m.approvalVerificationMs} ms`],
        ['Audit-chain verification (100 events)', `${m.auditChainVerificationMs?.events100} ms`],
        ['Audit-chain verification (1000 events)', `${m.auditChainVerificationMs?.events1000} ms`],
        [`False positives over ${m.falsePositivesOverCleanScans?.cleanScans ?? 50} clean scans`, String(m.falsePositivesOverCleanScans?.falsePositives ?? '—')]
      ];
      const esc = value => String(value).replace(/[&<>"]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));
      const scenarios = Array.isArray(body.scenarios) ? body.scenarios : [];
      if (scenarios.length) rows.push(['Synthetic scenarios passed', `${scenarios.filter(s => s.pass).length}/${scenarios.length}`]);
      const scenarioRows = scenarios.map(s => [`${s.pass ? '✓' : '✗'} ${s.id}`, `expected ${s.expected} · actual ${s.actual} · ${s.durationMs} ms${s.evidenceRef ? ` · ${s.evidenceRef}` : ''}`]);
      $('#rtBenchBody').innerHTML = rows.map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('') + scenarioRows.map(([k, v]) => `<tr><td class="${k.startsWith('✓') ? 'rt-blocked' : 'rt-passed'}">${esc(k)}</td><td>${esc(v)}</td></tr>`).join('');
      $('#rtBenchTable').hidden = false;
      statusEl.textContent = `Generated ${body.generatedAt || 'unknown'} · isolated temporary state only.`;
    } catch (error) {
      statusEl.textContent = `Benchmarks unavailable: ${error.message}`;
    }
  }

  $('#rtRun').addEventListener('click', run);
  $('#rtBenchRefresh').addEventListener('click', loadBenchmarks);
  loadBenchmarks();
})();
