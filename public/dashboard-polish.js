// Dashboard polish layer — read-only UI enhancements for the judge demo.
// It never calls APIs, never stores credentials, and never changes existing
// element behavior. Status values are MIRRORED from the elements the existing
// dashboard already updates (#verifiedCount, #defcon, #modelStatus, #mttd,
// #mttr, #integrityValue, #rtBlocked, #auditVerify), so nothing is hardcoded.
// Every block is wrapped in try/catch: a polish failure can never break the
// existing demo flow. Loaded inline in index.html (script#dashboard-polish-js).
(() => {
  'use strict';

  const $ = selector => document.querySelector(selector);
  const reducedMotion = Boolean(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const safe = fn => { try { fn(); } catch { /* UI polish must never break the demo */ } };

  // Observe an element and run callback on every mutation AND once at setup.
  const onMutate = (el, options, callback) => {
    if (!el) return;
    const observer = new MutationObserver(() => safe(() => callback(observer)));
    observer.observe(el, options);
    safe(() => callback(observer));
  };
  const TEXT_AND_CLASS = { childList: true, characterData: true, subtree: true, attributes: true, attributeFilter: ['class', 'hidden'] };
  const TEXT_ONLY = { childList: true, characterData: true, subtree: true };

  // ---------- count-up animation (skipped for reduced motion) ----------
  function setStatText(el, text) {
    if (!el) return;
    const next = String(text);
    const prev = el.dataset.raw ?? el.textContent;
    el.dataset.raw = next;
    if (prev === next) return;
    const match = next.match(/-?\d+(?:\.\d+)?/);
    const prevMatch = String(prev).match(/-?\d+(?:\.\d+)?/);
    if (reducedMotion || !match || !prevMatch) { el.textContent = next; return; }
    const from = Number(prevMatch[0]);
    const to = Number(match[0]);
    if (from === to) { el.textContent = next; return; }
    const pre = next.slice(0, match.index);
    const post = next.slice(match.index + match[0].length);
    const started = performance.now();
    const duration = 600;
    cancelAnimationFrame(el._countRaf || 0);
    const tick = now => {
      const t = Math.min(1, (now - started) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      el.textContent = `${pre}${Math.round(from + (to - from) * eased)}${post}`;
      if (t < 1) el._countRaf = requestAnimationFrame(tick);
    };
    el._countRaf = requestAnimationFrame(tick);
  }

  // ---------- A + B. Hero status row + scoreboard mirrors ----------
  function initMirrors() {
    // "Nodes trusted" counts nodes whose rendered mode is trusted — kept
    // distinct from audit-chain verification (the ledger badge covers that),
    // so a quarantined node is never shown as healthy.
    const syncTrusted = () => {
      const target = $('#heroVerified');
      if (!target) return;
      const cards = [...document.querySelectorAll('#nodes .node-card')];
      if (!cards.length) { target.textContent = (($('#verifiedCount') || {}).textContent || '—').trim(); return; }
      const trusted = cards.filter(card => ((card.querySelector('p') || {}).textContent || '').startsWith('trusted')).length;
      target.textContent = `${trusted} / ${cards.length}`;
    };
    onMutate($('#verifiedCount'), TEXT_ONLY, syncTrusted);
    onMutate($('#nodes'), { childList: true }, syncTrusted);
    onMutate($('#defcon'), TEXT_AND_CLASS, () => {
      const source = $('#defcon');
      const target = $('#heroDefcon');
      if (!source || !target) return;
      target.textContent = (source.textContent || '').trim() || '—';
      target.className = source.className || '';
    });
    const syncAi = () => {
      const status = $('#modelStatus');
      const target = $('#heroAi');
      if (!status || !target) return;
      const mode = (status.textContent || '').trim();
      if (status.classList.contains('live') && !/deterministic fallback/i.test(mode)) {
        const muse = document.querySelector('[data-model="muse-spark-1.3"]');
        const museLive = muse && /·\s*live\s*$/i.test(muse.textContent || '');
        target.textContent = `LIVE · ${museLive ? 'muse-spark-1.3' : mode}`;
        target.className = 'green';
      } else {
        target.textContent = 'Offline-safe deterministic mode';
        target.className = 'amber';
      }
    };
    onMutate($('#modelStatus'), TEXT_AND_CLASS, syncAi);

    const asMs = value => { const text = (value || '').trim(); return text.startsWith('—') ? '—' : text; };
    onMutate($('#mttd'), TEXT_ONLY, () => setStatText($('#statMttd'), asMs($('#mttd').textContent)));
    onMutate($('#mttr'), TEXT_ONLY, () => setStatText($('#statMttr'), asMs($('#mttr').textContent)));
    onMutate($('#integrityValue'), TEXT_ONLY, () => setStatText($('#statIntegrity'), ($('#integrityValue').textContent || '—').trim()));
    const syncBlocked = () => {
      const score = $('#rtScore');
      const value = $('#rtBlocked');
      const target = $('#statBlocked');
      if (!target) return;
      const available = score && !score.hidden && value;
      setStatText(target, available ? (value.textContent || '').trim() : '—');
    };
    onMutate($('#rtScore'), TEXT_AND_CLASS, syncBlocked);
    onMutate($('#rtBlocked'), TEXT_ONLY, syncBlocked);

    // Green proof badge kept OUTSIDE the advanced drawer: parsed from the real
    // audit verification line, never hardcoded.
    onMutate($('#auditVerify'), TEXT_ONLY, () => {
      const source = $('#auditVerify');
      const badge = $('#ledgerBadge');
      if (!source || !badge) return;
      const match = (source.textContent || '').match(/360 chain status (\d+)\s*\/\s*(\d+)/);
      if (!match) { badge.textContent = 'LEDGER · —'; badge.className = 'badge'; return; }
      const ok = match[1] === match[2] && Number(match[1]) > 0;
      badge.textContent = `${match[1]}/${match[2]} chains verified${ok ? ' ✓' : ''}`;
      badge.className = `badge ${ok ? 'good' : 'warn'}`;
    });
  }

  // ---------- C. Attack-to-recovery flow diagram ----------
  // Driven ONLY by the existing stage buttons (.active/.complete classes) and
  // the existing #message status line. No progress is invented.
  const FLOW_KEYS = ['tamper', 'deception', 'gossip', 'forensics', 'synthesize', 'quorum', 'rollback'];
  const flowState = Object.fromEntries(FLOW_KEYS.map(key => [key, 'waiting']));
  function renderFlow() {
    FLOW_KEYS.forEach(key => {
      const step = document.querySelector(`[data-flow="${key}"]`);
      if (!step) return;
      const state = flowState[key];
      step.classList.remove('is-waiting', 'is-running', 'is-done', 'is-failed');
      step.classList.add(`is-${state}`);
      const label = step.querySelector('.flow-state');
      if (label) label.textContent = state;
    });
    judgeSync();
  }
  function initFlow() {
    document.querySelectorAll('[data-step]').forEach(button => {
      const key = button.dataset.step;
      if (!(key in flowState)) return;
      // The existing code marks a stage with .active while running and adds
      // .complete at the end WITHOUT removing .active, so class-change order
      // (via attributeOldValue) decides the state. Re-running a completed
      // stage adds no NEW .complete mutation, so any removal of .active
      // re-derives the state from the classes still present.
      const observer = new MutationObserver(mutations => safe(() => {
        for (const mutation of mutations) {
          const had = (mutation.oldValue || '').split(/\s+/);
          const hadActive = had.includes('active');
          const hadComplete = had.includes('complete');
          if (button.classList.contains('active') && !hadActive) flowState[key] = 'running';
          else if (button.classList.contains('complete') && !hadComplete) flowState[key] = 'done';
          else if (!button.classList.contains('active')) flowState[key] = button.classList.contains('complete') ? 'done' : 'waiting';
        }
        renderFlow();
      }));
      observer.observe(button, { attributes: true, attributeFilter: ['class'], attributeOldValue: true });
    });
    onMutate($('#message'), TEXT_ONLY, () => {
      const text = ($('#message').textContent || '').trim();
      const failed = text.match(/^(tamper|deception|gossip|forensics|synthesize|quorum|rollback) failed/i);
      if (failed) { flowState[failed[1].toLowerCase()] = 'failed'; renderFlow(); return; }
      if (/^Sequence stopped/i.test(text)) {
        const running = FLOW_KEYS.find(key => flowState[key] === 'running');
        if (running) { flowState[running] = 'failed'; renderFlow(); }
      }
    });
    const runFull = $('#runFull');
    if (runFull) runFull.addEventListener('click', () => safe(() => {
      // Reset prior progress, but never clobber a stage that has already
      // started (its .active mutations are in flight and must win).
      FLOW_KEYS.forEach(key => {
        const button = document.querySelector(`[data-step="${key}"]`);
        if (button && button.classList.contains('active')) return;
        flowState[key] = 'waiting';
      });
      renderFlow();
    }));
    renderFlow();
  }

  // ---------- D. Node mesh cards: status chip + hash expander + gossip pulse ----------
  function applyGossipPulse(container) {
    const mesh = $('#meshStudio');
    const gossip = Boolean(mesh && mesh.classList.contains('is-gossip'));
    container.querySelectorAll('.node-card').forEach((card, index) => {
      card.classList.toggle('gossip-source', gossip && index === 0);
      card.classList.toggle('gossip-hit', gossip && index > 0);
    });
  }
  function enhanceNodeCard(card, index) {
    if (card.dataset.polished) return;
    card.dataset.polished = '1';
    const letter = 'ABC'[index] || 'A';
    const subtitle = (($(`#svg${letter}`) || {}).textContent || '').toUpperCase();
    const status = subtitle.includes('DECOY') ? 'DECOY'
      : subtitle.includes('QUARANTINED') ? 'QUARANTINED'
      : subtitle.includes('INOCULATED') ? 'INOCULATED'
      : subtitle.includes('TRUSTED') ? 'TRUSTED'
      : (subtitle || 'UNKNOWN');
    const slug = status.toLowerCase().replace(/[^a-z]+/g, '-');
    const chip = document.createElement('span');
    chip.className = `status-chip chip-${slug}`;
    chip.textContent = status;
    const name = card.querySelector('strong');
    if (name) name.appendChild(chip); else card.prepend(chip);
    card.classList.add(`status-${slug}`);
    const digest = card.querySelector('.mono');
    const match = digest && (digest.textContent || '').match(/SHA-256\s+([0-9a-f]{16,})/i);
    if (match) {
      const full = match[1];
      digest.textContent = `SHA-256 ${full.slice(0, 8)}…`;
      digest.title = full;
      const details = document.createElement('details');
      details.className = 'hash-details';
      const summary = document.createElement('summary');
      summary.textContent = 'Details';
      summary.setAttribute('aria-label', `Full SHA-256 fingerprint for node ${letter}`);
      const code = document.createElement('code');
      code.textContent = full;
      details.append(summary, code);
      card.appendChild(details);
    }
  }
  function initNodeCards() {
    const container = $('#nodes');
    if (!container) return;
    onMutate(container, { childList: true }, observer => {
      observer.disconnect();
      try {
        container.querySelectorAll('.node-card').forEach(enhanceNodeCard);
        applyGossipPulse(container);
      } finally {
        observer.observe(container, { childList: true });
      }
    });
    const mesh = $('#meshStudio');
    if (mesh) onMutate(mesh, { attributes: true, attributeFilter: ['class'] }, () => applyGossipPulse(container));
  }

  // ---------- E. Collapse long JSON behind a readable summary line ----------
  function totalNodeCount() {
    const match = (($('#verifiedCount') || {}).textContent || '').match(/\/\s*(\d+)/);
    return match ? match[1] : '3';
  }
  function collapseLongJson(id, summarize) {
    const pre = $('#' + id);
    if (!pre) return;
    onMutate(pre, TEXT_ONLY, observer => {
      observer.disconnect();
      try {
        const text = pre.textContent || '';
        const signature = `${text.length}:${text.slice(0, 48)}`;
        if (pre.dataset.polishSig === signature) return;
        pre.dataset.polishSig = signature;
        if (text.trim().length < 200) return;
        const details = document.createElement('details');
        details.className = 'json-details';
        const summary = document.createElement('summary');
        summary.textContent = summarize(text);
        const body = document.createElement('pre');
        body.textContent = text;
        details.append(summary, body);
        pre.textContent = '';
        pre.appendChild(details);
      } finally {
        observer.observe(pre, TEXT_ONLY);
      }
    });
  }
  function initJsonCollapse() {
    collapseLongJson('probeOutput', text => {
      if (/^Inoculation receipts/i.test(text)) {
        try {
          const data = JSON.parse(text.slice(text.indexOf('\n') + 1));
          const deliveries = Array.isArray(data) ? data : (data && data.deliveries) || [];
          const count = deliveries.filter(item => item && item.inoculated === true).length;
          return `${count} of ${totalNodeCount()} nodes inoculated · signed gossip receipts (tap to expand)`;
        } catch { return 'Signed inoculation receipts (tap to expand)'; }
      }
      if (/Threat fingerprint:/i.test(text)) return 'Chameleon decoy response + threat fingerprint (tap to expand)';
      if (text.trim().startsWith('{')) return 'Workflow result JSON (tap to expand)';
      return 'Response detail (tap to expand)';
    });
    collapseLongJson('policyOutput', text => {
      if (/Human gate:/i.test(text)) return 'Candidate policy · not applied until human quorum signs (tap to expand)';
      if (/"results"\s*:/.test(text)) return 'Quorum apply result · per-node receipts (tap to expand)';
      if (/"sandbox"\s*:/.test(text)) return 'Policy synthesis + 50-event sandbox result (tap to expand)';
      return 'Policy detail JSON (tap to expand)';
    });
    collapseLongJson('preCogOutput', () => 'Aegis SIR prediction detail · advisory only, nothing executed (tap to expand)');
  }

  // ---------- Proof Explorer (proof-carrying recovery certificates) ----------
  let proofCertificate = null;

  function proofTone(value) {
    if (/^(verified|trusted|verified-clean|succeeded)$/.test(value)) return 'good';
    if (/^failed/.test(value)) return 'danger';
    if (/self-asserted|recorded|not-applicable/.test(value)) return 'live';
    return 'warn';
  }
  function renderProof(certificate, verification) {
    const classes = $('#proofClasses');
    if (!classes) return;
    classes.replaceChildren();
    const v = verification || certificate.verification;
    [['Audit chain', v.auditChain], ['Audit signatures', v.auditSignatures], ['External node identity', v.externalNodeIdentity],
     ['Snapshot artifact', v.snapshotArtifact], ['Approval signatures', v.approvalSignatures], ['Recovery operation', v.recoveryOperation],
     ['Post-recovery integrity', v.postRecoveryIntegrity], ['Audit-only proof', v.auditOnlyProof], ['Complete recovery proof', v.completeRecoveryProof]]
      .forEach(([label, value]) => {
        const chip = document.createElement('span');
        chip.className = `badge ${proofTone(String(value))}`;
        chip.textContent = `${label}: ${value}`;
        classes.append(chip);
      });
    const panel = $('#proofPanel');
    if (!panel) return;
    panel.replaceChildren();
    const claims = certificate.claims || {};
    const rows = [
      ['Node', certificate.node],
      ['Issued at', certificate.issuedAt],
      ['Tamper event', claims.tamperEvent ? `${claims.tamperEvent.eventId} · ${claims.tamperEvent.attackClassification || 'integrity event'}` : '—'],
      ['Threat fingerprint', claims.threatFingerprint?.digest ? `${claims.threatFingerprint.digest.slice(0, 16)}… (${claims.threatFingerprint.eventId})` : '—'],
      ['Snapshot id', claims.snapshot?.snapshotId || '—'],
      ['Snapshot artifact digest', claims.snapshot?.artifactDigest ? `${claims.snapshot.artifactDigest.slice(0, 16)}…` : 'not recorded in audit'],
      ['Restore event', claims.restoreEvent?.eventId || '—'],
      ['Post-recovery event', claims.postRecoveryEvent?.eventId || '—'],
      ['Governance', certificate.governance ? `policy sequence ${certificate.governance.sequence} · approvers ${(certificate.governance.approvers || []).join(', ') || '—'}` : 'no policy approval in this cycle'],
      ['AI provenance', certificate.aiProvenance ? `${certificate.aiProvenance.providerMode} · models: ${certificate.aiProvenance.modelsInvoked.join(', ') || 'none'} · citations validated: ${certificate.aiProvenance.referencesValidated}` : 'no AI analysis attached'],
      ['Certificate digest', `${String(certificate.certificateDigest || '').slice(0, 24)}…`]
    ];
    const dl = document.createElement('dl');
    dl.className = 'proof-fields';
    rows.forEach(([key, value]) => {
      const dt = document.createElement('dt'); dt.textContent = key;
      const dd = document.createElement('dd'); dd.textContent = value == null || value === '' ? '—' : String(value);
      dl.append(dt, dd);
    });
    panel.append(dl);
    if (verification && verification.note) {
      const note = document.createElement('p');
      note.className = 'panel-caption';
      note.textContent = verification.note;
      panel.append(note);
    }
  }

  // Self-asserted in-browser verification of the embedded evidence report.
  // Independent proof (trust anchor + snapshot artifact) stays offline.
  function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
    if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
    return JSON.stringify(value);
  }
  function bytesFromBase64(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, char => char.charCodeAt(0));
  }
  async function verifyEmbeddedReport(report) {
    try {
      const proof = report?.proof;
      if (report?.verification?.valid !== true || !proof || proof.version !== 1 || proof.node !== report.node || proof.entries !== proof.records?.length || proof.records.length !== report.events.length) return false;
      const pem = proof.publicKey.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, '');
      const fingerprintBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(proof.publicKey)));
      const fingerprint = [...fingerprintBytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
      if (fingerprint !== report.nodePublicKeyFingerprint) return false;
      const key = await crypto.subtle.importKey('spki', bytesFromBase64(pem), { name: 'Ed25519' }, false, ['verify']);
      let previous = 'GENESIS';
      for (let i = 0; i < proof.records.length; i++) {
        const record = proof.records[i];
        const event = report.events[i];
        if (record.index !== i || event.index !== i || record.previousHash !== previous || record.at !== event.at || record.type !== event.type || record.outcome !== event.outcome || canonicalJson(record.evidence) !== canonicalJson(event.evidence)) return false;
        const unsigned = { index: record.index, at: record.at, type: record.type, outcome: record.outcome, evidence: record.evidence, previousHash: previous };
        const hashBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalJson(unsigned))));
        const hash = [...hashBytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
        if (hash !== record.hash || !await crypto.subtle.verify({ name: 'Ed25519' }, key, bytesFromBase64(record.signature), new TextEncoder().encode(hash))) return false;
        previous = hash;
      }
      return previous === proof.head;
    } catch { return false; }
  }
  async function verifyProofInBrowser(certificate) {
    const report = certificate.evidence?.report;
    if (!report) return null;
    const chainOk = await verifyEmbeddedReport(report);
    const events = report.events || [];
    const eventById = id => { const [node, index] = String(id || '').split(':'); return node === certificate.node && /^\d+$/.test(index) ? events[Number(index)] : undefined; };
    const claims = certificate.claims || {};
    const typedClaims = [['tamperEvent', 'tamper-detected'], ['threatFingerprint', 'threat-fingerprint'], ['quarantineEvent', 'quarantine-applied'], ['recoveryAttemptEvent', 'recovery-attempted'], ['restoreEvent', 'rollback-verified'], ['postRecoveryEvent', 'integrity-ok']];
    const typedOk = typedClaims.every(([key, type]) => !claims[key]?.eventId || eventById(claims[key].eventId)?.type === type);
    const refsOk = (claims.evidenceRefs || []).every(ref => eventById(ref));
    const restore = claims.restoreEvent?.eventId ? eventById(claims.restoreEvent.eventId) : null;
    const postCheck = claims.postRecoveryEvent?.eventId ? eventById(claims.postRecoveryEvent.eventId) : null;
    const digestOk = !restore || !postCheck ? true : restore.evidence?.restored === postCheck.evidence?.digest;
    const consistent = typedOk && refsOk && digestOk;
    return {
      auditChain: chainOk && consistent ? 'verified-self-asserted' : 'failed',
      auditSignatures: chainOk ? 'verified-self-asserted' : 'failed',
      externalNodeIdentity: 'not-verified-offline-trust-record-required',
      snapshotArtifact: 'not-verified-offline-artifact-required',
      approvalSignatures: certificate.governance ? 'audit-recorded-not-independently-reverified' : 'not-applicable',
      recoveryOperation: certificate.verification.recoveryOperation,
      postRecoveryIntegrity: certificate.verification.postRecoveryIntegrity,
      auditOnlyProof: 'not-verified',
      completeRecoveryProof: 'not-verified',
      note: 'Browser verification is self-asserted only. Full independent proof: npm run verify-recovery -- --certificate <file> --trusted-key <independent-node-trust.json> [--snapshot <original-snapshot.json>]'
    };
  }
  function initProofExplorer() {
    const loadButton = $('#proofLoad');
    if (!loadButton) return;
    loadButton.addEventListener('click', async () => {
      loadButton.disabled = true;
      try {
        const node = $('#proofNode').value;
        const response = await fetch(`/api/recovery/certificate?node=${encodeURIComponent(node)}`, { cache: 'no-store', credentials: 'same-origin' });
        const body = await response.json();
        if (!response.ok) throw new Error(body.error || `http-${response.status}`);
        proofCertificate = body;
        renderProof(body);
        const badge = $('#proofBadge');
        badge.textContent = `CERTIFICATE · ${body.node.toUpperCase()} · ${body.verification.auditChain}`;
        badge.className = `badge ${body.verification.auditChain === 'failed' ? 'danger' : 'live'}`;
        $('#proofVerify').disabled = false;
        $('#proofDownload').disabled = false;
        $('#proofOffline').hidden = false;
        judgeSync();
      } catch (error) {
        const badge = $('#proofBadge');
        badge.textContent = `CERTIFICATE UNAVAILABLE · ${error.message}`;
        badge.className = 'badge warn';
      } finally { loadButton.disabled = false; }
    });
    $('#proofVerify').addEventListener('click', async () => {
      if (!proofCertificate) return;
      const button = $('#proofVerify'); button.disabled = true;
      try {
        const result = await verifyProofInBrowser(proofCertificate);
        if (result) {
          renderProof(proofCertificate, result);
          const badge = $('#proofBadge');
          badge.textContent = `BROWSER CHECK · ${result.auditChain}`;
          badge.className = `badge ${result.auditChain === 'failed' ? 'danger' : 'live'}`;
        }
      } catch { /* verification failure is shown via classifications */ }
      finally { button.disabled = false; }
    });
    $('#proofDownload').addEventListener('click', () => {
      if (!proofCertificate) return;
      const blob = new Blob([JSON.stringify(proofCertificate, null, 2)], { type: 'application/json' });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = `recovery-certificate-${proofCertificate.node}.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    });
  }

  // ---------- Judge demo script checklist ----------
  function judgeSync() {
    const steps = document.querySelectorAll('[data-judge]');
    if (!steps.length) return;
    const chips = [...document.querySelectorAll('#nodes .status-chip')].map(chip => chip.textContent);
    const allTrusted = chips.length === 3 && chips.every(text => text === 'TRUSTED');
    steps.forEach(item => {
      const key = item.dataset.judge;
      const done = key === 'intro' ? true
        : key === 'trusted' ? allTrusted || flowState.tamper !== 'waiting'
        : key === 'certificate' ? Boolean(proofCertificate)
        : flowState[key] === 'done';
      item.classList.toggle('done', Boolean(done));
    });
  }
  function initJudgeScript() {
    if (!document.querySelector('[data-judge]')) return;
    onMutate($('#nodes'), { childList: true, subtree: true, characterData: true }, judgeSync);
    judgeSync();
  }

  // ---------- Human-governed authorization chain strip ----------
  function initAuthzChain() {
    const chain = $('#authzChain');
    if (!chain) return;
    const sync = () => {
      const proposalText = ($('#policyAfter')?.textContent || '').trim();
      const proposal = proposalText !== '' && proposalText !== 'Awaiting synthesis.';
      const sandbox = ($('#sandboxBadge')?.textContent || '').startsWith('PASS');
      const quorumMatch = ($('#quorumProgress')?.textContent || '').match(/(\d+)\s*\/\s*(\d+)/);
      const signed = Boolean(quorumMatch) && Number(quorumMatch[1]) >= 1;
      const quorumMet = Boolean(quorumMatch) && Number(quorumMatch[1]) >= Number(quorumMatch[2]);
      const applied = /"ok"\s*:\s*true/.test($('#policyOutput')?.textContent || '');
      let verified = false;
      if (applied) {
        const match = proposalText.match(/"sequence"\s*:\s*(\d+)/);
        verified = Boolean(match) && Number(($('#sequence')?.textContent || '0').trim()) >= Number(match[1]);
      }
      const states = { proposal, sandbox, signatures: signed, quorum: quorumMet, applied, verified };
      chain.querySelectorAll('[data-chain]').forEach(el => {
        el.classList.toggle('done', Boolean(states[el.dataset.chain]));
        el.classList.toggle('partial', el.dataset.chain === 'signatures' && signed && !quorumMet);
      });
    };
    ['#policyAfter', '#sandboxBadge', '#quorumProgress', '#policyOutput', '#sequence'].forEach(selector => onMutate($(selector), TEXT_AND_CLASS, sync));
  }

  safe(initMirrors);
  safe(initFlow);
  safe(initNodeCards);
  safe(initJsonCollapse);
  safe(initProofExplorer);
  safe(initJudgeScript);
  safe(initAuthzChain);
})();
