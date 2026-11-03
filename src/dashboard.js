const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { makePolicyUpdate, parseWebAuthnRegistration, policyDigest, readJson, sha256, stable, validatePolicyApprovals, verifySanitizedAuditEvidence, verify, verifyWebAuthnAssertion, writeJsonAtomic } = require('./core');
const { validToken } = require('./runtime-config');
const { RequestError, ReplayCache, requestSecurity, createMetrics, readJsonBody, createRateLimiter, clientKey } = require('./http-utils');
const { createIncidentAnalyst } = require('./ai-analyst');
const { createTimeline } = require('./timeline');
const { registerExtensions, extendManifest, annotateTimeline, annotateAnalyst } = require('./extensions');

function json(response, status, body, headers = {}) { response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers }); response.end(JSON.stringify(body)); }
function equal(a, b) { return typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); }
function isLoopbackAddress(address) { return address === '::1' || address === '127.0.0.1' || address === '::ffff:127.0.0.1'; }
function cookieValue(request, name) {
  const cookies = String(request.headers.cookie || '').split(';');
  const entry = cookies.map(value => value.trim()).find(value => value.startsWith(`${name}=`));
  return entry ? entry.slice(name.length + 1) : '';
}
function requestJson(url, method = 'GET', payload, token, security) {
  return new Promise((resolve, reject) => {
    const target = new URL(url); const raw = payload ? JSON.stringify(payload) : undefined;
    const req = http.request({ hostname: target.hostname, port: target.port, path: target.pathname, method, headers: { ...(raw ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) } : {}), ...(token ? { 'x-node-service-token': token } : {}), ...(security ? { 'x-request-id': security.id, 'x-request-timestamp': String(security.timestamp) } : {}) }, timeout: 4000 }, res => { let data = ''; res.on('data', c => { data += c; if (data.length > 65536) req.destroy(new Error('node-response-too-large')); }); res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(data) }); } catch { reject(new Error('node-invalid-json')); } }); });
    req.on('error', reject); req.on('timeout', () => req.destroy(new Error('node-timeout'))); if (raw) req.write(raw); req.end();
  });
}
function sanitizeNodeStatus(value, fallbackName) {
  if (!value || typeof value !== 'object' || typeof value.name !== 'string') return { name: fallbackName, mode: 'offline', error: 'unavailable' };
  return { name: value.name, mode: ['trusted', 'quarantined', 'safe-mode'].includes(value.mode) ? value.mode : 'unknown', quarantined: Boolean(value.quarantined), decoyState: value.decoyState === 'DECOY_HONEYPOT' ? value.decoyState : null, shieldState: value.shieldState === 'INOCULATED_SHIELD' ? value.shieldState : 'normal', currentDigest: typeof value.currentDigest === 'string' && /^[a-f0-9]{64}$/.test(value.currentDigest) ? value.currentDigest : null, lastPolicySequence: Number.isSafeInteger(value.lastPolicySequence) ? value.lastPolicySequence : 0, trustedSnapshotPresent: Boolean(value.trustedSnapshot), audit: { valid: Boolean(value.audit?.valid), entries: Number.isSafeInteger(value.audit?.entries) ? value.audit.entries : 0 } };
}
function summarizeCommand(result, index) { return { node: `node-${String.fromCharCode(97 + index)}`, ok: result.status === 200, outcome: result.status === 200 ? 'completed' : 'unavailable' }; }
function summarizeWorkflow(stage, result, index) {
  const expected = { tamper: 'tampered', snapshot: 'valid', detection: 'quarantined', recovery: 'restored', verification: 'clean' }[stage];
  const ok = result.status === 200 && result.body?.[expected] === true;
  return { node: `node-${String.fromCharCode(97 + index)}`, ok, outcome: ok ? 'completed' : 'failed' };
}
function sanitizeForensicTranscript(value) {
  return (typeof value === 'string' ? value : '')
    .slice(0, 1000)
    .replace(/(?:DASHBOARD_ADMIN_TOKEN|NODE_SERVICE_TOKEN|MODEL_API_KEY|BASETEN_API_KEY)\s*[:=]\s*[^\s,;]+/gi, '[REDACTED_CREDENTIAL]')
    .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, '[REDACTED_SIGNING_MATERIAL]')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[REDACTED_IP]')
    .replace(/(?:[A-Za-z]:\\|\/)[^\s,;]+/g, '[REDACTED_PATH]');
}

function startDashboard({ port = 7000, host = '127.0.0.1', nodeUrls, authorityDirectory, authorityTrustFile, serviceToken, adminToken, operatorToken = process.env.DASHBOARD_OPERATOR_TOKEN || undefined, quorum = Number(process.env.POLICY_QUORUM || 2), staticDirectory = path.join(__dirname, '..', 'public'), logger = console, rateLimiter = createRateLimiter(), incidentRateLimiter = createRateLimiter({ perClientLimit: 5, globalLimit: 30 }), replayCache = new ReplayCache(), metrics = createMetrics(), incidentAnalyst = createIncidentAnalyst(), nodeTransport }) {
  if (operatorToken === '') operatorToken = undefined;
  if (!validToken(adminToken) || !validToken(serviceToken) || (operatorToken !== undefined && !validToken(operatorToken))) throw new Error('dashboard, operator, and service tokens must be non-whitespace tokens of at least 32 characters');
  if (!Array.isArray(nodeUrls) || nodeUrls.length === 0) throw new Error('at least one node URL is required');
  if (!Number.isSafeInteger(quorum) || quorum < 2 || quorum > 3) throw new Error('policy quorum is invalid');
  const trustedAuthorities = readJson(authorityTrustFile || path.join(path.dirname(authorityDirectory), 'authority-trust.json'), null);
  const authorityNames = ['authority-1', 'authority-2', 'authority-3'];
  if (!trustedAuthorities || authorityNames.some(name => typeof trustedAuthorities[name] !== 'string')) throw new Error('authority trust material missing or invalid');
  const webauthnTrustFile = path.join(authorityDirectory, 'webauthn-authorities.json');
  const webauthnAuthorities = readJson(webauthnTrustFile, {});
  const webauthnChallenges = new Map();
  const developmentSessions = new Map();
  const nodeRequest = (index, route, { method = 'GET', payload, security } = {}) => {
    if (nodeTransport) return nodeTransport(index, route, { method, payload, security });
    return requestJson(`${nodeUrls[index]}${route}`, method, payload, serviceToken, security);
  };
  const statuses = () => Promise.all(nodeUrls.map(async (url, index) => { try { return sanitizeNodeStatus((await nodeRequest(index, '/status')).body, `node-${String.fromCharCode(97 + index)}`); } catch { return { name: `node-${String.fromCharCode(97 + index)}`, mode: 'offline', error: 'unavailable' }; } }));
  const auditReports = () => Promise.all(nodeUrls.map(async (url, index) => { try { const result = await nodeRequest(index, '/audit'); return result.status === 200 ? result.body : { node: `node-${String.fromCharCode(97 + index)}`, verification: { valid: false }, events: [] }; } catch { return { node: `node-${String.fromCharCode(97 + index)}`, verification: { valid: false }, events: [] }; } }));
  const commandAll = (endpoint, payload, security) => Promise.all(nodeUrls.map((url, index) => nodeRequest(index, endpoint, { method: 'POST', payload, security }).catch(() => ({ status: 503, body: {} }))));
  const securityEvents = [];
  const visualForensicsLedger = [];
  const gossipReceipts = [];
  function recordSecurityEvent(request, outcome, stage) {
    const timestamp = Number(request.headers['x-request-timestamp']);
    securityEvents.push({
      at: new Date().toISOString(),
      requestIdHash: typeof request.headers['x-request-id'] === 'string' ? crypto.createHash('sha256').update(request.headers['x-request-id']).digest('hex') : null,
      timestampDriftMs: Number.isSafeInteger(timestamp) ? Date.now() - timestamp : null,
      stage,
      outcome
    });
    if (securityEvents.length > 100) securityEvents.shift();
  }
  let policyQueue = Promise.resolve();
  function serializePolicy(operation) {
    const result = policyQueue.then(operation, operation);
    policyQueue = result.then(() => undefined, () => undefined);
    return result;
  }
  const server = http.createServer(async (request, response) => {
    metrics.increment('http_requests_total');
    const url = new URL(request.url, 'http://dashboard.local'); const route = url.pathname;
    try {
      if (!rateLimiter.allow(clientKey(request))) {
        recordSecurityEvent(request, 'rejected', 'rate-limit');
        return json(response, 429, { error: 'rate-limited' });
      }
      if (await registerExtensions({ request, response, route, url, method: request.method, json, isAdmin: equal(request.headers['x-dashboard-admin-token'], adminToken) || Boolean(developmentSessions.get(cookieValue(request, 'danms_dev_admin'))?.expiresAt > Date.now() && process.env.NODE_ENV !== 'production'), replayCache, metrics, recordSecurityEvent, statuses, auditReports, incidentAnalyst, incidentRateLimiter, staticDirectory, logger })) return;
      if (request.method === 'GET' && route === '/') { response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); return response.end(fs.readFileSync(path.join(staticDirectory, 'index.html'))); }
      if (request.method === 'GET' && route === '/api/status') return json(response, 200, { nodes: await statuses() });
      if (request.method === 'GET' && route === '/api/hackathon-manifest') return json(response, 200, extendManifest({
        event: 'Meta Global AI Developer Hackathon', eventWindow: 'Oct 26 - Nov 4',
        workstreams: {
          'Pre-Existing Base MVP Scaffold': [
            'Three-node local security service and dashboard',
            'Ed25519 policy quorum, SHA-256 integrity checks, signed snapshots, quarantine, and verified rollback',
            'Replay-protected authenticated operations and sanitized audit-chain verification',
            'Meta incident analyst with deterministic evidence-grounded fallback'
          ],
          'Newly Engineered During Meta Hackathon (Oct 26 - Nov 4)': [
            'Chameleon decoy honeypot with signed threat fingerprints and model-aware synthetic responses',
            'Verified-event policy synthesis with a signed 50-event dry-run certificate',
            'WebAuthn passkey authority enrollment and quorum proposal approvals',
            'Privacy-first visual/voice forensics with verified audit correlation',
            'Ed25519 threat-antibody gossip, signed peer receipts, and inoculated rate-limit posture',
            'Unified six-dimension audit ledger and structured submission manifest'
          ]
        },
        implementationBoundary: 'No external backend packages; live model providers are optional and fall back deterministically.'
      }));
      if (request.method === 'GET' && route === '/api/policy/proposal') {
        const current = await statuses(); const sequence = Math.max(...current.map(node => node.lastPolicySequence || 0)) + 1;
        return json(response, 200, { update: makePolicyUpdate(sequence, { enforcement: 'observe-only', changeWindow: 'operator-requested' }), quorum });
      }
      if (request.method === 'GET' && route === '/api/audit') {
        const [reports, nodeStatuses] = await Promise.all([auditReports(), statuses()]);
        const nodes = reports.map(report => ({
          ...report,
          allAspects: {
            hashChain: { valid: report.verification?.valid === true, entries: report.verification?.entries || 0, head: report.verification?.head || null, signerPublicKeyFingerprint: report.nodePublicKeyFingerprint || null },
            replayAndRateLimit: { recentRequests: securityEvents.slice(-50) },
            snapshotIntegrity: {
              snapshots: (report.events || []).filter(event => event.type === 'snapshot-created' || event.type === 'rollback-verified').map(event => ({
                eventId: `${report.node}:${event.index}`, type: event.type, digest: event.evidence?.digest || event.evidence?.restored || null,
                signatureVerified: event.evidence?.snapshotSignatureVerified === true
              }))
            },
            aiPrivacy: { status: 'payload-projections-are-allowlisted', redactedFields: report.privacyLedger?.redactedFields || 0, categories: report.privacyLedger?.categories || {} },
            deceptionAndGossip: { events: (report.events || []).filter(event => ['deception-probe', 'threat-antibody-created', 'gossip-inoculated'].includes(event.type)) }
          }
        }));
        return json(response, 200, {
          nodes,
          auditPillars: {
            hashChainAndSignatures: { nodesVerified: nodes.filter(node => node.verification?.valid === true).length, nodesTotal: nodes.length },
            antiReplayAndRateLimit: { recentRequests: securityEvents.slice(-50), metrics: metrics.snapshot() },
            snapshotIntegrity: { nodes: nodeStatuses.map(node => ({ node: node.name, digest: node.currentDigest || null, quarantined: Boolean(node.quarantined) })) },
            aiPrivacyAndSanitization: {
              redactedFields: nodes.reduce((total, node) => total + (node.privacyLedger?.redactedFields || 0), 0),
              categories: ['tokens', 'secrets', 'private keys', 'filesystem paths'],
              rawCredentialsIncluded: false
            },
            deceptionAndGossip: { eventCount: nodes.reduce((total, node) => total + node.allAspects.deceptionAndGossip.events.length, 0) },
            exportVerification: { algorithm: 'SHA-256 + Ed25519', verifier: 'npm run verify-audit' }
          }
        }, url.searchParams.get('download') === '1' ? { 'content-disposition': 'attachment; filename="danms-audit-evidence.json"' } : {});
      }
      if (request.method === 'GET' && route === '/api/audit/360') {
        const [reports, nodeStatuses] = await Promise.all([auditReports(), statuses()]);
        const verifiedReports = reports.filter(report => verifySanitizedAuditEvidence(report).valid);
        const records = verifiedReports.flatMap(report => report.proof.records.map(record => ({
          node: report.node, index: record.index, previousHash: record.previousHash, currentHash: record.hash,
          signerFingerprint: report.nodePublicKeyFingerprint, signatureVerified: true
        })));
        const eventRows = verifiedReports.flatMap(report => report.events.map(event => ({
          node: report.node, eventId: `${report.node}:${event.index}`, at: event.at, type: event.type,
          outcome: event.outcome, evidence: event.evidence
        })));
        const detectionTimes = [];
        const recoveryTimes = [];
        for (const report of verifiedReports) {
          let detectedAt = null;
          for (const event of report.events) {
            if (event.type === 'tamper-detected') detectedAt = Date.parse(event.at);
            if (detectedAt && event.type === 'quarantine-applied') {
              const elapsed = Date.parse(event.at) - detectedAt;
              if (Number.isFinite(elapsed) && elapsed >= 0) detectionTimes.push(elapsed);
            }
            if (detectedAt && event.type === 'rollback-verified') {
              const elapsed = Date.parse(event.at) - detectedAt;
              if (Number.isFinite(elapsed) && elapsed >= 0) recoveryTimes.push(elapsed);
              detectedAt = null;
            }
          }
        }
        const timestampDrifts = securityEvents.map(event => event.timestampDriftMs).filter(Number.isFinite);
        const latestAcceptedPolicy = eventRows.filter(event => event.type === 'policy-accepted').at(-1);
        const latestPolicyApprovers = Array.isArray(latestAcceptedPolicy?.evidence?.approvers)
          ? [...new Set(latestAcceptedPolicy.evidence.approvers.filter(name => authorityNames.includes(name)))] : [];
        const aiPrivacy = verifiedReports.map(report => ({
          node: report.node, strippedFieldCounts: report.privacyLedger?.categories || {},
          redactedFields: report.privacyLedger?.redactedFields || 0
        }));
        const visualMasks = visualForensicsLedger.reduce((sum, item) => sum + item.redactionBoxCount, 0);
        return json(response, 200, {
          hashChainLedger: {
            chainVerificationStatus: reports.map(report => ({ node: report.node, valid: verifySanitizedAuditEvidence(report).valid })),
            publicKeyFingerprints: verifiedReports.map(report => ({ node: report.node, fingerprint: report.nodePublicKeyFingerprint })),
            links: records
          },
          antiReplayLedger: {
            recentRequestNonces: securityEvents.slice(-100).map(event => ({ requestIdHash: event.requestIdHash, timestampDriftMs: event.timestampDriftMs, outcome: event.outcome, stage: event.stage })),
            timestampDrift: { samples: timestampDrifts.length, maxAbsMs: timestampDrifts.length ? Math.max(...timestampDrifts.map(Math.abs)) : 0 },
            rateLimitCounters: metrics.snapshot(),
            policySequenceLocks: nodeStatuses.map(node => ({ node: node.name, sequence: node.lastPolicySequence || 0 }))
          },
          snapshotIntegrityLedger: {
            nodes: nodeStatuses.map(node => ({ node: node.name, currentDigest: node.currentDigest, quarantined: node.quarantined, safeMode: node.mode === 'safe-mode' })),
            events: eventRows.filter(event => ['snapshot-created', 'tamper-detected', 'deception-probe', 'rollback-verified'].includes(event.type)).map(event => ({
              ...event, digest: event.evidence?.digest || event.evidence?.actual || event.evidence?.restored || null
            }))
          },
          aiBoundaryLedger: {
            proofOfStrippedFields: aiPrivacy, sam31VisualMaskCount: visualMasks,
            museSparkReferenceValidation: visualForensicsLedger.map(item => ({
              at: item.at, valid: item.referencesValidated, citedEventCount: item.verifiedEventIds.length,
              verifiedEventIds: item.verifiedEventIds
            }))
          },
          deceptionAndGossipLedger: {
            honeypotFingerprints: eventRows.filter(event => ['deception-probe', 'threat-fingerprint'].includes(event.type)),
            peerInoculationReceipts: gossipReceipts.slice(-100)
          },
          complianceSummary: {
            mttdMs: detectionTimes.length ? Math.round(detectionTimes.reduce((sum, value) => sum + value, 0) / detectionTimes.length) : null,
            mttrMs: recoveryTimes.length ? Math.round(recoveryTimes.reduce((sum, value) => sum + value, 0) / recoveryTimes.length) : null,
            quorumThresholdStatus: {
              required: quorum, availableAuthorities: authorityNames.length,
              met: quorum >= 2 && quorum <= authorityNames.length,
              latestAcceptedPolicy: latestAcceptedPolicy ? {
                eventId: latestAcceptedPolicy.eventId, distinctApprovers: latestPolicyApprovers.length,
                met: latestPolicyApprovers.length >= quorum
              } : { status: 'no-accepted-policy-recorded' }
            }
          }
        });
      }
      if (request.method === 'GET' && route === '/api/timeline') {
        const [nodeStatuses, reports] = await Promise.all([statuses(), auditReports()]);
        return json(response, 200, annotateTimeline(createTimeline(nodeStatuses, reports)));
      }
      if (request.method === 'GET' && route === '/metrics') return json(response, 200, metrics.snapshot());
      const getWebAuthnChallenge = request.method === 'GET' && route === '/api/webauthn/challenge';
      if (request.method !== 'POST' && !getWebAuthnChallenge) return json(response, 404, { error: 'not-found' });
      if (request.method === 'POST' && ['/api/dev-session', '/api/dev-session/revoke'].includes(route)) {
        const security = requestSecurity(request, replayCache, { required: true });
        const expectedOrigin = `${request.socket.encrypted ? 'https' : 'http'}://${request.headers.host}`;
        let originIsLoopback = false;
        try { originIsLoopback = new URL(expectedOrigin).protocol === 'http:' && ['localhost', '127.0.0.1', '::1'].includes(new URL(expectedOrigin).hostname); }
        catch { originIsLoopback = false; }
        if (process.env.NODE_ENV === 'production' || !isLoopbackAddress(request.socket.remoteAddress) ||
            !originIsLoopback || request.headers.origin !== expectedOrigin) {
          metrics.increment('authorization_denials_total');
          return json(response, 403, { error: 'local-development-session-unavailable' });
        }
        recordSecurityEvent(request, 'accepted', route);
        const sessionCookie = 'danms_dev_admin';
        if (route.endsWith('/revoke')) {
          developmentSessions.delete(cookieValue(request, sessionCookie));
          return json(response, 200, { revoked: true }, { 'set-cookie': `${sessionCookie}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0` });
        }
        for (const [id, session] of developmentSessions) if (session.expiresAt <= Date.now()) developmentSessions.delete(id);
        if (developmentSessions.size >= 100) return json(response, 429, { error: 'development-session-capacity-reached' });
        const sessionId = crypto.randomBytes(32).toString('base64url');
        const expiresAt = Date.now() + 10 * 60 * 1000;
        developmentSessions.set(sessionId, { expiresAt });
        return json(response, 200, { enabled: true, role: 'ADMIN', expiresAt, tokenExposed: false }, {
          'set-cookie': `${sessionCookie}=${sessionId}; Path=/; HttpOnly; SameSite=Strict; Max-Age=600`
        });
      }
      const suppliedAdmin = request.headers['x-dashboard-admin-token'];
      const suppliedOperator = request.headers['x-dashboard-operator-token'];
      const sessionId = cookieValue(request, 'danms_dev_admin');
      const session = developmentSessions.get(sessionId);
      if (session && session.expiresAt <= Date.now()) developmentSessions.delete(sessionId);
      const isAdmin = equal(suppliedAdmin, adminToken) || Boolean(session && session.expiresAt > Date.now() && process.env.NODE_ENV !== 'production');
      const isOperator = operatorToken !== undefined && equal(suppliedOperator, operatorToken);
      if (!isAdmin && !isOperator) { metrics.increment('auth_failures_total'); return json(response, 401, { error: 'administrator-or-operator-token-required' }); }
      const adminOnly = ['/api/demo', '/api/incident-analysis', '/api/incident-response', '/api/deception/simulate', '/api/gossip/broadcast', '/api/visual-forensics', '/api/pre-cog/analyze', '/api/webauthn/register-authority', '/api/webauthn/register'];
      if (isOperator && adminOnly.includes(route)) { metrics.increment('authorization_denials_total'); return json(response, 403, { error: 'admin-role-required' }); }
      const mutation = ['/api/policy', '/api/demo', '/api/incident-analysis', '/api/incident-response', '/api/deception/simulate', '/api/policy/synthesize', '/api/gossip/broadcast', '/api/visual-forensics', '/api/pre-cog/analyze', '/api/webauthn/challenge', '/api/webauthn/register-authority', '/api/webauthn/register', '/api/webauthn/sign-proposal', '/api/webauthn/sign'].includes(route);
      const security = mutation ? requestSecurity(request, replayCache, { required: true }) : { checked: false };
      if (mutation && security.checked) recordSecurityEvent(request, 'accepted', route);
      let input;
      if (getWebAuthnChallenge) {
        input = { authority: url.searchParams.get('authority'), purpose: url.searchParams.get('purpose') };
        const encodedUpdate = url.searchParams.get('update');
        if (encodedUpdate) {
          try { input.update = JSON.parse(Buffer.from(encodedUpdate, 'base64url').toString('utf8')); }
          catch { return json(response, 400, { error: 'invalid-webauthn-proposal' }); }
        }
      } else input = await readJsonBody(request, route === '/api/visual-forensics' ? 12 * 1024 * 1024 : 8192);
      if (route === '/api/webauthn/challenge') {
        const { authority, purpose, update } = input;
        if (!authorityNames.includes(authority) || !['registration', 'sign-proposal'].includes(purpose)) return json(response, 400, { error: 'invalid-webauthn-challenge-request' });
        if (purpose === 'registration' && isOperator) return json(response, 403, { error: 'admin-role-required' });
        if (purpose === 'registration' && webauthnAuthorities[authority]) return json(response, 409, { error: 'authority-passkey-already-registered' });
        const origin = `${request.socket.encrypted ? 'https' : 'http'}://${request.headers.host}`;
        if (request.headers.origin && request.headers.origin !== origin) return json(response, 403, { error: 'webauthn-origin-invalid' });
        let digest;
        if (purpose === 'sign-proposal') {
          if (!webauthnAuthorities[authority]) return json(response, 409, { error: 'authority-passkey-not-registered' });
          const current = await statuses();
          const nextSequence = Math.max(0, ...current.map(node => node.lastPolicySequence || 0)) + 1;
          if (!webauthnAuthorities[authority] || !update || update.kind !== 'policy-update' ||
              update.sequence !== nextSequence || !update.payload || typeof update.payload !== 'object' || Array.isArray(update.payload)) {
            return json(response, 409, { error: 'webauthn-proposal-invalid-or-stale' });
          }
          digest = policyDigest(update);
        }
        if (webauthnChallenges.size >= 1000) return json(response, 429, { error: 'webauthn-challenge-capacity-reached' });
        const challenge = purpose === 'sign-proposal'
          ? Buffer.from(digest, 'hex').toString('base64url')
          : crypto.randomBytes(32).toString('base64url');
        const challengeId = crypto.randomUUID();
        const rpId = new URL(origin).hostname;
        webauthnChallenges.set(challengeId, { authority, purpose, challenge, origin, rpId, digest, expiresAt: Date.now() + 120000 });
        for (const [id, entry] of webauthnChallenges) if (entry.expiresAt <= Date.now()) webauthnChallenges.delete(id);
        return json(response, 200, {
          challengeId, challenge, rpId, purpose,
          ...(purpose === 'sign-proposal' ? { allowCredentialIds: [webauthnAuthorities[authority].credentialId] } : {})
        });
      }
      if (route === '/api/webauthn/register-authority' || route === '/api/webauthn/register') {
        const pending = webauthnChallenges.get(input.challengeId);
        if (!pending || pending.expiresAt <= Date.now() || pending.purpose !== 'registration' || pending.authority !== input.authority) {
          return json(response, 409, { error: 'webauthn-challenge-invalid-or-expired' });
        }
        let credential;
        try { credential = parseWebAuthnRegistration(input.registration, pending); }
        catch (error) { return json(response, 400, { error: error.message }); }
        if (Object.entries(webauthnAuthorities).some(([name, existing]) => name !== input.authority && existing.credentialId === credential.credentialId)) {
          return json(response, 409, { error: 'webauthn-credential-already-bound' });
        }
        const existing = webauthnAuthorities[input.authority];
        if (existing && (existing.credentialId !== credential.credentialId || existing.publicKey !== credential.publicKey)) {
          return json(response, 409, { error: 'authority-passkey-already-registered' });
        }
        const registrations = await Promise.all(nodeUrls.map((nodeUrl, index) => nodeRequest(index, '/webauthn/authority', { method: 'POST', payload: {
          authority: input.authority, credential
        }, security: {
          id: `${crypto.createHash('sha256').update(`${security.id}:${index}`).digest('hex').slice(0, 32)}:webauthn-register`,
          timestamp: security.timestamp
        } }).catch(() => ({ status: 503, body: {} }))));
        if (registrations.some(result => result.status !== 200)) return json(response, 503, { error: 'webauthn-trust-propagation-failed' });
        webauthnAuthorities[input.authority] = credential;
        writeJsonAtomic(webauthnTrustFile, webauthnAuthorities);
        webauthnChallenges.delete(input.challengeId);
        return json(response, 200, { registered: true, authority: input.authority, credentialIdHash: sha256(credential.credentialId) });
      }
      if (route === '/api/webauthn/sign-proposal' || route === '/api/webauthn/sign') {
        const pending = webauthnChallenges.get(input.challengeId);
        if (!pending || pending.expiresAt <= Date.now() || pending.purpose !== 'sign-proposal' || pending.authority !== input.authority) {
          return json(response, 409, { error: 'webauthn-challenge-invalid-or-expired' });
        }
        if (!input.update || policyDigest(input.update) !== pending.digest) return json(response, 409, { error: 'webauthn-proposal-digest-mismatch' });
        const registered = webauthnAuthorities[input.authority];
        const approval = {
          algorithm: 'WebAuthn', authority: input.authority, digest: pending.digest,
          credentialId: input.assertion?.credentialId,
          authenticatorData: input.assertion?.authenticatorData,
          clientDataJSON: input.assertion?.clientDataJSON,
          signature: input.assertion?.signature
        };
        const assertion = verifyWebAuthnAssertion(approval, pending.digest, registered, {
          origin: pending.origin, rpId: pending.rpId, previousSignCount: registered?.signCount || 0
        });
        if (!assertion.valid) return json(response, 403, { error: 'webauthn-assertion-invalid' });
        if (assertion.signCount > 0) registered.signCount = assertion.signCount;
        writeJsonAtomic(webauthnTrustFile, webauthnAuthorities);
        webauthnChallenges.delete(input.challengeId);
        return json(response, 200, { approval });
      }
      if (route === '/api/deception/simulate') {
        if (typeof input.node !== 'string' || !/^node-[a-c]$/.test(input.node) ||
            typeof input.input !== 'string' || input.input.length > 512) return json(response, 400, { error: 'invalid-deception-probe' });
        const index = input.node.charCodeAt(input.node.length - 1) - 97;
        if (index >= nodeUrls.length) return json(response, 404, { error: 'node-not-found' });
        const result = await nodeRequest(index, '/deception-probe', { method: 'POST', payload: { input: input.input, durationMs: input.durationMs }, security: {
          id: `${crypto.createHash('sha256').update(security.id).digest('hex').slice(0, 32)}:deception`, timestamp: security.timestamp
        } }).catch(() => ({ status: 503, body: {} }));
        if (result.status !== 200) return json(response, result.status === 400 ? 409 : 503, { error: result.body.error || 'deception-probe-failed' });
        const reports = await auditReports();
        const report = reports[index];
        const auditIndex = result.body.threatFingerprint?.auditIndex;
        const event = report?.events?.find(item => item.index === auditIndex && item.type === 'deception-probe');
        const verifiedEventIds = event && verifySanitizedAuditEvidence(report).valid ? [`${input.node}:${auditIndex}`] : [];
        const ai = typeof incidentAnalyst.deceptionResponse === 'function'
          ? await incidentAnalyst.deceptionResponse({
            commandPattern: result.body.threatFingerprint?.commandPattern,
            payloadDigest: result.body.threatFingerprint?.payloadDigest,
            verifiedEventIds
          })
          : { response: result.body.response, providerMode: 'Deterministic Fallback', modelsInvoked: [], verifiedEventIds };
        return json(response, 200, {
          ...result.body, response: ai.response, ai,
          providerMode: ai.providerMode, modelsInvoked: ai.modelsInvoked, verifiedEventIds: ai.verifiedEventIds
        });
      }
      if (route === '/api/policy/synthesize') {
        const [nodeStatuses, reports] = await Promise.all([statuses(), auditReports()]);
        const currentSequence = Math.max(0, ...nodeStatuses.map(node => node.lastPolicySequence || 0));
        const verifiedReports = reports.filter(report => verifySanitizedAuditEvidence(report).valid);
        const verifiedEvents = verifiedReports.flatMap(report => report.events.map(event => ({
          id: `${report.node}:${event.index}`, type: event.type, evidence: event.evidence
        }))).filter(event => ['tamper-detected', 'deception-probe', 'gossip-inoculated'].includes(event.type));
        const synthesis = typeof incidentAnalyst.synthesizePolicy === 'function'
          ? incidentAnalyst.synthesizePolicy({ sequence: currentSequence + 1, verifiedEvents })
          : { candidatePolicy: makePolicyUpdate(currentSequence + 1, {
            enforcement: 'quarantine-on-integrity-mismatch', requireSignedPolicy: true,
            triggerEvents: ['tamper-detected'], rateLimitPosture: 'strict', source: 'verified-audit-synthesis'
          }), providerMode: 'Deterministic Fallback', modelsInvoked: [], verifiedEventIds: verifiedEvents.map(event => event.id) };
        const update = synthesis.candidatePolicy;
        const analysis = await incidentAnalyst.analyze({ statuses: nodeStatuses, reports: verifiedReports });
        const target = nodeUrls.findIndex((_, index) => nodeStatuses[index]?.mode === 'trusted');
        if (target < 0) return json(response, 409, { error: 'no-trusted-node-for-sandbox' });
        const result = await nodeRequest(target, '/dry-run', { method: 'POST', payload: {
          candidatePolicy: update
        }, security: {
          id: `${crypto.createHash('sha256').update(security.id).digest('hex').slice(0, 32)}:dry-run`, timestamp: security.timestamp
        } }).catch(() => ({ status: 503, body: {} }));
        if (result.status !== 200) return json(response, 503, { error: 'sandbox-unavailable' });
        const sandbox = result.body;
        const { signature: sandboxSignature, ...unsigned } = sandbox;
        const proof = (await auditReports())[target]?.proof;
        const keyFingerprint = typeof proof?.publicKey === 'string' ? crypto.createHash('sha256').update(proof.publicKey).digest('hex') : '';
        if (!proof || sandbox.signerFingerprint !== keyFingerprint || !verify(proof.publicKey, stable(unsigned), sandboxSignature)) {
          return json(response, 503, { error: 'sandbox-signature-invalid' });
        }
        return json(response, 200, {
          sandbox, candidatePolicy: update, quorum,
          providerMode: analysis.providerMode || synthesis.providerMode || 'Deterministic Fallback',
          modelsInvoked: [...new Set([...(analysis.modelsInvoked || []), ...(synthesis.modelsInvoked || [])])],
          verifiedEventIds: [...new Set([...(analysis.verifiedEventIds || []), ...(synthesis.verifiedEventIds || [])])],
          analysisSource: analysis.providerSource, analysisStatus: analysis.analysisStatus, privacyLedger: analysis.privacyLedger
        });
      }
      if (route === '/api/pre-cog/analyze') {
        if (!incidentRateLimiter.allow(clientKey(request))) return json(response, 429, { error: 'pre-cog-rate-limited' });
        const [nodeStatuses, reports] = await Promise.all([statuses(), auditReports()]);
        const verifiedReports = reports.filter(report => verifySanitizedAuditEvidence(report).valid);
        const candidates = verifiedReports.flatMap(report => report.events
          .filter(event => event.type === 'tamper-detected')
          .map(event => ({ report, event })))
          .filter(item => item.event.evidence && Number.isFinite(item.event.evidence.entropyScore) &&
            Number.isFinite(item.event.evidence.sirBetaValue) && Number.isFinite(item.event.evidence.sirGammaValue));
        const selected = typeof input.node === 'string'
          ? candidates.find(item => item.report.node === input.node)
          : candidates.at(-1);
        if (!selected) return json(response, 409, { error: 'verified-predictive-threat-evidence-required' });
        const sourceNode = selected.report.node;
        const evidence = selected.event.evidence;
        const verifiedEventIds = [`${sourceNode}:${selected.event.index}`];
        const availableNodes = nodeStatuses.filter(node => node.mode !== 'offline').map(node => node.name);
        const prediction = await incidentAnalyst.predictThreat({
          entropyScore: evidence.entropyScore,
          sirBetaValue: evidence.sirBetaValue,
          sirGammaValue: evidence.sirGammaValue,
          sourceNode,
          nodes: availableNodes,
          verifiedEventIds
        });
        return json(response, 200, {
          ...prediction,
          threatType: evidence.attackClassification || 'INTEGRITY_TAMPER',
          attackVectorHash: evidence.actual,
          evidenceEventId: verifiedEventIds[0],
          predictionBoundary: 'AI prediction is advisory; patchCode is never executed. Applying policy requires distinct authority quorum approval.'
        });
      }
      if (route === '/api/gossip/broadcast') {
        const allStatuses = await statuses();
        const deceptionActive = node => Boolean(node?.quarantined) || node?.decoyState === 'DECOY_HONEYPOT';
        const sourceName = typeof input.sourceNode === 'string' ? input.sourceNode : allStatuses.find(deceptionActive)?.name;
        if (typeof sourceName !== 'string' || !/^node-[a-c]$/.test(sourceName)) return json(response, 409, { error: 'quarantined-source-node-required' });
        const sourceIndex = sourceName.charCodeAt(sourceName.length - 1) - 97;
        if (sourceIndex >= nodeUrls.length || !deceptionActive(allStatuses[sourceIndex])) return json(response, 409, { error: 'source-node-not-quarantined' });
        const source = await nodeRequest(sourceIndex, '/threat-antibody').catch(() => ({ status: 503, body: {} }));
        if (source.status !== 200) return json(response, 503, { error: 'threat-antibody-unavailable' });
        const deliveries = await Promise.all(nodeUrls.map(async (nodeUrl, index) => {
          if (index === sourceIndex) return { node: `node-${String.fromCharCode(97 + index)}`, inoculated: false, reason: 'source-node' };
          if (allStatuses[index]?.mode !== 'trusted') return { node: `node-${String.fromCharCode(97 + index)}`, inoculated: false, reason: 'peer-not-eligible' };
          const result = await nodeRequest(index, '/gossip/inoculate', { method: 'POST', payload: source.body, security: {
            id: `${crypto.createHash('sha256').update(`${security.id}:${index}`).digest('hex').slice(0, 32)}:inoculate`, timestamp: security.timestamp
          } }).catch(() => ({ status: 503, body: {} }));
          const receipt = result.body?.receipt;
          if (result.status === 200 && result.body.inoculated === true && receipt) {
            const peerReports = await auditReports();
            const peerReport = peerReports[index];
            const { signature, publicKey, ...unsignedReceipt } = receipt;
            const receiptVerified = Boolean(peerReport?.proof?.publicKey &&
              sha256(peerReport.proof.publicKey) === peerReport.nodePublicKeyFingerprint &&
              publicKey === peerReport.proof.publicKey && verify(publicKey, stable(unsignedReceipt), signature));
            if (receiptVerified) {
              gossipReceipts.push({ node: `node-${String.fromCharCode(97 + index)}`, receipt, signatureVerified: true });
              if (gossipReceipts.length > 100) gossipReceipts.shift();
            }
            return { node: `node-${String.fromCharCode(97 + index)}`, inoculated: receiptVerified, receipt: receiptVerified ? receipt : undefined };
          }
          return { node: `node-${String.fromCharCode(97 + index)}`, inoculated: false };
        }));
        return json(response, deliveries.filter(item => item.inoculated).length ? 200 : 503, { deliveries });
      }
      if (route === '/api/visual-forensics') {
        if (!incidentRateLimiter.allow(clientKey(request))) return json(response, 429, { error: 'visual-forensics-rate-limited' });
        const image = input.imageBase64;
        const hasImage = typeof image === 'string' && image.length >= 16 && image.length <= 5 * 1024 * 1024 &&
          /^(?:data:image\/(?:png|jpeg|webp);base64,)?[A-Za-z0-9+/]+={0,2}$/.test(image);
        const telemetry = Array.isArray(input.canvasTelemetry) ? input.canvasTelemetry.slice(0, 500) : [];
        if (!hasImage && !telemetry.length) return json(response, 400, { error: 'visual-evidence-required' });
        if (input.audioBase64 !== undefined && (typeof input.audioBase64 !== 'string' || input.audioBase64.length > 5 * 1024 * 1024 || !/^(?:data:audio\/[A-Za-z0-9.+-]+;base64,)?[A-Za-z0-9+/]+={0,2}$/.test(input.audioBase64))) return json(response, 400, { error: 'invalid-incident-audio' });
        if (input.voiceNote !== undefined && (typeof input.voiceNote !== 'string' || input.voiceNote.length > 1000)) return json(response, 400, { error: 'invalid-voice-note' });
        const telemetryBoxes = telemetry.filter(item => item && typeof item.text === 'string' && item.text.length <= 1024 &&
          /(?:DASHBOARD_ADMIN_TOKEN|NODE_SERVICE_TOKEN|private.?key|ip[_ ]address|filepath)/i.test(item.text) &&
          [item.x, item.y, item.width, item.height].every(value => Number.isFinite(value) && value >= 0 && value <= 1))
          .map(item => ({ label: /private.?key/i.test(item.text) ? 'private_key' : /ip[_ ]address/i.test(item.text) ? 'ip_address' : /filepath/i.test(item.text) ? 'filepath' : 'credential', box: [item.x, item.y, item.width, item.height], method: 'canvas-telemetry' }));
        const [nodeStatuses, reports] = await Promise.all([statuses(), auditReports()]);
        const verified = reports.filter(report => verifySanitizedAuditEvidence(report).valid);
        const audioDataUri = typeof input.audioBase64 === 'string' ? input.audioBase64.match(/^data:audio\/(wav|mpeg|mp3|webm|ogg);base64,/) : null;
        const visual = typeof incidentAnalyst.visualProviders === 'function'
          ? await incidentAnalyst.visualProviders({
            imageBase64: hasImage ? image.replace(/^data:image\/(?:png|jpeg|webp);base64,/, '') : undefined,
            audioBase64: input.audioBase64?.replace(/^data:audio\/[A-Za-z0-9.+-]+;base64,/, ''),
            audioFormat: audioDataUri ? (audioDataUri[1] === 'mpeg' ? 'mp3' : audioDataUri[1]) : 'wav',
            voiceNote: input.voiceNote
          })
          : { transcript: input.voiceNote || '', redactionBoxes: [], providerMode: 'Deterministic Fallback', modelsInvoked: [] };
        let redactionBoxes = [...telemetryBoxes, ...(visual.redactionBoxes || []).map(item => ({ ...item, method: 'sam-3.1' }))];
        if (!redactionBoxes.length && hasImage) redactionBoxes = [{ label: 'full-frame-withheld', box: [0, 0, 1, 1], method: 'full-frame-withheld' }];
        const voiceTranscript = sanitizeForensicTranscript(visual.transcript || '');
        const imagePayload = hasImage ? image.replace(/^data:image\/(?:png|jpeg|webp);base64,/, '') : '';
        const redactedProofHash = sha256(stable({
          imageDigest: imagePayload ? sha256(Buffer.from(imagePayload, 'base64')) : null,
          boxes: redactionBoxes.map(({ label, box }) => ({ label, box })),
          telemetryCount: telemetry.length,
          voiceTranscriptDigest: voiceTranscript ? sha256(voiceTranscript) : null
        }));
        const verifiedEventIds = verified.flatMap(report => report.events.map(event => `${report.node}:${event.index}`));
        const referencesValidated = verifiedEventIds.every(id => /^[A-Za-z0-9-]{1,64}:\d+$/.test(id));
        const correlation = await incidentAnalyst.analyze({ statuses: nodeStatuses, reports: verified, context: {
          voiceTranscript,
          redactionBoxes,
          redactedProofHash
        } });
        const modelsInvoked = [...new Set([...(visual.modelsInvoked || []), ...(correlation.modelsInvoked || [])])];
        const providerMode = correlation.providerMode !== 'Deterministic Fallback' ? correlation.providerMode
          : visual.providerMode || 'Deterministic Fallback';
        visualForensicsLedger.push({ at: new Date().toISOString(), redactionBoxCount: redactionBoxes.length, referencesValidated, verifiedEventIds });
        if (visualForensicsLedger.length > 100) visualForensicsLedger.shift();
        return json(response, 200, {
          providerMode,
          modelsInvoked,
          verifiedEventIds,
          voiceTranscript,
          voiceTranscriptSource: input.audioBase64 ? (visual.modelsInvoked?.includes('muse-voice-transcribe') ? 'muse-voice-transcribe' : 'Deterministic Fallback') : input.voiceNote ? 'operator-text-note' : 'not-provided',
          redactionSource: visual.modelsInvoked?.includes('sam-3.1') ? 'sam-3.1' : 'Deterministic Fallback',
          redactionBoxes,
          redactions: redactionBoxes.map(item => ({ label: item.label, bounds: item.box, method: item.method })),
          redactedProofHash,
          imageReturned: false,
          visualAnalysisStatus: visual.modelsInvoked?.includes('sam-3.1') ? 'segmentation-validated' : 'withheld-no-verified-segmentation-provider',
          correlationSource: correlation.providerMode || correlation.providerSource || 'Deterministic Fallback',
          privacyLedger: correlation.privacyLedger,
          incidentReport: correlation.analysis,
          verifiedCitationCount: verifiedEventIds.length,
          referencesValidated,
          limitations: [
            ...(visual.modelsInvoked?.includes('sam-3.1') ? [] : ['The image is withheld in full when no verified SAM-3.1 segmentation provider is available.']),
            ...(visual.transcript ? [] : ['No verified voice transcript is available.']),
            'Correlation cites only event IDs from independently verified node hash chains.'
          ]
        });
      }
      if (route === '/api/incident-analysis') {
        if (!incidentRateLimiter.allow(clientKey(request))) return json(response, 429, { error: 'incident-analysis-rate-limited' });
        const [nodeStatuses, reports] = await Promise.all([statuses(), auditReports()]);
        return json(response, 200, annotateAnalyst(await incidentAnalyst.analyze({ statuses: nodeStatuses, reports }), reports));
      }
      if (route === '/api/incident-response') {
        if (typeof input.node !== 'string' || !/^node-[a-c]$/.test(input.node) || !['tamper', 'scan', 'verify-snapshot', 'recover'].includes(input.action)) return json(response, 400, { error: 'invalid-incident-response' });
        const index = input.node.charCodeAt(input.node.length - 1) - 97;
        if (index >= nodeUrls.length) return json(response, 404, { error: 'node-not-found' });
        const downstream = stage => ({ id: `${crypto.createHash('sha256').update(security.id).digest('hex').slice(0, 32)}:${stage}`, timestamp: security.timestamp });
        if (input.action === 'tamper') {
          const result = await nodeRequest(index, '/simulate-tamper', { method: 'POST', payload: {}, security: downstream('incident-tamper') }).catch(() => ({ status: 503, body: {} }));
          return json(response, result.status === 200 ? 200 : 503, result.status === 200
            ? { node: input.node, action: 'tamper', operationStatus: 'simulated', tampered: result.body.tampered === true }
            : { node: input.node, action: 'tamper', operationStatus: 'failed', error: 'node-unavailable' });
        }
        if (input.action === 'verify-snapshot') {
          const snapshot = await nodeRequest(index, '/snapshot').catch(() => ({ status: 503, body: {} }));
          if (snapshot.status !== 200) return json(response, 503, { node: input.node, action: 'verify-snapshot', operationStatus: 'failed', error: 'node-unavailable' });
          return json(response, snapshot.body.valid === true ? 200 : 409, {
            node: input.node, action: 'verify-snapshot',
            operationStatus: snapshot.body.valid === true ? 'verified' : 'rejected',
            snapshotVerified: snapshot.body.valid === true
          });
        }
        if (input.action === 'scan') {
          const result = await nodeRequest(index, '/scan', { method: 'POST', payload: {}, security: downstream('incident-scan') }).catch(() => ({ status: 503, body: {} }));
          if (result.status !== 200) return json(response, 503, { node: input.node, action: 'scan', operationStatus: 'failed', error: 'node-unavailable' });
          return json(response, 200, {
            node: input.node,
            action: 'scan',
            operationStatus: result.body.clean ? 'clean' : result.body.quarantined ? 'quarantined' : 'failed',
            integrity: result.body.clean ? 'verified-clean' : 'mismatch-or-unverifiable',
            quarantined: Boolean(result.body.quarantined),
            safeMode: Boolean(result.body.safeMode)
          });
        }
        const current = await nodeRequest(index, '/status').catch(() => ({ status: 503, body: {} }));
        if (current.status !== 200) return json(response, 503, { node: input.node, action: 'recover', operationStatus: 'failed', error: 'node-unavailable' });
        if (current.body.quarantined !== true) return json(response, 409, { node: input.node, action: 'recover', operationStatus: 'rejected', error: 'node-not-quarantined' });
        const snapshot = await nodeRequest(index, '/snapshot').catch(() => ({ status: 503, body: {} }));
        if (snapshot.status !== 200 || snapshot.body.valid !== true) return json(response, 409, { node: input.node, action: 'recover', operationStatus: 'rejected', error: 'trusted-snapshot-invalid' });
        const restored = await nodeRequest(index, '/rollback', { method: 'POST', payload: {}, security: downstream('incident-recovery') }).catch(() => ({ status: 503, body: {} }));
        if (restored.status !== 200 || restored.body.restored !== true) return json(response, 503, { node: input.node, action: 'recover', operationStatus: 'failed', error: restored.body.reason || 'recovery-failed' });
        const verification = await nodeRequest(index, '/scan', { method: 'POST', payload: {}, security: downstream('incident-post-recovery-scan') }).catch(() => ({ status: 503, body: {} }));
        if (verification.status !== 200 || verification.body.clean !== true) return json(response, 503, { node: input.node, action: 'recover', operationStatus: 'post-recovery-check-failed', restored: true, postRecoveryVerified: false });
        return json(response, 200, { node: input.node, action: 'recover', operationStatus: 'verified', restored: true, postRecoveryVerified: true, digest: verification.body.digest });
      }
      if (route === '/api/policy') {
        if (!input.update || typeof input.update !== 'object' || Array.isArray(input.update) || !Array.isArray(input.approvals)) return json(response, 400, { error: 'invalid-policy-request' });
        return await serializePolicy(async () => {
          const current = await statuses(); const sequence = Math.max(...current.map(n => n.lastPolicySequence || 0)) + 1;
          if (input.update.sequence !== sequence) return json(response, 409, { error: 'stale-policy-proposal', expectedSequence: sequence });
          try { validatePolicyApprovals(input.update, input.approvals, trustedAuthorities, quorum, sequence - 1, webauthnAuthorities); }
          catch (error) { return json(response, 403, { error: error.message }); }
          const update = input.update; const approvals = input.approvals;
          const results = await commandAll('/policy', { update, approvals }, security); const summary = results.map(summarizeCommand);
          metrics.increment('replay_protected_operations_total');
          return json(response, nodeUrls.length > 0 && summary.length === nodeUrls.length && summary.every(result => result.ok) ? 200 : 503, { update: { sequence: update.sequence }, approvals: approvals.map(approval => approval.authority), results: summary });
        });
      }
      if (route === '/api/demo') {
        const downstream = stage => ({ id: `${crypto.createHash('sha256').update(security.id).digest('hex').slice(0, 32)}:${stage}`, timestamp: security.timestamp });
        const tamper = await commandAll('/simulate-tamper', {}, downstream('tamper')); const snapshot = await Promise.all(nodeUrls.map((url, index) => nodeRequest(index, '/snapshot').catch(() => ({ status: 503, body: {} })))); const detection = await commandAll('/scan', {}, downstream('detection')); const recovery = await commandAll('/rollback', {}, downstream('recovery')); const verification = await commandAll('/scan', {}, downstream('verification'));
        const groups = { tamper, snapshot, detection, recovery, verification };
        const workflow = Object.fromEntries(Object.entries(groups).map(([name, results]) => [name, results.map((result, index) => summarizeWorkflow(name, result, index))]));
        const allOk = Object.values(workflow).flat().every(result => result.ok);
        return json(response, allOk ? 200 : 503, { workflow, nodes: await statuses(), audit: await auditReports() });
      }
      return json(response, 404, { error: 'not-found' });
    } catch (error) {
      if (request.method === 'POST') recordSecurityEvent(request, 'rejected', error instanceof RequestError ? error.code : 'operation-rejected');
      metrics.increment('operation_failures_total');
      if (error instanceof RequestError) return json(response, error.code === 'request-too-large' ? 413 : error.code === 'stale-request' || error.code === 'replayed-request' ? 409 : 400, { error: error.code });
      logger.warn?.('dashboard-request-failed', { route });
      return json(response, 500, { error: 'request-failed' });
    }
  });
  server.listen(port, host, () => console.log(`Dashboard listening at http://${host}:${server.address().port}`)); return server;
}
if (require.main === module) startDashboard({ port: Number(process.env.PORT || 7000), host: process.env.HOST || '127.0.0.1', nodeUrls: (process.env.NODE_URLS || '').split(',').filter(Boolean), authorityDirectory: process.env.AUTHORITY_DIRECTORY, authorityTrustFile: process.env.AUTHORITY_TRUST_FILE, serviceToken: process.env.NODE_SERVICE_TOKEN, adminToken: process.env.DASHBOARD_ADMIN_TOKEN, operatorToken: process.env.DASHBOARD_OPERATOR_TOKEN });
module.exports = { startDashboard, requestJson, sanitizeNodeStatus };
