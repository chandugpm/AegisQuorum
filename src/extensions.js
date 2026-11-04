const fs = require('node:fs');
const path = require('node:path');
const { runRedTeam } = require('./red-team');
const { exportStix } = require('./threat-intel');
const { withEventTechniques, withAnalystTechniques } = require('./mitre');
const { buildRecoveryCertificate } = require('./recovery-certificate');
const { requestSecurity, clientKey, readJsonBody, RequestError } = require('./http-utils');

// Additive hackathon extensions. Everything here is registered under NEW
// routes only and is gated by ENABLE_EXTENSIONS (default: true). When
// ENABLE_EXTENSIONS === 'false' nothing is registered and the app behaves
// exactly as the baseline. Each handler is wrapped so a failure returns a
// clean 500 for that route only and can never crash the dashboard or nodes.

const EXTENSION_ROUTES = ['/api/red-team/run', '/api/benchmarks', '/api/threat-intel/export', '/api/recovery/certificate'];

function enabled(environment = process.env) {
  return environment.ENABLE_EXTENSIONS !== 'false';
}

// context: { json, request, response, route, url, method, isAdmin, replayCache,
//            metrics, recordSecurityEvent, statuses, auditReports, incidentAnalyst,
//            incidentRateLimiter, staticDirectory, logger }
// Returns true when the request was handled by an extension route.
async function registerExtensions(context) {
  if (!enabled()) return false;
  const { request, response, route, method, json, logger } = context;
  const isExtensionRoute = EXTENSION_ROUTES.includes(route);
  if (!isExtensionRoute) return false;

  const fail = error => {
    logger?.warn?.('extension-route-failed', { route, error: error?.message });
    if (!response.headersSent) json(response, 500, { error: 'extension-failed' });
    return true;
  };

  try {
    if (route === '/api/benchmarks') {
      if (method !== 'GET') { json(response, 405, { error: 'method-not-allowed' }); return true; }
      const file = path.join(process.cwd(), 'benchmark-results.json');
      if (!fs.existsSync(file)) { json(response, 404, { error: 'benchmark-results-unavailable' }); return true; }
      json(response, 200, JSON.parse(fs.readFileSync(file, 'utf8')));
      return true;
    }

    if (route === '/api/recovery/certificate') {
      if (method !== 'GET') { json(response, 405, { error: 'method-not-allowed' }); return true; }
      const reports = await (context.auditReportsCached || context.auditReports)();
      const requested = context.url.searchParams.get('node');
      const report = requested ? reports.find(item => item.node === requested) : (reports.length === 1 ? reports[0] : null);
      if (!report) { json(response, 404, { error: 'node-report-not-found' }); return true; }
      // AI provenance from the latest visual/voice forensic correlation, when
      // one exists. The certificate never claims analysis that did not run.
      const aiProvenance = (context.visualForensicsLedger || []).at(-1) || null;
      json(response, 200, buildRecoveryCertificate(report, { aiProvenance }));
      return true;
    }

    if (route === '/api/threat-intel/export') {
      if (method !== 'GET') { json(response, 405, { error: 'method-not-allowed' }); return true; }
      const reports = await context.auditReports();
      json(response, 200, exportStix(reports));
      return true;
    }

    if (route === '/api/red-team/run') {
      if (method !== 'POST') { json(response, 405, { error: 'method-not-allowed' }); return true; }
      if (!context.isAdmin) { context.metrics.increment('authorization_denials_total'); json(response, 403, { error: 'admin-role-required' }); return true; }
      if (!context.incidentRateLimiter.allow(clientKey(request))) { json(response, 429, { error: 'red-team-rate-limited' }); return true; }
      const security = requestSecurity(request, context.replayCache, { required: true });
      if (security.checked) context.recordSecurityEvent(request, 'accepted', route);
      await readJsonBody(request); // drain/validate body; no input is required
      const result = await runRedTeam({ logger });
      json(response, 200, result);
      return true;
    }

    return false;
  } catch (error) {
    if (error instanceof RequestError) { json(response, error.code === 'stale-request' || error.code === 'replayed-request' ? 409 : 400, { error: error.code }); return true; }
    return fail(error);
  }
}

// Appends new-work entries to the hackathon manifest without altering the
// existing entries. Returns a NEW object; the input is never mutated.
function extendManifest(manifest) {
  if (!enabled() || !manifest || typeof manifest !== 'object') return manifest;
  const key = 'Newly Engineered During Meta Hackathon (Oct 26 - Nov 4)';
  const workstreams = { ...manifest.workstreams };
  workstreams[key] = [
    ...(workstreams[key] || []),
    'Red Team vs Blue Team attack simulator with a live defense timeline and scoreboard',
    'Performance benchmark harness (MTTD, MTTR, approval and audit-chain verification, false positives)',
    'MITRE ATT&CK technique tagging and a read-only STIX 2.1-style threat-intel export',
    'Proof-carrying recovery certificates with a portable JSON bundle, dashboard Proof Explorer, and offline CLI certificate verification',
    'Prompt-injection firewall with dual-model adversarial co-evolution (Baseten open-weights prediction + Meta Spark counter-antibody) and SHA-256 AI provenance proofs',
    'SAM 3.1 multiplexed 16-object edge-rack forensics scan correlated with signed quarantine evidence',
    'Rate-limit reliability hardening: shielded-node control-plane observability, control-plane read caching, and single-flight incident serialization'
  ];
  return { ...manifest, workstreams };
}

// Returns a copy of a timeline response with MITRE attackTechniques attached
// to each event that has a truthful mapping. Input is never mutated.
function annotateTimeline(timeline) {
  if (!enabled() || !timeline || !Array.isArray(timeline.events)) return timeline;
  return { ...timeline, events: timeline.events.map(withEventTechniques) };
}

// Returns a copy of an analyst response with attackTechniques derived from the
// verified event types in the supplied reports. Input is never mutated.
function annotateAnalyst(response, reports) {
  if (!enabled() || !response || typeof response !== 'object') return response;
  const eventTypes = (Array.isArray(reports) ? reports : [])
    .flatMap(report => Array.isArray(report?.events) ? report.events : [])
    .map(event => event?.type)
    .filter(type => typeof type === 'string');
  return withAnalystTechniques(response, eventTypes);
}

module.exports = { registerExtensions, extendManifest, annotateTimeline, annotateAnalyst, enabled, EXTENSION_ROUTES };
