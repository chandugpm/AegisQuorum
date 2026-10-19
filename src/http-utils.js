class RequestError extends Error {
  constructor(code) { super(code); this.code = code; }
}

class ReplayCache {
  constructor({ ttlMs = 300000, maxEntries = 10000 } = {}) { this.ttlMs = ttlMs; this.maxEntries = maxEntries; this.entries = new Map(); }
  accept(id, timestamp = Date.now()) {
    if (typeof id !== 'string' || !/^[A-Za-z0-9._:-]{8,128}$/.test(id)) return false;
    for (const [key, expires] of this.entries) if (expires <= timestamp) this.entries.delete(key);
    if (this.entries.has(id) || this.entries.size >= this.maxEntries) return false;
    this.entries.set(id, timestamp + this.ttlMs); return true;
  }
}

function requestSecurity(request, replayCache, { required = false } = {}) {
  const id = request.headers['x-request-id']; const rawTimestamp = request.headers['x-request-timestamp'];
  if (id === undefined && rawTimestamp === undefined) {
    if (required) throw new RequestError('replay-protection-required');
    return { checked: false };
  }
  const timestamp = Number(rawTimestamp);
  if (!Number.isSafeInteger(timestamp) || Math.abs(Date.now() - timestamp) > 300000) throw new RequestError('stale-request');
  if (!replayCache?.accept(id, timestamp)) throw new RequestError('replayed-request');
  return { checked: true, id, timestamp };
}

function createMetrics() {
  const values = new Map();
  return { increment(name, amount = 1) { values.set(name, (values.get(name) || 0) + amount); }, snapshot() { return Object.fromEntries(values); } };
}

function readJsonBody(request, maxBytes = 8192) {
  const declaredLength = Number(request.headers['content-length'] || 0);
  if (declaredLength > maxBytes) return Promise.reject(new RequestError('request-too-large'));
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0; let finished = false;
    const fail = error => { if (!finished) { finished = true; request.resume(); reject(error); } };
    request.on('data', chunk => {
      size += chunk.length;
      if (size > maxBytes) return fail(new RequestError('request-too-large'));
      if (!finished) chunks.push(chunk);
    });
    request.on('error', () => fail(new RequestError('request-read-failed')));
    request.on('end', () => {
      if (finished) return;
      finished = true;
      const raw = Buffer.concat(chunks).toString('utf8');
      try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new RequestError('invalid-json')); }
    });
  });
}

function createRateLimiter({ windowMs = 60000, perClientLimit = 20, globalLimit = 120 } = {}) {
  const clients = new Map(); const global = []; let calls = 0;
  return {
    allow(clientKey, timestamp = Date.now()) {
      const after = timestamp - windowMs;
      while (global.length && global[0] <= after) global.shift();
      if (++calls % 256 === 0) {
        for (const [key, prior] of clients) {
          const active = prior.filter(time => time > after);
          if (active.length) clients.set(key, active);
          else clients.delete(key);
        }
      }
      const events = (clients.get(clientKey) || []).filter(time => time > after);
      if (events.length >= perClientLimit || global.length >= globalLimit) { clients.set(clientKey, events); return false; }
      events.push(timestamp); clients.set(clientKey, events); global.push(timestamp); return true;
    }
  };
}

function clientKey(request) { return request.socket.remoteAddress || 'unknown-client'; }

module.exports = { RequestError, ReplayCache, requestSecurity, createMetrics, readJsonBody, createRateLimiter, clientKey };
