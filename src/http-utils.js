class RequestError extends Error {
  constructor(code) { super(code); this.code = code; }
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
  const clients = new Map(); const global = [];
  return {
    allow(clientKey, timestamp = Date.now()) {
      const after = timestamp - windowMs;
      while (global.length && global[0] <= after) global.shift();
      const events = (clients.get(clientKey) || []).filter(time => time > after);
      if (events.length >= perClientLimit || global.length >= globalLimit) { clients.set(clientKey, events); return false; }
      events.push(timestamp); clients.set(clientKey, events); global.push(timestamp); return true;
    }
  };
}

function clientKey(request) { return request.socket.remoteAddress || 'unknown-client'; }

module.exports = { RequestError, readJsonBody, createRateLimiter, clientKey };
