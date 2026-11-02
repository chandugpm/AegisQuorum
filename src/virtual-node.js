const { SecurityNode, readJson, sha256 } = require('./core');

// In-memory node transport for single-port deployments (e.g. Render), where
// separate loopback HTTP ports for each node are unavailable. The dashboard
// calls handleRequest with the same route/payload shape used over HTTP.
function createVirtualNodes({ root, names = ['node-a', 'node-b', 'node-c'], authorityFile, quorum = 2 }) {
  const trustedAuthorities = readJson(authorityFile, null);
  if (!trustedAuthorities || Object.keys(trustedAuthorities).length !== 3) throw new Error('authority trust file missing or invalid');
  const nodes = names.map(name => new SecurityNode({ directory: `${root}/nodes/${name}`, name, trustedAuthorities, quorum }));
  const byName = new Map(nodes.map(node => [node.name, node]));
  async function broadcastAntibody(source) {
    const envelope = source.threatAntibody();
    const deliveries = nodes.filter(node => node !== source).map(node => {
      try {
        const result = node.inoculate(envelope.packet, envelope.sourcePublicKey);
        return { peer: `virtual://${node.name}`, inoculated: result.inoculated === true, status: 200 };
      } catch {
        return { peer: `virtual://${node.name}`, inoculated: false, status: 400 };
      }
    });
    source.appendAudit('threat-antibody-broadcast', {
      attackVectorHash: envelope.packet.attackVectorHash,
      peerCount: deliveries.length,
      inoculatedCount: deliveries.filter(item => item.inoculated).length
    });
    return deliveries;
  }
  async function handleRequest(index, route, { method = 'GET', payload = {} } = {}) {
    const node = nodes[index];
    if (!node) return { status: 404, body: { error: 'node-not-found' } };
    try {
      if (method === 'GET' && route === '/status') return { status: 200, body: node.status() };
      if (method === 'GET' && route === '/audit') return { status: 200, body: node.auditReport() };
      if (method === 'GET' && route === '/snapshot') return { status: 200, body: { valid: node.verifySnapshot().valid } };
      if (method === 'GET' && route === '/threat-antibody') return { status: 200, body: node.threatAntibody() };
      if (method !== 'POST') return { status: 404, body: { error: 'not-found' } };
      const requestedVector = typeof payload.attackVectorHash === 'string' ? payload.attackVectorHash
        : route === '/deception-probe' && typeof payload.input === 'string' ? sha256(Buffer.from(payload.input.slice(0, 512))) : null;
      if (requestedVector && node.state.blockList?.includes(requestedVector)) {
        node.appendAudit('gossip-vector-blocked', { vectorHash: requestedVector });
        return { status: 403, body: { error: 'gossip-vector-blocked' } };
      }
      if (route === '/policy') return { status: 200, body: node.applyPolicy(payload.update, payload.approvals) };
      if (route === '/scan') {
        const result = node.scanIntegrity();
        if (result.quarantined && node.state.decoyState === 'DECOY_HONEYPOT') result.gossipDeliveries = await broadcastAntibody(node);
        return { status: 200, body: result };
      }
      if (route === '/rollback') return { status: 200, body: node.rollback(payload.snapshotId) };
      if (route === '/simulate-tamper') return { status: 200, body: node.simulateTamper() };
      if (route === '/deception-probe') return { status: 200, body: node.deceptionProbe(payload) };
      if (route === '/gossip/inoculate') return { status: 200, body: node.inoculate(payload.packet, payload.sourcePublicKey) };
      if (route === '/dry-run') return { status: 200, body: node.executeDryRunSandbox(payload.candidatePolicy) };
      if (route === '/webauthn/authority') return { status: 200, body: node.registerWebAuthnAuthority(payload.authority, payload.credential) };
      return { status: 404, body: { error: 'not-found' } };
    } catch (error) {
      return { status: 400, body: { error: error.message || 'operation-rejected' } };
    }
  }
  return { nodes, byName, handleRequest };
}

module.exports = { createVirtualNodes };
