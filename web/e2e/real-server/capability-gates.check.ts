/**
 * Shape check for capability-gates.spec.ts (#2033, epic #1665). Run from web/:
 *   node e2e/real-server/capability-gates.check.ts
 * (Node strips the types.) The real-server harness has no OVS backend, so the
 * VLAN and flow pages show their error view when the bridge read fails. The
 * spec must read the bridges from the daemon and expect that error view rather
 * than assume a bridge exists. Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const spec = fs.readFileSync(path.join(import.meta.dirname, 'capability-gates.spec.ts'), 'utf8');

assert.ok(spec.includes('sdk.sdn.listBridges('), 'the spec reads the bridges with sdk.sdn.listBridges()');
assert.ok(spec.includes("'Error Loading VLANs'"), 'the spec names the VLAN page error title');
assert.ok(spec.includes("'Error Loading Flows'"), 'the spec names the flow page error title');

function controlLine(pagePath: string): string {
  const line = spec.split('\n').find((l) => l.includes(`path: '${pagePath}'`));
  assert.ok(line, `SDN_CONTROLS has an entry for ${pagePath}`);
  return line;
}

for (const pagePath of ['/networking/vlans', '/networking/flows']) {
  assert.match(controlLine(pagePath), /needsBridge: true/, `${pagePath} needs a bridge`);
}
assert.match(controlLine('/networking/sdn'), /needsBridge: false/, '/networking/sdn needs no bridge');

console.log('capability-gates.check: ok');
