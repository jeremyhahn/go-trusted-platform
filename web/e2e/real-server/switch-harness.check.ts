/**
 * Check of the real-server switch harness, without a browser or a server:
 *
 *   node web/e2e/real-server/switch-harness.check.ts
 *
 * (Node strips the types.) The test daemon config must declare the in-memory
 * switch harness-1, and switch-harness.spec.ts must drive all five
 * SwitchService operations through the SDK against it (#2066). Exits non-zero
 * on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const dir = import.meta.dirname;

// The harness switch: a memory vendor named harness-1 under `switches:`.
const config = fs.readFileSync(path.join(dir, 'platformd.test.yaml'), 'utf8').split('\n');
const switchesAt = config.indexOf('switches:');
assert.ok(switchesAt >= 0, 'platformd.test.yaml has a top-level switches: block');
const block: string[] = [];
for (const line of config.slice(switchesAt + 1)) {
  if (line !== '' && !line.startsWith(' ')) break;
  block.push(line);
}
const nameAt = block.indexOf('  - name: harness-1');
assert.ok(nameAt >= 0, 'switches: declares `  - name: harness-1`');
assert.ok(block.slice(nameAt + 1).includes('    vendor: memory'), 'harness-1 has `    vendor: memory`');

// The spec next to this script drives every SwitchService operation on it.
const specPath = path.join(dir, 'switch-harness.spec.ts');
assert.ok(fs.existsSync(specPath), 'switch-harness.spec.ts exists next to switch-harness.check.ts');
const spec = fs.readFileSync(specPath, 'utf8');
assert.ok(spec.includes("'harness-1'"), "switch-harness.spec.ts names 'harness-1'");
for (const op of [
  'sdk.switches.listPorts',
  'sdk.switches.getPortStatus',
  'sdk.switches.enablePort',
  'sdk.switches.disablePort',
  'sdk.switches.setPortVLAN',
]) {
  assert.ok(spec.includes(op), `switch-harness.spec.ts calls ${op}`);
}

// The spec also drives the switches page itself as the seeded admin.
for (const text of ["page.goto('/networking/switches')", "getByLabel('Switch name')", 'adminPage']) {
  assert.ok(spec.includes(text), `switch-harness.spec.ts drives the switches page (${text})`);
}

console.log('switch-harness.check: ok');
