/**
 * Unit check of ports.ts, without a browser or a server:
 *
 *   node web/e2e/real-server/ports.check.ts
 *
 * (Node strips the types.) The public and internal TLS listeners of the test
 * daemon must never share a port, whatever E2E_PORT says, and the rendered
 * config must carry both. Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import path from 'node:path';

// A computed specifier: tsc (the web typecheck) does not resolve it, so the
// `.ts` extension Node needs is not a TS5097 error there.
const modPath = path.join(import.meta.dirname, 'ports.ts');
const ports: typeof import('./ports') = await import(modPath);

// The default public port keeps the internal port the template always had.
const def = ports.pickPorts(18443);
assert.deepEqual(def, { publicPort: 18443, internalPort: 19443 });

// E2E_PORT=19443 (the old fixed internal port) moves the internal port too.
const moved = ports.pickPorts(19443);
assert.equal(moved.publicPort, 19443);
assert.notEqual(moved.internalPort, 19443, 'internal port differs from E2E_PORT 19443');
assert.notEqual(moved.internalPort, 18443, 'internal port differs from the default 18443');

// Near the top of the range the internal port goes below.
const top = ports.pickPorts(65000);
assert.ok(top.internalPort > 0 && top.internalPort <= 65535 && top.internalPort !== 65000);

// Every port gets a distinct internal port.
for (const p of [1, 1024, 18443, 19443, 64535, 64536, 65535]) {
  const got = ports.pickPorts(p);
  assert.notEqual(got.internalPort, got.publicPort, `public ${p}`);
  assert.ok(got.internalPort > 0 && got.internalPort <= 65535, `public ${p} internal ${got.internalPort}`);
}

for (const bad of [0, -1, 65536, 1.5, Number.NaN]) {
  assert.throws(() => ports.pickPorts(bad), Error, `public port ${bad}`);
}

// renderConfig rewrites both ports, the public one first.
const template = [
  'tls-port: 18443',
  'origin: https://localhost:18443',
  `tls-port: ${ports.INTERNAL_PORT_PLACEHOLDER}`,
  `origin: https://localhost:${ports.INTERNAL_PORT_PLACEHOLDER}`,
].join('\n');
assert.equal(
  ports.renderConfig(template, moved),
  [
    'tls-port: 19443',
    'origin: https://localhost:19443',
    `tls-port: ${moved.internalPort}`,
    `origin: https://localhost:${moved.internalPort}`,
  ].join('\n'),
);
// An internal port equal to the template public port is not rewritten again.
const low = ports.pickPorts(17443);
assert.equal(low.internalPort, 18443);
assert.equal(
  ports.renderConfig(template, low),
  ['tls-port: 17443', 'origin: https://localhost:17443', 'tls-port: 18443', 'origin: https://localhost:18443'].join(
    '\n',
  ),
);
assert.ok(!ports.renderConfig(template, def).includes(ports.INTERNAL_PORT_PLACEHOLDER));

console.log('ports.check: ok');
