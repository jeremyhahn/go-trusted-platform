/**
 * Unit check of the part-3 real-server ports, without a browser or a server:
 *
 *   node web/e2e/real-server/port-3-sdk.check.ts
 *
 * (Node strips the types.) The part-3 ports (#2037) seed and read daemon state
 * through the JS SDK's `sdk` fixture, not a hand-written request helper: the
 * old fixtures/daemon-api.ts called routes the console does not serve, and the
 * route-audit plan no longer lists those calls as SDK gaps.
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const dir = import.meta.dirname;
const read = (rel: string) => fs.readFileSync(path.join(dir, rel), 'utf8');

assert.ok(
  !fs.existsSync(path.join(dir, 'fixtures', 'daemon-api.ts')),
  'fixtures/daemon-api.ts: must not exist (the part-3 ports call the SDK)',
);

const required: Record<string, string[]> = {
  'platform-services.spec.ts': [
    'sdk.platform.getStatus(',
    'sdk.platform.listServices(',
    'sdk.platform.getServiceStatus(',
    'sdk.platform.startService(',
    'sdk.platform.stopService(',
  ],
  'sdn-ports.spec.ts': ['sdk.sdn.listPolicies(', 'sdk.sdn.applyPolicy('],
  'switch-ports.spec.ts': [
    'sdk.switches.listPorts(',
    'sdk.switches.getPortStatus(',
    'sdk.switches.enablePort(',
    'sdk.switches.disablePort(',
    'sdk.switches.setPortVLAN(',
  ],
  'tenant-admin.spec.ts': ['sdk.tenant.initBarrier('],
  'tpm-keys.spec.ts': ['sdk.tpm.getCapabilities(', 'sdk.tpm.getPlatformAttributes('],
};

for (const [spec, calls] of Object.entries(required)) {
  const src = read(spec);
  for (const banned of ['daemon-api', 'daemonApi(']) {
    assert.ok(!src.includes(banned), `${spec}: must not use the daemon-api helper (found \`${banned}\`)`);
  }
  for (const call of calls) {
    assert.ok(src.includes(call), `${spec}: must call the SDK (\`${call}\` missing)`);
  }
}

const planPath = path.join(dir, '..', '..', '..', 'docs', 'plans', '1665-port-3.md');
const gaps = fs
  .readFileSync(planPath, 'utf8')
  .split('\n')
  .filter((line) => line.startsWith('SDK gap: the JS SDK has no client'));
assert.deepEqual(gaps, [], 'docs/plans/1665-port-3.md: must list no "SDK gap: the JS SDK has no client" line');

console.log('port-3-sdk.check: ok');
