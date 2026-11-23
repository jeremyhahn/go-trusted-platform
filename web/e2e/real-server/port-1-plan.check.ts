/**
 * Unit check of part 1 of the real-server ports (#2035), without a browser or
 * a server:
 *
 *   node web/e2e/real-server/port-1-plan.check.ts
 *
 * (Node strips the types.) The nine mocked part-1 specs are removed, and
 * docs/plans/1665-port-1.md lists each of the nine port specs as done and
 * every `// gap:` and `// covered:` line of them for the route audit.
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const mocked = [
  'attest-cert-record',
  'attestation-reports',
  'auth',
  'ca',
  'compute',
  'dashboard',
  'devices',
  'iam',
  'invitations',
];
for (const name of mocked) {
  assert.ok(
    !fs.existsSync(path.join(import.meta.dirname, '..', `${name}.spec.ts`)),
    `web/e2e/${name}.spec.ts (mocked) is removed`,
  );
}

const plan = fs.readFileSync(
  path.join(import.meta.dirname, '..', '..', '..', 'docs', 'plans', '1665-port-1.md'),
  'utf8',
);

const ports = [
  'devices-port',
  'device-profiles-port',
  'device-idevid-port',
  'device-vtpm-port',
  'iam-users-port',
  'iam-access-port',
  'iam-tokens-port',
  'iam-apps-port',
  'invitations-port',
];
for (const name of ports) {
  const spec = fs.readFileSync(path.join(import.meta.dirname, `${name}.spec.ts`), 'utf8');
  assert.ok(plan.includes(`${name}.spec.ts`), `plan lists ${name}.spec.ts as done`);
  for (const m of spec.matchAll(/^\s*\/\/ (gap|covered): (.+?): /gm)) {
    assert.ok(plan.includes(m[2]), `plan lists the ${m[1]} of ${name}.spec.ts: ${m[2]}`);
  }
}

const allPorts = [
  'attest-cert-record',
  'attestation-reports',
  'auth-port',
  'ca-port',
  'compute',
  'dashboard-port',
  ...ports,
];
for (const name of allPorts) {
  const file = `${name}.spec.ts`;
  const spec = fs.readFileSync(path.join(import.meta.dirname, file), 'utf8');
  assert.match(
    spec,
    /import\s*\{[^}]*\btest\b[^}]*\}\s*from\s*'\.\/fixtures'/,
    `${file} runs on the real-server fixtures`,
  );
  assert.ok(!spec.includes('page.route'), `${file} names no page.route`);
  assert.ok(!spec.includes('route.fulfill'), `${file} names no route.fulfill`);
  assert.ok(!/from\s*'\.\.\/fixtures\//.test(spec), `${file} imports no mocked-spec fixture`);
  assert.ok(
    !/api-mock|dashboard-api-mocks|device-api-mock/.test(spec),
    `${file} imports no API mock helper`,
  );
}

console.log('port-1-plan.check: ok');
