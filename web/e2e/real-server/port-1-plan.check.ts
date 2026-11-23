/**
 * Unit check of part 1 of the real-server ports (#2035), without a browser or
 * a server:
 *
 *   node web/e2e/real-server/port-1-plan.check.ts
 *
 * (Node strips the types.) The nine mocked part-1 specs are removed, and
 * docs/plans/1665-port-1.md lists each of the fifteen port specs as done and
 * every `// gap:` and `// covered:` line of the nine devices/iam/invitations
 * ports for the route audit. All fifteen run on the real-server fixtures
 * with no route mock or mock import, each `// covered:` reference is a test
 * line, and the round-4 page fixes are listed as fixed, not as defects.
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
  assert.ok(plan.includes(file), `plan names ${file}`);
  for (const m of spec.matchAll(
    /^\s*\/\/ covered: .+?: web\/e2e\/real-server\/([\w.-]+\.spec\.ts):(\d+)\s*$/gm,
  )) {
    const target = fs.readFileSync(path.join(import.meta.dirname, m[1]), 'utf8').split('\n');
    assert.match(
      target[Number(m[2]) - 1] ?? '',
      /^\s*test(\.describe)?\(/,
      `covered reference ${m[1]}:${m[2]} is a test line`,
    );
  }
}

const defectsAt = plan.indexOf('- Likely page defects found while porting');
assert.ok(defectsAt >= 0, 'plan has the "Likely page defects" section');
const defects = plan.slice(defectsAt);
for (const fixed of [
  'web/src/app/admin/invitations/page.tsx',
  'web/src/app/(dashboard)/iam/tokens/page.tsx',
]) {
  assert.ok(!defects.includes(fixed), `plan no longer lists ${fixed} as a page defect`);
}
assert.ok(
  defects.includes('web/src/app/(dashboard)/devices/idevid/page.tsx'),
  'plan still lists the IDevID page defect',
);
const fixedAt = plan.indexOf('Fixed on this branch');
assert.ok(fixedAt >= 0, 'plan has a "Fixed on this branch" list');
for (const sha of ['ef7863f4a', '22a9f62f8']) {
  assert.ok(plan.slice(fixedAt).includes(sha), `plan's fixed list names ${sha}`);
}

console.log('port-1-plan.check: ok');
