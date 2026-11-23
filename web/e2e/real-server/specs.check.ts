/**
 * Unit check of the real-server harness files, without a browser or a server:
 *
 *   node web/e2e/real-server/specs.check.ts
 *
 * (Node strips the types.) The test daemon config must point the embedded
 * server's AAGUID gate at the allowlist global-setup writes, and every browser
 * context auth.spec.ts creates by hand must carry the fixture base URL.
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

// A computed specifier: tsc (the web typecheck) does not resolve it, so the
// `.ts` extension Node needs is not a TS5097 error there.
const modPath = path.join(import.meta.dirname, 'fixtures', 'soft-authenticator.ts');
const sa: typeof import('./fixtures/soft-authenticator') = await import(modPath);

const config = fs.readFileSync(path.join(import.meta.dirname, 'platformd.test.yaml'), 'utf8');
const want = `  webauthn-aaguid-allowlist-file: webauthn-attestation/${sa.ATTESTATION_FILES.aaguidAllowlist}`;
assert.ok(config.split('\n').includes(want), `platformd.test.yaml carries "${want}"`);

const spec = fs.readFileSync(path.join(import.meta.dirname, 'auth.spec.ts'), 'utf8');
const calls = [...spec.matchAll(/browser\.newContext\(([^)]*)\)/g)];
assert.ok(calls.length > 0, 'auth.spec.ts creates at least one browser context');
for (const call of calls) {
  assert.match(call[1], /\bbaseURL\b/, `newContext call names baseURL: ${call[0]}`);
}

// The CA pages run on the real server only (#2041): the mocked spec is gone.
assert.ok(
  !fs.existsSync(path.join(import.meta.dirname, '..', 'ca-operations.spec.ts')),
  'web/e2e/ca-operations.spec.ts (the mocked CA spec) does not exist',
);
const caSpecPath = path.join(import.meta.dirname, 'ca-operations.spec.ts');
assert.ok(fs.existsSync(caSpecPath), 'real-server/ca-operations.spec.ts exists');
const caSpec = fs.readFileSync(caSpecPath, 'utf8');
assert.ok(caSpec.includes("from './fixtures'"), "ca-operations.spec.ts imports from './fixtures'");
assert.ok(!caSpec.includes('api-mock'), 'ca-operations.spec.ts does not use api-mock');
assert.ok(!caSpec.includes('page.route('), 'ca-operations.spec.ts does not route requests');
for (const route of ['/ca', '/ca/sign', '/ca/verify']) {
  assert.ok(caSpec.includes(`goto('${route}')`), `ca-operations.spec.ts visits ${route}`);
}
const caCertsSpecPath = path.join(import.meta.dirname, 'ca-certificates.spec.ts');
assert.ok(fs.existsSync(caCertsSpecPath), 'real-server/ca-certificates.spec.ts exists');
const caCertsSpec = fs.readFileSync(caCertsSpecPath, 'utf8');
assert.ok(caCertsSpec.includes("from './fixtures'"), "ca-certificates.spec.ts imports from './fixtures'");
assert.ok(!caCertsSpec.includes('api-mock'), 'ca-certificates.spec.ts does not use api-mock');
assert.ok(!caCertsSpec.includes('page.route('), 'ca-certificates.spec.ts does not route requests');

// The invitation lookup pages run on the real server only (#2056): the mocked specs are gone.
for (const name of ['invitation-accept.spec.ts', 'invitation-accept-flow.spec.ts']) {
  assert.ok(
    !fs.existsSync(path.join(import.meta.dirname, '..', name)),
    `web/e2e/${name} (the mocked invitation spec) does not exist`,
  );
}
const invitationSpecs: Record<string, string[]> = {
  'invitation-accept.spec.ts': ['goto(`/tenant/invitations/', 'goto(`/invite/'],
  'invitation-accept-flow.spec.ts': ["goto('/admin/invitations')", 'goto(`/invite/?token='],
};
for (const [name, gotos] of Object.entries(invitationSpecs)) {
  const specPath = path.join(import.meta.dirname, name);
  assert.ok(fs.existsSync(specPath), `real-server/${name} exists`);
  const body = fs.readFileSync(specPath, 'utf8');
  assert.ok(body.includes("from './fixtures'"), `${name} imports from './fixtures'`);
  assert.ok(!body.includes('api-mock'), `${name} does not use api-mock`);
  assert.ok(!body.includes('page.route('), `${name} does not route requests`);
  for (const goto of gotos) {
    assert.ok(body.includes(goto), `${name} calls ${goto}`);
  }
}
const apiMock = fs.readFileSync(path.join(import.meta.dirname, '..', 'fixtures', 'api-mock.ts'), 'utf8');
for (const helper of ['mockInvitationLookupApi', 'mockInvitationFlowApi']) {
  assert.ok(!apiMock.includes(helper), `fixtures/api-mock.ts no longer defines ${helper}`);
}

// The EAB pages run on the real server only (#2050): the mocked spec is gone.
assert.ok(
  !fs.existsSync(path.join(import.meta.dirname, '..', 'eab.spec.ts')),
  'web/e2e/eab.spec.ts (the mocked EAB spec) does not exist',
);
const eabSpecPath = path.join(import.meta.dirname, 'eab.spec.ts');
assert.ok(fs.existsSync(eabSpecPath), 'real-server/eab.spec.ts exists');
const eabSpec = fs.readFileSync(eabSpecPath, 'utf8');
assert.ok(eabSpec.includes("from './fixtures'"), "eab.spec.ts imports from './fixtures'");
assert.ok(!eabSpec.includes('api-mock'), 'eab.spec.ts does not use api-mock');
assert.ok(!eabSpec.includes('page.route('), 'eab.spec.ts does not route requests');
for (const goto of ["goto('/ca/eab')", 'goto(`/ca/eab/']) {
  assert.ok(eabSpec.includes(goto), `eab.spec.ts calls ${goto}`);
}
for (const helper of ['mockEABApi', 'createMockEABCredential']) {
  assert.ok(!apiMock.includes(helper), `fixtures/api-mock.ts no longer defines ${helper}`);
}

// Part 3 of the port (#2037): these pages run on the real server only.
const part3 = ['kms-ops', 'platform-services', 'sdn-ports', 'switch-ports', 'tenant-admin', 'tenant-lifecycle', 'tpm-keys', 'vtpm'];
for (const name of part3) {
  assert.ok(
    !fs.existsSync(path.join(import.meta.dirname, '..', `${name}.spec.ts`)),
    `web/e2e/${name}.spec.ts (the mocked spec) does not exist`,
  );
  const specPath = path.join(import.meta.dirname, `${name}.spec.ts`);
  assert.ok(fs.existsSync(specPath), `real-server/${name}.spec.ts exists`);
  const body = fs.readFileSync(specPath, 'utf8');
  assert.ok(body.includes("from './fixtures'"), `${name}.spec.ts imports from './fixtures'`);
  assert.ok(!body.includes('api-mock'), `${name}.spec.ts does not use api-mock`);
  assert.ok(!body.includes('page.route('), `${name}.spec.ts does not route requests`);
}

// Part 2 leftovers (#2036): mocked copies with real-server ports are gone.
for (const [mocked, port] of [
  ['auth', 'auth'],
  ['dashboard', 'dashboard'],
  ['iam-groups-tenants', 'iam-groups-tenants'],
  ['iam-policies', 'iam-policies'],
  ['idevid', 'idevid-port'],
]) {
  assert.ok(
    !fs.existsSync(path.join(import.meta.dirname, '..', `${mocked}.spec.ts`)),
    `web/e2e/${mocked}.spec.ts (the mocked spec) does not exist`,
  );
  assert.ok(fs.existsSync(path.join(import.meta.dirname, `${port}.spec.ts`)), `real-server/${port}.spec.ts exists`);
}
for (const helper of [
  'mockAdminTenantsApi',
  'mockTenantLifecycleApi',
  'mockRegistryApi',
  'mockGatewayBgpApi',
  'mockSwitchApi',
  'mockPlatformDaemonApi',
  'mockKmsOpsApi',
  'mockSdnBridgeApi',
  'mockTPMOpsApi',
  'mockTPMKeyOperationsApi',
  'mockOverlayApi',
  'mockVTPMRuntimeApi',
  'mockDeviceTemplateApi',
  'mockDeviceLookupApi',
  'mockIAMGroupsTenantsApi',
  'mockIAMPolicyAppApi',
  'mockIDevIDApi',
  // No spec uses these either (#2037).
  'mockHealthApi',
  'mockAllApis',
]) {
  assert.ok(!apiMock.includes(helper), `fixtures/api-mock.ts no longer defines ${helper}`);
}

console.log('specs.check: ok');
