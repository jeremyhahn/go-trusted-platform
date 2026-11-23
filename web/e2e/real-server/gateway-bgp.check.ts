/**
 * Unit check of the gateway BGP and IPAM real-server port, without a browser
 * or a server:
 *
 *   node web/e2e/real-server/gateway-bgp.check.ts
 *
 * (Node strips the types.) The mocked web/e2e/gateway-bgp.spec.ts must be
 * gone, and its cases must live in web/e2e/real-server/gateway-bgp.spec.ts on
 * the harness fixtures, with no route mocks and no skipped cases (#2036).
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const mocked = path.join(import.meta.dirname, '..', 'gateway-bgp.spec.ts');
const ported = path.join(import.meta.dirname, 'gateway-bgp.spec.ts');

assert.equal(fs.existsSync(mocked), false, `${mocked} must be deleted: the spec runs on the real server`);
assert.equal(fs.existsSync(ported), true, `${ported} must exist`);

const text = fs.readFileSync(ported, 'utf8');
assert.ok(text.includes("from './fixtures'"), 'the spec must import the real-server fixtures');
assert.ok(text.includes("'/networking/gateway/bgp'"), 'the spec must drive /networking/gateway/bgp');
for (const banned of ['api-mock', 'auth-setup', 'page.route(', 'test.skip(', 'test.fixme(']) {
  assert.ok(!text.includes(banned), `the spec must not contain ${banned}`);
}

const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
for (const title of [
  'lists BGP peers',
  'announces a prefix',
  'withdraws a prefix',
  'allocates an IP',
  'allocate needs a device id',
  'releases an IP',
  'lists IPAM allocations',
]) {
  const re = new RegExp(`test\\(\\s*['\`"][^'\`"]*${escape(title)}`);
  assert.match(text, re, `the spec must have a test titled "${title}"`);
}

console.log('gateway-bgp.check: ok');
