/**
 * Static check: the part-2 real-server ports read the raw HTTP answers they
 * compare the page with through fixtures/wire.unwrapPayload. `Response.json()`
 * is the `{code, success, error, payload}` envelope, so a resource field read
 * straight off it is undefined and the assertion holds whatever the server
 * returned.
 *
 * Run: node web/e2e/real-server/port-2-wire.check.ts
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const RAW_READS = [
  'idOf(await res.json()',
  'profileOf(await res.json())',
  '(await res.json()) as {',
  '(await response.json()) as',
];

const specs: Record<string, string[]> = {
  'device-templates.spec.ts': [],
  'idevid-port.spec.ts': ['wireCount('],
  'registry-port.spec.ts': [],
};

for (const [name, extra] of Object.entries(specs)) {
  const body = fs.readFileSync(path.join(import.meta.dirname, name), 'utf8');
  assert.ok(body.includes("from './fixtures/wire'"), `${name} imports from './fixtures/wire'`);
  assert.ok(/unwrapPayload(<[^>]*>)?\(/.test(body), `${name} reads raw answers through unwrapPayload`);
  for (const raw of RAW_READS) {
    assert.ok(!body.includes(raw), `${name} reads no resource from the raw envelope (${raw})`);
  }
  for (const want of extra) {
    assert.ok(body.includes(want), `${name} reads the flush count through wireCount (protojson may write it as a string)`);
  }
}

const registry = fs.readFileSync(path.join(import.meta.dirname, 'registry-port.spec.ts'), 'utf8');
assert.ok(!registry.includes('body.data'), 'registry-port.spec.ts reads the status from payload, not body.data');

console.log('port-2-wire.check: ok');
