/**
 * Unit check of registry-seed.ts, without a browser or a server:
 *
 *   node web/e2e/real-server/fixtures/registry-seed.check.ts
 *
 * (Node strips the types.) buildTestImage must build a deterministic
 * one-layer OCI image whose digests are the sha256 of its bytes, and
 * pushTestImage must push it through /v2 as two monolithic blob uploads and
 * one manifest PUT, failing loudly on any answer that is not 201. Exits
 * non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import path from 'node:path';

// A computed specifier: tsc (the web typecheck) does not resolve it, so the
// `.ts` extension Node needs is not a TS5097 error there.
const modPath = path.join(import.meta.dirname, 'registry-seed.ts');
const seed: typeof import('./registry-seed') = await import(modPath);

const sha = (b: Uint8Array) => 'sha256:' + crypto.createHash('sha256').update(b).digest('hex');

// (1) buildTestImage: digests are the sha256 of the bytes, the manifest names them.
const img = seed.buildTestImage('e2e');
assert.ok(img.config instanceof Uint8Array, 'config is a Uint8Array');
assert.ok(img.layer instanceof Uint8Array, 'layer is a Uint8Array');
assert.ok(img.layer.length > 0, 'layer is not empty');
assert.equal(img.digests.config, sha(img.config));
assert.equal(img.digests.layer, sha(img.layer));
assert.equal(img.digests.manifest, sha(img.manifestBytes));
assert.equal(img.manifest.schemaVersion, 2);
assert.equal(img.manifest.mediaType, 'application/vnd.oci.image.manifest.v1+json');
assert.deepEqual(img.manifest.config, {
  mediaType: 'application/vnd.oci.image.config.v1+json',
  size: img.config.length,
  digest: img.digests.config,
});
assert.deepEqual(img.manifest.layers, [
  { mediaType: 'application/vnd.oci.image.layer.v1.tar', size: img.layer.length, digest: img.digests.layer },
]);
assert.deepEqual(img.manifestBytes, new TextEncoder().encode(JSON.stringify(img.manifest)));

const other = seed.buildTestImage('other');
assert.notEqual(other.digests.config, img.digests.config, 'a different label gives a different config');
assert.deepEqual(seed.buildTestImage('e2e').digests, img.digests, 'the same label gives the same digests');

// A stub fetch that records each request and answers with the status picked by `answer`.
type Call = { url: string; method: string; headers: Headers; body: Uint8Array };
function stub(answer: (c: Call, i: number) => number) {
  const calls: Call[] = [];
  const fn = (async (input: string | URL | Request, init?: RequestInit) => {
    const body = init?.body == null ? new Uint8Array() : new Uint8Array(await new Response(init.body).arrayBuffer());
    const c: Call = { url: String(input), method: init?.method ?? 'GET', headers: new Headers(init?.headers), body };
    calls.push(c);
    const status = answer(c, calls.length - 1);
    const headers: Record<string, string> = {};
    if (status === 201 && c.url.includes('/manifests/')) headers['Docker-Content-Digest'] = sha(c.body);
    else if (status === 201) headers['Docker-Content-Digest'] = new URL(c.url).searchParams.get('digest') ?? '';
    return new Response(status === 201 ? null : `answer ${status}`, { status, headers });
  }) as typeof fetch;
  return { fn, calls };
}

// (2) a push: config blob, layer blob, then the manifest, in that order.
const seeded = seed.buildTestImage('e2e/seed');
const ok = stub(() => 201);
const pushed = await seed.pushTestImage(ok.fn, 'https://cp.example', 'e2e/seed', 'v1');
assert.equal(ok.calls.length, 3, 'exactly three requests');
assert.equal(ok.calls[0].method, 'POST');
assert.equal(ok.calls[0].url, `https://cp.example/v2/e2e/seed/blobs/uploads/?digest=${encodeURIComponent(seeded.digests.config)}`);
assert.deepEqual(ok.calls[0].body, seeded.config);
assert.equal(ok.calls[1].method, 'POST');
assert.equal(ok.calls[1].url, `https://cp.example/v2/e2e/seed/blobs/uploads/?digest=${encodeURIComponent(seeded.digests.layer)}`);
assert.deepEqual(ok.calls[1].body, seeded.layer);
assert.equal(ok.calls[2].method, 'PUT');
assert.equal(ok.calls[2].url, 'https://cp.example/v2/e2e/seed/manifests/v1');
assert.equal(ok.calls[2].headers.get('Content-Type'), 'application/vnd.oci.image.manifest.v1+json');
assert.deepEqual(ok.calls[2].body, seeded.manifestBytes);
assert.deepEqual(pushed, { name: 'e2e/seed', tag: 'v1', digest: seeded.digests.manifest });

// (3) a 401 on the first blob upload rejects, naming the status and the route; no PUT.
const denied = stub(() => 401);
await assert.rejects(
  seed.pushTestImage(denied.fn, 'https://cp.example', 'e2e/seed', 'v1'),
  (e: unknown) => e instanceof Error && e.message.includes('401') && e.message.includes('blobs/uploads'),
);
assert.ok(!denied.calls.some((c) => c.method === 'PUT'), 'no manifest PUT after a refused upload');

// (4) a 400 on the manifest PUT rejects, naming the status and the manifest route.
const badManifest = stub((c) => (c.method === 'PUT' ? 400 : 201));
await assert.rejects(
  seed.pushTestImage(badManifest.fn, 'https://cp.example', 'e2e/seed', 'v1'),
  (e: unknown) => e instanceof Error && e.message.includes('400') && e.message.includes('manifests/v1'),
);

console.log('registry-seed.check: ok');
