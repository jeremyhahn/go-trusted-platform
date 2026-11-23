/**
 * Registry seed for the real-server e2e: pushes a tiny OCI image so the
 * registry spec has something to Inspect and Delete (#2063).
 *
 * The real harness starts with an empty registry and the SDK has no push,
 * so this pushes one through the OCI Distribution routes the platform
 * serves at /v2 on the host root: each blob as a monolithic upload (a POST
 * to /v2/<name>/blobs/uploads/ carrying ?digest= and the bytes, answered
 * 201), then the manifest with a PUT to /v2/<name>/manifests/<tag>
 * (answered 201). Any other answer throws, naming the route and status.
 * Only node:crypto and the Fetch API.
 */
import crypto from 'node:crypto';

export const OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json';
export const OCI_CONFIG = 'application/vnd.oci.image.config.v1+json';
export const OCI_LAYER = 'application/vnd.oci.image.layer.v1.tar';

export interface OCIDescriptor {
  mediaType: string;
  size: number;
  digest: string;
}

export interface OCIManifest {
  schemaVersion: 2;
  mediaType: typeof OCI_MANIFEST;
  config: OCIDescriptor;
  layers: OCIDescriptor[];
}

export interface TestImage {
  // ArrayBuffer-backed, so each is a valid fetch BodyInit.
  config: Uint8Array<ArrayBuffer>;
  layer: Uint8Array<ArrayBuffer>;
  manifest: OCIManifest;
  manifestBytes: Uint8Array<ArrayBuffer>;
  digests: { config: string; layer: string; manifest: string };
}

export interface PushedImage {
  name: string;
  tag: string;
  digest: string;
}

function sha256Digest(bytes: Uint8Array): string {
  return 'sha256:' + crypto.createHash('sha256').update(bytes).digest('hex');
}

/** A deterministic one-layer OCI image; the label makes its config distinct. */
export function buildTestImage(label: string): TestImage {
  const enc = new TextEncoder();
  const config = enc.encode(
    JSON.stringify({
      architecture: 'amd64',
      os: 'linux',
      config: { Labels: { 'e2e.seed': label } },
      rootfs: { type: 'layers', diff_ids: [] },
    }),
  );
  const labelBytes = enc.encode(label);
  const fixed = [0x65, 0x32, 0x65, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x0a]; // "e2e-seed\n"
  const layer = new Uint8Array(fixed.length + labelBytes.length);
  layer.set(fixed, 0);
  layer.set(labelBytes, fixed.length);
  const digests = { config: sha256Digest(config), layer: sha256Digest(layer), manifest: '' };
  const manifest: OCIManifest = {
    schemaVersion: 2,
    mediaType: OCI_MANIFEST,
    config: { mediaType: OCI_CONFIG, size: config.length, digest: digests.config },
    layers: [{ mediaType: OCI_LAYER, size: layer.length, digest: digests.layer }],
  };
  const manifestBytes = enc.encode(JSON.stringify(manifest));
  digests.manifest = sha256Digest(manifestBytes);
  return { config, layer, manifest, manifestBytes, digests };
}

async function expect201(res: Response, method: string, url: URL): Promise<void> {
  if (res.status === 201) return;
  const text = (await res.text().catch(() => '')).slice(0, 200);
  throw new Error(`registry seed: ${method} ${url.pathname} answered ${res.status}: ${text}`);
}

/**
 * Pushes buildTestImage(label) as name:tag through /v2 at baseURL (the host
 * root, not /api). fetchFn must carry the operator's session.
 */
export async function pushTestImage(
  fetchFn: typeof fetch,
  baseURL: string,
  name: string,
  tag: string,
  label = name,
): Promise<PushedImage> {
  const img = buildTestImage(label);
  const repo = name.split('/').map(encodeURIComponent).join('/');

  for (const [bytes, digest] of [
    [img.config, img.digests.config],
    [img.layer, img.digests.layer],
  ] as const) {
    const url = new URL(`/v2/${repo}/blobs/uploads/?digest=${encodeURIComponent(digest)}`, baseURL);
    const res = await fetchFn(url.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: bytes,
    });
    await expect201(res, 'POST', url);
  }

  const url = new URL(`/v2/${repo}/manifests/${encodeURIComponent(tag)}`, baseURL);
  const res = await fetchFn(url.toString(), {
    method: 'PUT',
    headers: { 'Content-Type': OCI_MANIFEST },
    body: img.manifestBytes,
  });
  await expect201(res, 'PUT', url);
  const digest = res.headers.get('Docker-Content-Digest') || img.digests.manifest;
  return { name, tag, digest };
}
