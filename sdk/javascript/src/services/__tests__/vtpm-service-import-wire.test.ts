/**
 * VTPMService.importBundle answers with BundleResponse from
 * pkg/webservice/v1/rest/vtpm/types.go: snake_case fields at every level.
 * ApiClient only unwraps the envelope, so the service must map the wire
 * shape onto the camelCase VTPMBundle it promises.
 */

import { describe, it, expect, vi } from 'vitest';
import { ApiClient } from '../../client/api-client.js';
import { VTPMService } from '../vtpm-service.js';

/** A complete handler-shaped BundleResponse. */
const wireBundle = {
  id: 'bundle-1',
  mode: 'pre-assigned',
  manifest: {
    version: '1',
    id: 'bundle-1',
    mode: 'pre-assigned',
    hostname: 'vm-web',
    created_at: '2026-11-19T10:00:00Z',
    ek_certificate: {
      subject: 'CN=ek',
      issuer: 'CN=ca',
      serial_number: '42',
      not_before: '2026-01-01T00:00:00Z',
      not_after: '2036-01-01T00:00:00Z',
      fingerprint: 'ab:cd',
    },
    ek_algorithm: 'ECC',
    ek_handle: 0x81010001,
    secure_boot_enabled: true,
    secure_boot_keys: {
      pk_fingerprint: 'pk',
      kek_fingerprint: 'kek',
      db_fingerprint: 'db',
      owner_guid: 'guid-1',
    },
    checksums: { 'tpm2-00.permall': 'sha256:00' },
    labels: { tier: 'web' },
    cloned_from: 'tmpl-1',
  },
  tpm_state: {
    state_dir: '/var/lib/vtpm/bundle-1/tpm',
    permall_file: 'tpm2-00.permall',
    volatile_file: 'tpm2-00.volatilestate',
  },
  ovmf_state: { nvram_file: '/var/lib/vtpm/bundle-1/OVMF_VARS.fd' },
  secure_boot_keys: {
    dir: '/var/lib/vtpm/bundle-1/keys',
    pk_key: 'PK.key',
    pk_crt: 'PK.crt',
    kek_key: 'KEK.key',
    kek_crt: 'KEK.crt',
    db_key: 'db.key',
    db_crt: 'db.crt',
  },
  created_at: '2026-11-19T10:00:01Z',
  cloned_from: 'tmpl-1',
};

describe('VTPMService.importBundle wire shape', () => {
  it('returns the camelCase VTPMBundle for a snake_case BundleResponse', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ success: true, payload: wireBundle }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );
    const client = new ApiClient({
      baseUrl: 'https://platform.test/api/v1',
      fetch: fetchImpl as unknown as typeof fetch,
      retry: { maxRetries: 0 },
    });

    const result = await new VTPMService(client).importBundle(new Blob([new Uint8Array([0x1f, 0x8b])]));

    expect(result.success).toBe(true);
    expect(result.data).toEqual({
      id: 'bundle-1',
      mode: 'PRE_ASSIGNED',
      manifest: {
        version: '1',
        id: 'bundle-1',
        mode: 'PRE_ASSIGNED',
        hostname: 'vm-web',
        createdAt: '2026-11-19T10:00:00Z',
        ekCertificate: {
          subject: 'CN=ek',
          issuer: 'CN=ca',
          serialNumber: '42',
          notBefore: '2026-01-01T00:00:00Z',
          notAfter: '2036-01-01T00:00:00Z',
          fingerprint: 'ab:cd',
        },
        ekAlgorithm: 'ECC',
        ekHandle: 0x81010001,
        secureBootEnabled: true,
        secureBootKeys: {
          pkFingerprint: 'pk',
          kekFingerprint: 'kek',
          dbFingerprint: 'db',
          ownerGuid: 'guid-1',
        },
        checksums: { 'tpm2-00.permall': 'sha256:00' },
        labels: { tier: 'web' },
        clonedFrom: 'tmpl-1',
      },
      tpmState: {
        stateDir: '/var/lib/vtpm/bundle-1/tpm',
        permallFile: 'tpm2-00.permall',
        volatileFile: 'tpm2-00.volatilestate',
      },
      ovmfState: { nvramFile: '/var/lib/vtpm/bundle-1/OVMF_VARS.fd' },
      secureBootKeys: {
        dir: '/var/lib/vtpm/bundle-1/keys',
        pkKey: 'PK.key',
        pkCrt: 'PK.crt',
        kekKey: 'KEK.key',
        kekCrt: 'KEK.crt',
        dbKey: 'db.key',
        dbCrt: 'db.crt',
      },
      createdAt: '2026-11-19T10:00:01Z',
      clonedFrom: 'tmpl-1',
    });
    expect(result.data?.tpmState.stateDir).toBe('/var/lib/vtpm/bundle-1/tpm');
    expect(result.data?.createdAt).toBe('2026-11-19T10:00:01Z');
  });

  it('decodes an unknown wire mode and EK algorithm to UNSPECIFIED', async () => {
    const odd = {
      ...wireBundle,
      mode: 'INSTANCE',
      manifest: { ...wireBundle.manifest, mode: 'INSTANCE', ek_algorithm: 'ECC_P256' },
    };
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ success: true, payload: odd }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );
    const client = new ApiClient({
      baseUrl: 'https://platform.test/api/v1',
      fetch: fetchImpl as unknown as typeof fetch,
      retry: { maxRetries: 0 },
    });

    const result = await new VTPMService(client).importBundle(new Blob([new Uint8Array([0x1f, 0x8b])]));

    expect(result.data?.mode).toBe('UNSPECIFIED');
    expect(result.data?.manifest.mode).toBe('UNSPECIFIED');
    expect(result.data?.manifest.ekAlgorithm).toBe('UNSPECIFIED');
  });

  it('passes an error response through unchanged', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ code: 'INVALID', error: 'bad archive' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      })
    );
    const client = new ApiClient({
      baseUrl: 'https://platform.test/api/v1',
      fetch: fetchImpl as unknown as typeof fetch,
      retry: { maxRetries: 0 },
    });

    const result = await new VTPMService(client).importBundle(new Blob([new Uint8Array([0])]));

    expect(result.success).toBe(false);
    expect(result.data).toBeUndefined();
    expect(result.error?.message).toBe('bad archive');
  });

  it('maps the daemon REST listener response { bundle, timestamp }', async () => {
    // pkg/api/rest/vtpm_handlers.go ImportBundleResponse: a plain object
    // (no envelope) whose bundle carries flattened manifest metadata.
    const daemonResponse = {
      bundle: {
        id: 'bundle-1',
        mode: 'pre-assigned',
        hostname: 'vm-web',
        ek_algorithm: 'ECC',
        secure_boot_enabled: true,
        running: false,
        created_at: '2026-11-19T10:00:01Z',
        cloned_from: 'tmpl-1',
        labels: { tier: 'web' },
        ek_certificate: {
          subject: 'CN=ek',
          issuer: 'CN=ca',
          serial_number: '42',
          not_before: '2026-01-01T00:00:00Z',
          not_after: '2036-01-01T00:00:00Z',
          fingerprint: 'ab:cd',
        },
        secure_boot_keys: { pk_fingerprint: 'pk', kek_fingerprint: 'kek', db_fingerprint: 'db' },
      },
      timestamp: '2026-11-19T10:00:02Z',
    };
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(daemonResponse), {
        status: 201,
        headers: { 'content-type': 'application/json' },
      })
    );
    const client = new ApiClient({
      baseUrl: 'https://platform.test/api/v1',
      fetch: fetchImpl as unknown as typeof fetch,
      retry: { maxRetries: 0 },
    });

    const result = await new VTPMService(client).importBundle(new Blob([new Uint8Array([0x1f, 0x8b])]));

    expect(result.success).toBe(true);
    expect(result.data).toEqual({
      id: 'bundle-1',
      mode: 'PRE_ASSIGNED',
      manifest: {
        version: '',
        id: 'bundle-1',
        mode: 'PRE_ASSIGNED',
        hostname: 'vm-web',
        createdAt: '2026-11-19T10:00:01Z',
        ekCertificate: {
          subject: 'CN=ek',
          issuer: 'CN=ca',
          serialNumber: '42',
          notBefore: '2026-01-01T00:00:00Z',
          notAfter: '2036-01-01T00:00:00Z',
          fingerprint: 'ab:cd',
        },
        ekAlgorithm: 'ECC',
        ekHandle: 0,
        secureBootEnabled: true,
        secureBootKeys: { pkFingerprint: 'pk', kekFingerprint: 'kek', dbFingerprint: 'db', ownerGuid: '' },
        labels: { tier: 'web' },
        clonedFrom: 'tmpl-1',
      },
      tpmState: { stateDir: '', permallFile: '', volatileFile: '' },
      ovmfState: { nvramFile: '' },
      createdAt: '2026-11-19T10:00:01Z',
      clonedFrom: 'tmpl-1',
    });
  });

  it('sends the import once and surfaces a lost response without a resend', async () => {
    // Archiver.ImportFromFile persists the bundle under the archive ID, so a
    // client resend after a lost response would report ErrBundleAlreadyExists.
    const fetchImpl = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('network error: response lost after the server imported'))
      .mockResolvedValue(
        new Response(JSON.stringify({ code: 'CONFLICT', error: 'bundle already exists' }), {
          status: 409,
          headers: { 'content-type': 'application/json' },
        })
      );
    const client = new ApiClient({
      baseUrl: 'https://platform.test/api/v1',
      fetch: fetchImpl as unknown as typeof fetch,
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
    });

    const result = await new VTPMService(client).importBundle(new Blob([new Uint8Array([0x1f, 0x8b])]));

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(result.success).toBe(false);
    expect(result.error?.message).toMatch(/network error/);
  });
});
