import * as React from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import KeyDetailPage from './key-detail-client';

// #2057: the key detail page enables and disables the key and each of its
// versions through PUT /kms/keys/{name}/status (UpdateKeyStatus), not
// DeleteKey.

vi.mock('next/navigation', () => ({
  usePathname: () => '/kms/key-1',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const KEY_PATH = 'GET /api/v1/kms/keys/key-1';
const VERSIONS_PATH = 'GET /api/v1/kms/keys/key-1/versions';
const STATUS_PATH = 'PUT /api/v1/kms/keys/key-1/status';
const METADATA_PATH = 'GET /api/v1/kms/keys/key-1/metadata';

const ROTATE_OP = 'POST /api/v1/kms/keys/{name}/rotate';
const STATUS_OP = 'PUT /api/v1/kms/keys/{name}/status';
const KMS_OPS = [ROTATE_OP, STATUS_OP] as const;
const REASON = 'not-configured: kms';

// The server's capabilities listing: every key op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = KMS_OPS.map((op) =>
    off.includes(op) ? { op, kind: 'route', enabled: false, reason: REASON } : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function servedVersions(currentStatus: string): Answer {
  return ok({
    versions: [
      { version: 1, status: 'DISABLED', algorithm: 'AES_256_GCM', created_at: '2026-10-01T00:00:00Z' },
      { version: 2, status: currentStatus, algorithm: 'AES_256_GCM', created_at: '2026-11-01T00:00:00Z' },
    ],
  });
}

// GetKey answers KeyInfoResponse, which has no status
// (pkg/webservice/v1/rest/kms/types.go): the whole-key status is served by
// GET /kms/keys/{name}/metadata (KeyMetadataResponse).
function servedMetadata(keyStatus: string): Answer {
  return ok({
    key_id: 'key-1',
    name: 'payments',
    algorithm: 'AES_256_GCM',
    status: keyStatus,
    version: 2,
    exportable: false,
    deletion_protection: false,
  });
}

function routes(status: Answer, keyStatus = 'ENABLED', off: string[] = []): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    [KEY_PATH]: ok({
      key_id: 'key-1',
      name: 'payments',
      algorithm: 'AES_256_GCM',
      version: 2,
      created_at: '2026-10-01T00:00:00Z',
    }),
    [METADATA_PATH]: servedMetadata(keyStatus),
    [VERSIONS_PATH]: servedVersions(keyStatus),
    [STATUS_PATH]: status,
  };
}

const STATUS_OK = ok({ key_id: 'key-1', version: 2, status: 'DISABLED' });

const toasts = () => screen.queryAllByTestId('toast').map((t) => t.textContent);

async function renderPage() {
  const params = Promise.resolve({ id: 'key-1' });
  // The page reads its params with use(); await the act so the suspended
  // render resumes once the promise settles.
  await act(async () => {
    render(
      withControlPlane(
        <React.Suspense fallback={null}>
          <KeyDetailPage params={params} />
        </React.Suspense>
      )
    );
  });
  await screen.findByRole('heading', { level: 1, name: 'payments' });
}

describe('KeyDetailPage key status (#2057)', () => {
  beforeEach(() => {
    vi.stubGlobal('confirm', vi.fn(() => true));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('disables the key through PUT /kms/keys/{name}/status, not DELETE', async () => {
    const sent = stubControlPlane(routes(STATUS_OK));
    await renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Disable' }));

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'PUT',
        path: '/api/v1/kms/keys/key-1/status',
        body: { status: 'DISABLED' },
      })
    );
    await waitFor(() => expect(toasts()).toContain('Key status updated: Key "payments" is now disabled'));
    expect(sent.some((r) => r.method === 'DELETE')).toBe(false);
  });

  it('enables a disabled key', async () => {
    const sent = stubControlPlane(routes(STATUS_OK, 'DISABLED'));
    await renderPage();

    expect(screen.queryByRole('button', { name: 'Disable' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Enable' }));

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'PUT',
        path: '/api/v1/kms/keys/key-1/status',
        body: { status: 'ENABLED' },
      })
    );
    await waitFor(() => expect(toasts()).toContain('Key status updated: Key "payments" is now enabled'));
  });

  it('shows Enable when the served current version is disabled and GetKey has no status', async () => {
    stubControlPlane(routes(STATUS_OK, 'DISABLED'));
    await renderPage();

    expect(await screen.findByRole('button', { name: 'Enable' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Disable' })).toBeNull();
  });

  it('shows Enable for a key the metadata reports disabled', async () => {
    // The current version is enabled; the whole key is disabled. The key's
    // status is the metadata's, not the current version's.
    stubControlPlane({
      ...routes(STATUS_OK, 'DISABLED'),
      [VERSIONS_PATH]: servedVersions('ENABLED'),
    });
    await renderPage();

    expect(await screen.findByRole('button', { name: 'Enable' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Disable' })).toBeNull();
  });

  it('withholds the status controls the server does not offer', async () => {
    const sent = stubControlPlane(routes(STATUS_OK, 'ENABLED', [STATUS_OP]));
    await renderPage();

    const button = (name: string) => screen.getByRole('button', { name }) as HTMLButtonElement;
    await screen.findByRole('button', { name: 'Disable version 2' });
    await waitFor(() => {
      for (const name of ['Disable', 'Disable version 2']) {
        const b = button(name);
        expect(b.getAttribute('data-capability-op')).toBe(STATUS_OP);
        expect(b.getAttribute('data-capability-enabled')).toBe('false');
        expect(b.disabled).toBe(true);
        expect(b.title).toBe(REASON);
      }
      const rotate = button('Rotate');
      expect(rotate.getAttribute('data-capability-op')).toBe(ROTATE_OP);
      expect(rotate.getAttribute('data-capability-enabled')).toBe('true');
      expect(rotate.disabled).toBe(false);
    });

    fireEvent.click(button('Disable'));
    fireEvent.click(button('Disable version 2'));
    expect(sent.some((r) => r.method === 'PUT')).toBe(false);
  });

  it("changes one version's status from the versions table", async () => {
    const sent = stubControlPlane(routes(STATUS_OK));
    await renderPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Disable version 2' }));
    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'PUT',
        path: '/api/v1/kms/keys/key-1/status',
        body: { status: 'DISABLED', version: 2 },
      })
    );
    await waitFor(() =>
      expect(toasts()).toContain('Key status updated: Version 2 of key "payments" is now disabled')
    );

    await waitFor(() => expect(screen.getByRole('button', { name: 'Enable version 1' })).toHaveProperty('disabled', false));
    fireEvent.click(screen.getByRole('button', { name: 'Enable version 1' }));
    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'PUT',
        path: '/api/v1/kms/keys/key-1/status',
        body: { status: 'ENABLED', version: 1 },
      })
    );
  });

  it('sends nothing when the confirm is declined', async () => {
    vi.stubGlobal('confirm', vi.fn(() => false));
    const sent = stubControlPlane(routes(STATUS_OK));
    await renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Disable' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Disable version 2' }));

    expect(sent.some((r) => r.method === 'PUT')).toBe(false);
  });

  it('shows a refused status change', async () => {
    stubControlPlane(routes(refused(403, 'kms: status change denied')));
    await renderPage();

    fireEvent.click(screen.getByRole('button', { name: 'Disable' }));

    const text = 'Key status change refused: kms: status change denied';
    await waitFor(() => expect(toasts()).toContain(text));
    const toast = screen.queryAllByTestId('toast').find((t) => t.textContent === text);
    expect(toast?.getAttribute('data-variant')).toBe('destructive');
  });
});
