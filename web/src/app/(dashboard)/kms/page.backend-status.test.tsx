import * as React from 'react';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import KMSKeysPage from './page';

vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-capabilities')>()),
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

// #2057: the KMS keys page shows which backend holds the keys and what it
// can do, read from GET /kms/backend/status.

vi.mock('next/navigation', () => ({
  usePathname: () => '/kms',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const KEYS_PATH = 'GET /api/v1/kms/keys';
const BACKEND_PATH = 'GET /api/v1/kms/backend/status';

function routes(backend: Answer, keys: unknown[] = []): Record<string, Answer> {
  return {
    [KEYS_PATH]: ok({ keys }),
    [BACKEND_PATH]: backend,
  };
}

const servedBackend = ok({
  backend_type: 'pkcs11',
  status: 'ready',
  device: '/dev/tpmrm0',
  capabilities: { sign: true, encrypt: true, export: false },
});

// One key in the snake_case wire shape the REST handler emits (page.tsx
// RestKeyResponse); the page maps ECDSA_P256 to ECDSA-P256.
const servedKey = {
  key_id: 'key-0001',
  name: 'release-signing',
  algorithm: 'ECDSA_P256',
  status: 'ENABLED',
  created_at: '2026-11-01T00:00:00Z',
  version: 1,
};

async function renderPage() {
  await act(async () => {
    render(withControlPlane(<KMSKeysPage />));
  });
  await screen.findByRole('heading', { level: 1, name: 'Cryptographic Keys' });
}

describe('KMSKeysPage backend status', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads the backend status through GET /kms/backend/status', async () => {
    const sent = stubControlPlane(routes(servedBackend));
    await renderPage();

    await waitFor(() =>
      expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/kms/backend/status', body: undefined })
    );
  });

  it('shows the backend type, its status and the enabled capabilities', async () => {
    stubControlPlane(routes(servedBackend));
    await renderPage();

    expect((await screen.findByTestId('kms-backend-type')).textContent).toBe('pkcs11');
    expect(screen.getByTestId('kms-backend-state').textContent).toBe('ready');
    expect(screen.getByTestId('kms-backend-device').textContent).toBe('/dev/tpmrm0');
    expect(screen.getByTestId('kms-backend-capabilities').textContent).toBe('encrypt, sign');
    expect(screen.queryByTestId('kms-backend-region')).toBeNull();
  });

  it('says so when the backend read is refused, and still lists the keys', async () => {
    stubControlPlane(routes(refused(403, 'kms: permission denied'), [servedKey]));
    await renderPage();

    expect(await screen.findByText('Backend status could not be read: kms: permission denied')).toBeTruthy();
    const row = (await screen.findByText('release-signing')).closest('tr');
    expect(row).not.toBeNull();
    expect(within(row as HTMLElement).getByText('ECDSA-P256')).toBeTruthy();
    // The refusal and the key row are on the page in the same render.
    expect(screen.getByText('Backend status could not be read: kms: permission denied')).toBeTruthy();
    expect(screen.queryByText('No results.')).toBeNull();
    expect(screen.queryByText('Error')).toBeNull();
  });
});
