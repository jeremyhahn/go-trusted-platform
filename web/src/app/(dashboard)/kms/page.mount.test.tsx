import * as React from 'react';
import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import KMSKeysPage from './page';

// #2057: the KMS keys page mounts the digest and key-admin cards, so Hash,
// HMAC, key status and key import are reachable on /kms.

vi.mock('next/navigation', () => ({
  usePathname: () => '/kms',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));
vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-capabilities')>()),
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

describe('KMSKeysPage cards', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('mounts the digest and key-admin cards', async () => {
    stubControlPlane({
      'GET /api/v1/kms/keys': ok({ keys: [] }),
      'GET /api/v1/kms/backend/status': ok({ backend_type: 'software', status: 'ready' }),
    });
    await act(async () => {
      render(withControlPlane(<KMSKeysPage />));
    });
    await screen.findByRole('heading', { level: 1, name: 'Cryptographic Keys' });

    expect(screen.getByTestId('kms-digest-card')).toBeTruthy();
    expect(screen.getByTestId('kms-key-admin-card')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Hash' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Import key' })).toBeTruthy();
  });
});
