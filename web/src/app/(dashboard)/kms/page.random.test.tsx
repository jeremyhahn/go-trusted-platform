import * as React from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import KMSKeysPage from './page';

vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-capabilities')>()),
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

// #2057: the KMS keys page draws random bytes from the KMS backend through
// POST /kms/random (GenerateRandom: num_bytes in, base64 bytes out).

vi.mock('next/navigation', () => ({
  usePathname: () => '/kms',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const KEYS_PATH = 'GET /api/v1/kms/keys';
const BACKEND_PATH = 'GET /api/v1/kms/backend/status';
const RANDOM_PATH = 'POST /api/v1/kms/random';

const servedBackend = ok({
  backend_type: 'pkcs11',
  status: 'ready',
  device: '/dev/tpmrm0',
  capabilities: { sign: true, encrypt: true, export: false },
});

function routes(random: Answer): Record<string, Answer> {
  return {
    [KEYS_PATH]: ok({ keys: [] }),
    [BACKEND_PATH]: servedBackend,
    [RANDOM_PATH]: random,
  };
}

async function renderPage() {
  await act(async () => {
    render(withControlPlane(<KMSKeysPage />));
  });
  await screen.findByRole('heading', { level: 1, name: 'Cryptographic Keys' });
}

const toasts = () => screen.queryAllByTestId('toast').map((t) => t.textContent);

describe('KMSKeysPage random bytes', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('draws random bytes with num_bytes and shows them as hex', async () => {
    const sent = stubControlPlane(routes(ok({ bytes: 'AQID/w==' })));
    await renderPage();

    const generate = await screen.findByRole('button', { name: 'Generate random bytes' });
    fireEvent.change(screen.getByLabelText('Bytes'), { target: { value: '4' } });
    fireEvent.click(generate);

    expect((await screen.findByTestId('kms-random-hex')).textContent).toBe('010203ff');
    expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/kms/random', body: { num_bytes: 4 } });
  });

  it('sends the default 32 bytes', async () => {
    const sent = stubControlPlane(routes(ok({ bytes: 'AA==' })));
    await renderPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Generate random bytes' }));

    await waitFor(() =>
      expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/kms/random', body: { num_bytes: 32 } })
    );
  });

  it('shows a refused draw', async () => {
    stubControlPlane(routes(refused(403, 'random draw denied')));
    await renderPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Generate random bytes' }));

    await waitFor(() => expect(toasts()).toContain('Random bytes refused: random draw denied'));
    const toast = screen
      .queryAllByTestId('toast')
      .find((t) => t.textContent === 'Random bytes refused: random draw denied');
    expect(toast?.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByTestId('kms-random-hex')).toBeNull();
  });
});
