import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { KmsDigestCard } from './kms-digest-card';

vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-capabilities')>()),
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

// #2057: the KMS digest card computes an HMAC under a named KMS key at
// POST /v1/kms/hmac/{name} and checks a tag at POST /v1/kms/hmac/{name}/verify,
// with base64 bodies; a refusal is shown verbatim as a destructive toast.

const HMAC = 'POST /api/v1/kms/hmac/mac-key';
const VERIFY = 'POST /api/v1/kms/hmac/mac-key/verify';
const HELLO_B64 = 'aGVsbG8gd29ybGQ=';

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe('KmsDigestCard HMAC', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('computes an HMAC under the named key', async () => {
    const sent = stubControlPlane({ [HMAC]: ok({ key_id: 'mac-key', hmac: 'dGFn' }) });
    render(withControlPlane(<KmsDigestCard />));

    type('Key name', 'mac-key');
    type('Message', 'hello world');
    await click('Compute HMAC');

    const toast = await screen.findByText('HMAC computed: Key mac-key');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(sent).toEqual([
      { method: 'POST', path: '/api/v1/kms/hmac/mac-key', body: { data: HELLO_B64, hash: 'SHA-256' } },
    ]);
    expect(screen.getByTestId('kms-hmac-tag-out').textContent).toBe('dGFn');
    expect((screen.getByLabelText('Tag (base64)') as HTMLInputElement).value).toBe('dGFn');
  });

  it('verifies a tag', async () => {
    const sent = stubControlPlane({ [VERIFY]: ok({ valid: true }) });
    render(withControlPlane(<KmsDigestCard />));

    type('Key name', 'mac-key');
    type('Message', 'hello world');
    type('Tag (base64)', 'dGFn');
    await click('Verify HMAC');

    const verdict = await screen.findByTestId('kms-hmac-verdict');
    expect(sent).toEqual([
      {
        method: 'POST',
        path: '/api/v1/kms/hmac/mac-key/verify',
        body: { data: HELLO_B64, hmac: 'dGFn', hash: 'SHA-256' },
      },
    ]);
    expect(verdict.textContent).toBe('Valid');
  });

  it('reports a mismatched tag', async () => {
    stubControlPlane({ [VERIFY]: ok({ valid: false }) });
    render(withControlPlane(<KmsDigestCard />));

    type('Key name', 'mac-key');
    type('Message', 'hello world');
    type('Tag (base64)', 'dGFn');
    await click('Verify HMAC');

    const verdict = await screen.findByTestId('kms-hmac-verdict');
    expect(verdict.textContent).toBe('Invalid');
  });

  it('keeps the HMAC buttons disabled with no key', () => {
    const sent = stubControlPlane({});
    render(withControlPlane(<KmsDigestCard />));

    expect((screen.getByRole('button', { name: 'Compute HMAC' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Verify HMAC' }) as HTMLButtonElement).disabled).toBe(true);
    expect(sent).toHaveLength(0);
  });

  it('shows an unknown key refusal verbatim', async () => {
    stubControlPlane({ [HMAC]: refused(404, 'key not found: mac-key') });
    render(withControlPlane(<KmsDigestCard />));

    type('Key name', 'mac-key');
    type('Message', 'hello world');
    await click('Compute HMAC');

    const toast = await screen.findByText('HMAC failed: key not found: mac-key');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByTestId('kms-hmac-tag-out')).toBeNull();
  });
});
