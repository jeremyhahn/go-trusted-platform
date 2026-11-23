import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { KmsDigestCard } from './kms-digest-card';

vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-capabilities')>()),
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

// #2057: the KMS digest card hashes text on the backend through the API
// client at POST /v1/kms/hash, sending the text as base64 (a Go []byte), and
// shows a refusal verbatim as a destructive toast.

const HASH = 'POST /api/v1/kms/hash';
const HELLO_B64 = 'aGVsbG8gd29ybGQ=';

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function typeText(value: string) {
  fireEvent.change(screen.getByLabelText('Text to hash'), { target: { value } });
}

describe('KmsDigestCard Hash', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('hashes text with SHA-256 by default', async () => {
    const digest = 'uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=';
    const sent = stubControlPlane({ [HASH]: ok({ hash: 'SHA-256', digest }) });
    render(withControlPlane(<KmsDigestCard />));

    typeText('hello world');
    await click('Hash');

    const result = await screen.findByTestId('kms-hash-result');
    expect(sent).toEqual([
      { method: 'POST', path: '/api/v1/kms/hash', body: { data: HELLO_B64, hash: 'SHA-256' } },
    ]);
    expect(result.textContent).toContain('SHA-256');
    expect(result.textContent).toContain(digest);
  });

  it('sends the picked algorithm', async () => {
    const sent = stubControlPlane({ [HASH]: ok({ hash: 'SHA-512', digest: 'ZGlnZXN0' }) });
    render(withControlPlane(<KmsDigestCard />));

    fireEvent.change(screen.getByLabelText('Hash algorithm'), { target: { value: 'SHA-512' } });
    typeText('hello world');
    await click('Hash');

    const result = await screen.findByTestId('kms-hash-result');
    expect(sent).toHaveLength(1);
    expect((sent[0].body as { hash: string }).hash).toBe('SHA-512');
    expect(result.textContent).toContain('SHA-512');
  });

  it('keeps Hash disabled with no text', () => {
    const sent = stubControlPlane({});
    render(withControlPlane(<KmsDigestCard />));

    const button = screen.getByRole('button', { name: 'Hash' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(sent).toHaveLength(0);
  });

  it('shows a hash refusal verbatim', async () => {
    stubControlPlane({ [HASH]: refused(400, 'invalid request: data is empty') });
    render(withControlPlane(<KmsDigestCard />));

    typeText('hello world');
    await click('Hash');

    const toast = await screen.findByText('Hash failed: invalid request: data is empty');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByTestId('kms-hash-result')).toBeNull();
  });
});
