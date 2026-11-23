import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import DataKeysPage from './page';

vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-capabilities')>()),
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

// #2057: the data-keys page calls GenerateDataKey through the SDK client,
// shows the plaintext once behind a Hide button and stores it nowhere.

const ROUTE = 'POST /api/v1/kms/data-keys';
const PLAIN = btoa('k'.repeat(32));
const minted = ok({ key_id: 'kek-1', plaintext_key: PLAIN, encrypted_key: 'ZW5j' });

function renderPage() {
  render(withControlPlane(<DataKeysPage />));
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function generateButton() {
  return screen.getByRole('button', { name: 'Generate data key' }) as HTMLButtonElement;
}

describe('DataKeysPage GenerateDataKey', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('renders the page and keeps Generate disabled until a key id is typed', () => {
    stubControlPlane({});
    renderPage();

    expect(screen.getByRole('heading', { name: 'Data keys' })).toBeDefined();
    expect(generateButton().disabled).toBe(true);
    type('Key ID', '  ');
    expect(generateButton().disabled).toBe(true);
    type('Key ID', 'kek-1');
    expect(generateButton().disabled).toBe(false);
  });

  it('generates a data key with a trimmed key id and shows it once', async () => {
    const sent = stubControlPlane({ [ROUTE]: minted });
    renderPage();

    type('Key ID', ' kek-1 ');
    await click('Generate data key');

    const toast = await screen.findByText('Data key generated: under kek-1');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(sent[0].body).toEqual({ key_id: 'kek-1' });
    expect(screen.getByTestId('data-key-plaintext').textContent).toBe(PLAIN);
    expect(screen.getByTestId('data-key-size').textContent).toContain('256-bit key');
    expect(screen.getByTestId('data-key-encrypted').textContent).toBe('ZW5j');
    for (const t of screen.getAllByTestId('toast')) {
      expect(t.textContent).not.toContain(PLAIN);
    }
  });

  it('sends the encryption context as base64', async () => {
    const sent = stubControlPlane({ [ROUTE]: minted });
    renderPage();

    type('Key ID', 'kek-1');
    type('Encryption context', ' tenant=a ');
    await click('Generate data key');

    await screen.findByTestId('data-key-plaintext');
    expect(sent[0].body).toEqual({ key_id: 'kek-1', context: btoa('tenant=a') });
  });

  it('hides the plaintext and stores nothing', async () => {
    stubControlPlane({ [ROUTE]: minted });
    renderPage();

    type('Key ID', 'kek-1');
    await click('Generate data key');
    await screen.findByTestId('data-key-plaintext');
    await click('Hide');

    expect(screen.queryByTestId('data-key-plaintext')).toBeNull();
    expect(screen.getByTestId('data-key-encrypted').textContent).toBe('ZW5j');
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it('shows the refusal verbatim', async () => {
    stubControlPlane({ [ROUTE]: refused(400, 'invalid kms request: key_id: is required') });
    renderPage();

    type('Key ID', 'kek-1');
    await click('Generate data key');

    const toast = await screen.findByText(
      'Generate data key failed: invalid kms request: key_id: is required'
    );
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByTestId('data-key-plaintext')).toBeNull();
  });
});
