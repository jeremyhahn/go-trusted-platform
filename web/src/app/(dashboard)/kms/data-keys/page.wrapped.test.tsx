import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import DataKeysPage from './page';

vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-capabilities')>()),
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

// #2057: the data-keys page calls GenerateWrappedDataKey through the SDK
// client; the plaintext never leaves the service, so none is shown.

const ROUTE = 'POST /api/v1/kms/data-keys/wrapped';
const wrapped = ok({ wrapping_key_id: 'kek-2', wrapped_key: 'd3JhcA==' });

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
  return screen.getByRole('button', { name: 'Generate wrapped data key' }) as HTMLButtonElement;
}

describe('DataKeysPage GenerateWrappedDataKey', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('keeps Generate wrapped disabled until a wrapping key id is typed', () => {
    stubControlPlane({});
    renderPage();

    expect(generateButton().disabled).toBe(true);
    type('Wrapping key ID', 'kek-2');
    expect(generateButton().disabled).toBe(false);
  });

  it('generates a wrapped data key with a trimmed id', async () => {
    const sent = stubControlPlane({ [ROUTE]: wrapped });
    renderPage();

    type('Wrapping key ID', ' kek-2 ');
    await click('Generate wrapped data key');

    const toast = await screen.findByText('Wrapped data key generated: under kek-2');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(sent[0].body).toEqual({ wrapping_key_id: 'kek-2' });
    expect(screen.getByTestId('wrapped-key').textContent).toBe('d3JhcA==');
    expect(screen.getByText('Wrapped under kek-2')).toBeDefined();
    expect(screen.queryByTestId('data-key-plaintext')).toBeNull();
  });

  it('offers no wrapping context input', () => {
    // #2180 round 9: the pinned backend ignores the context, so it is not offered.
    stubControlPlane({ [ROUTE]: wrapped });
    renderPage();

    expect(screen.queryByLabelText('Wrapping context')).toBeNull();
  });

  it('shows the unknown wrapping key refusal', async () => {
    stubControlPlane({ [ROUTE]: refused(404, 'key not found: nope') });
    renderPage();

    type('Wrapping key ID', 'nope');
    await click('Generate wrapped data key');

    const toast = await screen.findByText('Generate wrapped data key failed: key not found: nope');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByTestId('wrapped-key')).toBeNull();
  });
});
