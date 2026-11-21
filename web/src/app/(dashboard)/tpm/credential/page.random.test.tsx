import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import TPMCredentialPage from './page';

// The server draws 1 to 1024 bytes and turns 0 into its default of 32
// (#2069), so the credential page refuses any other byte count before it
// sends POST /tpm/random: the Get Random button is disabled, a hint names the
// range, and no request leaves the page.

const RANDOM_PATH = 'POST /api/v1/tpm/random';
const HINT = 'Number of bytes is a whole number from 1 to 1024';

function renderPage() {
  render(withControlPlane(<TPMCredentialPage />));
}

function setNumBytes(value: string) {
  fireEvent.change(screen.getByLabelText('Number of bytes'), { target: { value } });
}

function randomButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: 'Get Random' }) as HTMLButtonElement;
}

async function clickRandom() {
  await act(async () => {
    fireEvent.click(randomButton());
  });
}

describe('TPMCredentialPage GetRandom byte count', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it.each(['2000', '0', '-5', '1.5'])('refuses %s bytes and sends nothing', async (value) => {
    const sent = stubControlPlane({ [RANDOM_PATH]: ok({ randomBytes: 'AAEC' }) });
    renderPage();

    setNumBytes(value);

    expect(randomButton().disabled).toBe(true);
    expect(screen.getByText(HINT)).toBeTruthy();
    await clickRandom();
    expect(sent.some((r) => r.path === '/api/v1/tpm/random')).toBe(false);
  });

  it.each([
    ['1024', 1024],
    ['1', 1],
  ])('draws %s bytes', async (value, numBytes) => {
    const sent = stubControlPlane({ [RANDOM_PATH]: ok({ randomBytes: 'AAEC' }) });
    renderPage();

    setNumBytes(value);

    expect(randomButton().disabled).toBe(false);
    expect(screen.queryByText(HINT)).toBeNull();
    await clickRandom();
    await waitFor(() =>
      expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/tpm/random', body: { numBytes } })
    );
  });
});
