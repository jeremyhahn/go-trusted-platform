import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import KmsOperationsPage from './page';

// #2024 Codex P1: a verify-HMAC verdict belongs to the exact inputs it was
// computed for. Editing an input or a failed request must clear it.

const { verifyHmac } = vi.hoisted(() => ({ verifyHmac: vi.fn() }));

vi.mock('@/hooks', () => ({
  KMS_KEY_STATUSES: ['ENABLED', 'DISABLED'],
  useKmsOps: () => ({
    busy: false,
    error: null,
    importKey: vi.fn(),
    updateKeyStatus: vi.fn(),
    getKeyVersions: vi.fn(),
    hash: vi.fn(),
    hmac: vi.fn(),
    verifyHmac,
    generateRandom: vi.fn(),
    generateDataKey: vi.fn(),
    generateWrappedDataKey: vi.fn(),
    getBackendStatus: vi.fn(),
  }),
}));

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ open, children }: { open: boolean; children: ReactNode }) =>
    open ? <div role="dialog">{children}</div> : null,
  DialogContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  DialogHeader: ({ children }: { children: ReactNode }) => <>{children}</>,
  DialogFooter: ({ children }: { children: ReactNode }) => <>{children}</>,
  DialogTitle: ({ children }: { children: ReactNode }) => <>{children}</>,
  DialogDescription: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

function fillVerify() {
  const card = within(screen.getByTestId('op-verify-hmac'));
  fireEvent.change(card.getByLabelText('Key name'), { target: { value: 'k1' } });
  fireEvent.change(card.getByLabelText('Data'), { target: { value: 'hello' } });
  fireEvent.change(card.getByLabelText('HMAC (base64)'), { target: { value: 'bWFj' } });
  return card;
}

async function clickVerify(card: ReturnType<typeof within>) {
  await act(async () => {
    fireEvent.click(card.getByRole('button', { name: 'Verify HMAC' }));
  });
}

describe('KmsOperationsPage verify HMAC verdict', () => {
  afterEach(() => {
    cleanup();
    verifyHmac.mockReset();
  });

  it('clears the verdict when an input changes', async () => {
    verifyHmac.mockResolvedValue(true);
    render(<KmsOperationsPage />);
    const card = fillVerify();
    await clickVerify(card);
    expect(screen.getByTestId('verify-hmac-result').textContent).toBe('HMAC valid');

    fireEvent.change(card.getByLabelText('Data'), { target: { value: 'changed' } });
    expect(screen.queryByTestId('verify-hmac-result')).toBeNull();
  });

  it('clears the verdict when a later request fails', async () => {
    verifyHmac.mockResolvedValueOnce(true).mockResolvedValueOnce(null);
    render(<KmsOperationsPage />);
    const card = fillVerify();
    await clickVerify(card);
    expect(screen.getByTestId('verify-hmac-result').textContent).toBe('HMAC valid');

    await clickVerify(card);
    expect(verifyHmac).toHaveBeenCalledTimes(2);
    expect(screen.queryByTestId('verify-hmac-result')).toBeNull();
  });
});
