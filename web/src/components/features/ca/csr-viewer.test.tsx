import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CSRViewer } from './csr-viewer';

const CSR = '-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----';

function stubClipboard(writeText: (text: string) => Promise<void>) {
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
}

describe('CSRViewer', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('shows the CSR without metadata when none is given', () => {
    render(<CSRViewer csr={CSR} />);
    expect(screen.getByText(/BEGIN CERTIFICATE REQUEST/)).toBeDefined();
    expect(screen.queryByText('Subject')).toBeNull();
    expect(screen.queryByText('Public Key Algorithm')).toBeNull();
  });

  it('shows the subject and key algorithm', () => {
    render(<CSRViewer csr={CSR} subject="CN=device-7" publicKeyAlgorithm="ECDSA P-256" />);
    expect(screen.getByText('CN=device-7')).toBeDefined();
    expect(screen.getByText('ECDSA P-256')).toBeDefined();
  });

  it('shows the subject alone', () => {
    render(<CSRViewer csr={CSR} subject="CN=device-7" />);
    expect(screen.getByText('Subject')).toBeDefined();
    expect(screen.queryByText('Public Key Algorithm')).toBeNull();
  });

  it('shows the key algorithm alone', () => {
    render(<CSRViewer csr={CSR} publicKeyAlgorithm="RSA 2048" />);
    expect(screen.getByText('RSA 2048')).toBeDefined();
    expect(screen.queryByText('Subject')).toBeNull();
  });

  it('copies the CSR, shows Copied, then resets after two seconds', async () => {
    const writeText = vi.fn(() => Promise.resolve());
    stubClipboard(writeText);
    render(<CSRViewer csr={CSR} />);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
    });
    expect(writeText).toHaveBeenCalledWith(CSR);
    const copied = screen.getByRole('button', { name: 'Copied' });
    expect(copied.hasAttribute('disabled')).toBe(true);

    act(() => {
      vi.advanceTimersByTime(2000);
    });
    expect(screen.getByRole('button', { name: 'Copy' }).hasAttribute('disabled')).toBe(false);
  });

  it('logs a clipboard refusal and stays on Copy', async () => {
    const err = new Error('denied');
    stubClipboard(vi.fn(() => Promise.reject(err)));
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(<CSRViewer csr={CSR} />);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
    });
    expect(log).toHaveBeenCalledWith('Failed to copy:', err);
    expect(screen.getByRole('button', { name: 'Copy' })).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Copied' })).toBeNull();
  });

  it('shows an empty CSR without failing', () => {
    const { container } = render(<CSRViewer csr="" />);
    expect(container.querySelector('pre')?.textContent).toBe('');
  });
});
