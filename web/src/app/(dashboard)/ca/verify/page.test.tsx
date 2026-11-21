import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';

afterEach(cleanup);

// The page drives the verify mutation from @/hooks/use-ca-ops; the mock keeps
// its state here so a case can resolve the call (onSuccess) or fail it.
const hook = vi.hoisted(() => ({
  verify: vi.fn(),
  reset: vi.fn(),
  data: undefined as unknown,
  error: null as Error | null,
  isLoading: false,
  onSuccess: undefined as ((data: unknown, pem: string) => void) | undefined,
}));

vi.mock('@/hooks/use-ca-ops', () => ({
  useVerifyCertificate: (options?: { onSuccess?: (data: unknown, pem: string) => void }) => {
    hook.onSuccess = options?.onSuccess;
    return {
      verify: hook.verify,
      reset: hook.reset,
      data: hook.data,
      error: hook.error,
      isLoading: hook.isLoading,
    };
  },
}));

import VerifyCertificatePage from './page';

const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

function pem(): HTMLTextAreaElement {
  return screen.getByLabelText('Certificate (PEM)') as HTMLTextAreaElement;
}

function submit(): HTMLButtonElement {
  return screen.getByRole('button', { name: 'Verify' }) as HTMLButtonElement;
}

beforeEach(() => {
  hook.verify.mockReset();
  hook.reset.mockReset();
  hook.data = undefined;
  hook.error = null;
  hook.isLoading = false;
  hook.onSuccess = undefined;
});

describe('Verify certificate page', () => {
  it('keeps submit disabled on an empty or blank PEM', () => {
    render(<VerifyCertificatePage />);
    expect(submit().disabled).toBe(true);
    fireEvent.change(pem(), { target: { value: '   \n' } });
    expect(submit().disabled).toBe(true);
    fireEvent.change(pem(), { target: { value: PEM } });
    expect(submit().disabled).toBe(false);
  });

  it('calls verify with the trimmed PEM', () => {
    render(<VerifyCertificatePage />);
    fireEvent.change(pem(), { target: { value: `\n  ${PEM}  \n` } });
    fireEvent.click(submit());
    expect(hook.verify).toHaveBeenCalledTimes(1);
    expect(hook.verify).toHaveBeenCalledWith(PEM);
  });

  it('shows the error message of a failed verification', () => {
    hook.error = new Error('certificate is malformed');
    render(<VerifyCertificatePage />);
    expect(screen.getByText('certificate is malformed')).toBeTruthy();
    expect(screen.queryByTestId('verify-result')).toBeNull();
  });

  it('renders the verdict, revocation note, chain and errors, hidden once the PEM changes', () => {
    render(<VerifyCertificatePage />);
    fireEvent.change(pem(), { target: { value: PEM } });
    fireEvent.click(submit());
    hook.data = {
      valid: false,
      chain: ['leaf', 'Platform Root'],
      errors: ['certificate has expired', 'unknown issuer'],
    };
    act(() => hook.onSuccess?.(hook.data, PEM));

    expect(screen.getByTestId('verify-result').textContent).toBe('Certificate is not valid');
    expect(screen.getByTestId('verify-revocation').textContent).toContain('Revocation checking was requested');
    expect(screen.getByTestId('verify-chain').textContent).toContain('leaf → Platform Root');
    expect(screen.getByText('certificate has expired')).toBeTruthy();
    expect(screen.getByText('unknown issuer')).toBeTruthy();

    fireEvent.change(pem(), { target: { value: `${PEM}\nX` } });
    expect(screen.queryByTestId('verify-result')).toBeNull();
    expect(screen.queryByTestId('verify-chain')).toBeNull();
    expect(screen.queryByText('certificate has expired')).toBeNull();
  });

  it('says a valid certificate is valid', () => {
    render(<VerifyCertificatePage />);
    fireEvent.change(pem(), { target: { value: PEM } });
    fireEvent.click(submit());
    hook.data = { valid: true, chain: [], errors: [] };
    act(() => hook.onSuccess?.(hook.data, PEM));
    expect(screen.getByTestId('verify-result').textContent).toBe('Certificate is valid');
    expect(screen.queryByTestId('verify-chain')).toBeNull();
  });
});
