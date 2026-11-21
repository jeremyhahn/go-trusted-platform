import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';

afterEach(cleanup);

interface SignInput {
  csrPem: string;
  token: string;
  validDays?: number;
  key?: string;
}

// The page drives the SignCSR mutation from @/hooks/use-ca-ops; the mock keeps
// its state here so a case can resolve the call (onSuccess) or fail it.
const hook = vi.hoisted(() => ({
  sign: vi.fn(),
  reset: vi.fn(),
  data: undefined as unknown,
  error: null as Error | null,
  isLoading: false,
  onSuccess: undefined as ((data: unknown, input: unknown) => void) | undefined,
}));

vi.mock('@/hooks/use-ca-ops', () => ({
  useSignCSR: (options?: { onSuccess?: (data: unknown, input: unknown) => void }) => {
    hook.onSuccess = options?.onSuccess;
    return {
      sign: hook.sign,
      reset: hook.reset,
      data: hook.data,
      error: hook.error,
      isLoading: hook.isLoading,
    };
  },
}));

import SignCSRPage from './page';

const CSR = '-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----';
const CERT_PEM = '-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n';

function csr(): HTMLTextAreaElement {
  return screen.getByLabelText('CSR (PEM)') as HTMLTextAreaElement;
}

function token(): HTMLInputElement {
  return screen.getByLabelText('Platform token') as HTMLInputElement;
}

function validDays(): HTMLInputElement {
  return screen.getByLabelText('Validity (days)') as HTMLInputElement;
}

function submit(): HTMLButtonElement {
  return screen.getByRole('button', { name: 'Sign CSR' }) as HTMLButtonElement;
}

function lastInput(): SignInput {
  return hook.sign.mock.calls[hook.sign.mock.calls.length - 1][0] as SignInput;
}

beforeEach(() => {
  hook.sign.mockReset();
  hook.reset.mockReset();
  hook.data = undefined;
  hook.error = null;
  hook.isLoading = false;
  hook.onSuccess = undefined;
});

describe('Sign CSR page', () => {
  it('keeps submit disabled until both the CSR and the token are filled', () => {
    render(<SignCSRPage />);
    expect(submit().disabled).toBe(true);
    fireEvent.change(csr(), { target: { value: CSR } });
    expect(submit().disabled).toBe(true);
    fireEvent.change(token(), { target: { value: '   ' } });
    expect(submit().disabled).toBe(true);
    fireEvent.change(token(), { target: { value: 'tok-1' } });
    expect(submit().disabled).toBe(false);
    fireEvent.change(csr(), { target: { value: ' \n ' } });
    expect(submit().disabled).toBe(true);
  });

  it('calls sign with the trimmed CSR, the token and a positive validity', () => {
    render(<SignCSRPage />);
    fireEvent.change(csr(), { target: { value: `\n ${CSR} \n` } });
    fireEvent.change(token(), { target: { value: 'tok-1' } });
    fireEvent.change(validDays(), { target: { value: '30' } });
    fireEvent.click(submit());
    expect(hook.sign).toHaveBeenCalledTimes(1);
    const input = lastInput();
    expect(input.csrPem).toBe(CSR);
    expect(input.token).toBe('tok-1');
    expect(input.validDays).toBe(30);
  });

  it.each([[''], ['0'], ['-5']])('leaves validDays out for validity %j', (days) => {
    render(<SignCSRPage />);
    fireEvent.change(csr(), { target: { value: CSR } });
    fireEvent.change(token(), { target: { value: 'tok-1' } });
    fireEvent.change(validDays(), { target: { value: days } });
    // min={1} makes the browser refuse a click submit on 0 or below; submit
    // the form itself so the handler's own guard is what is tested.
    fireEvent.submit(submit().closest('form') as HTMLFormElement);
    expect(hook.sign).toHaveBeenCalledTimes(1);
    expect('validDays' in lastInput()).toBe(false);
  });

  it('shows the error message of a failed signing', () => {
    hook.error = new Error('token lacks the ca:sign-csr scope');
    render(<SignCSRPage />);
    expect(screen.getByText('token lacks the ca:sign-csr scope')).toBeTruthy();
    expect(screen.queryByTestId('signed-serial')).toBeNull();
  });

  it('shows the issued certificate, gone once the CSR text changes', () => {
    render(<SignCSRPage />);
    fireEvent.change(csr(), { target: { value: CSR } });
    fireEvent.change(token(), { target: { value: 'tok-1' } });
    fireEvent.click(submit());
    const input = lastInput();
    hook.data = { certificate: { serial: '1f', commonName: 'signer', pem: btoa(CERT_PEM) } };
    act(() => hook.onSuccess?.(hook.data, input));

    expect(screen.getByTestId('signed-serial').textContent).toBe('1f');
    expect(screen.getByTestId('signed-pem').textContent).toContain('-----BEGIN CERTIFICATE-----');
    expect(screen.getByText('signer')).toBeTruthy();

    fireEvent.change(csr(), { target: { value: `${CSR}\n` } });
    expect(screen.queryByTestId('signed-serial')).toBeNull();
    expect(screen.queryByTestId('signed-pem')).toBeNull();
  });
});
