import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, fireEvent } from '@testing-library/react';

afterEach(cleanup);

// The overview reads GetCAInfo and shows the three lifecycle controls the
// daemon serves no REST route for (InitCA, InstallCACertificates,
// UninstallCACertificates), disabled with their reason.
const getInfo = vi.fn();

vi.mock('next/link', () => ({
  default: ({ children, href, ...rest }: { children: React.ReactNode; href: string }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

vi.mock('@/hooks', () => ({
  useCA: () => ({ getInfo }),
  useApi: (fn: () => unknown) => {
    fn();
    return {
      data: {
        caInfo: {
          commonName: 'Platform Root',
          defaultAlgorithm: 'ECDSA_P256',
          defaultValidityDays: 90,
          rootCert: { serial: '0a', commonName: 'Platform Root' },
        },
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    };
  },
  usePlatformClient: () => ({ baseUrl: '' }),
  useMutation: () => ({ mutate: vi.fn(), reset: vi.fn(), isLoading: false, error: null }),
}));

import CAOverviewPage from './page';

describe('CA overview page', () => {
  it('shows what GetCAInfo returned', () => {
    render(<CAOverviewPage />);
    expect(getInfo).toHaveBeenCalled();
    expect(screen.getByTestId('ca-common-name').textContent).toBe('Platform Root');
    expect(screen.getByTestId('ca-default-algorithm').textContent).toBe('ECDSA_P256');
    expect(screen.getByTestId('ca-default-validity').textContent).toBe('90 days');
    expect(screen.getByTestId('ca-root-cert').textContent).toContain('serial 0a');
  });

  it.each([
    ['ca-init-control', 'Initialize CA', 'InitCA'],
    ['ca-install-control', 'Install CA certificates', 'InstallCACertificates'],
    ['ca-uninstall-control', 'Uninstall CA certificates', 'UninstallCACertificates'],
  ])('%s is disabled with its reason and calls nothing', (id, label, op) => {
    render(<CAOverviewPage />);
    const control = screen.getByTestId(id) as HTMLButtonElement;
    expect(control.textContent).toBe(label);
    expect(control.disabled).toBe(true);
    const reason = screen.getByTestId(`${id}-reason`);
    expect(reason.textContent).toMatch(/^Not available: /);
    expect(reason.textContent).toContain(op);
    expect(control.getAttribute('aria-describedby')).toBe(reason.id);
    getInfo.mockClear();
    fireEvent.click(control);
    expect(getInfo).not.toHaveBeenCalled();
  });
});
