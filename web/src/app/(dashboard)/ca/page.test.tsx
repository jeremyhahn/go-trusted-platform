import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';

afterEach(cleanup);

// The overview reads GetCAInfo and renders the gated lifecycle controls
// (InitCA, InstallCACertificates, UninstallCACertificates) in its Lifecycle card.
const getInfo = vi.fn();

vi.mock('@/components/features/ca/ca-lifecycle-controls', () => ({
  CALifecycleControls: () => <div data-testid="ca-lifecycle-controls" />,
}));

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

  it('renders the lifecycle controls in the Lifecycle card', () => {
    render(<CAOverviewPage />);
    // CardTitle sits in CardHeader, which sits in the Card.
    const card = screen.getByText('Lifecycle').parentElement?.parentElement as HTMLElement;
    expect(within(card).getByTestId('ca-lifecycle-controls')).toBeTruthy();
    const placeholders = Array.from(document.body.querySelectorAll('*')).filter((el) =>
      (el.textContent ?? '').startsWith('Not available: '),
    );
    expect(placeholders).toHaveLength(0);
  });
});
