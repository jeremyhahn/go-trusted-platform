import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

vi.mock('@/components/features/bmc/bmc-cert-card', () => ({
  BMCCertCard: ({ profileID }: { profileID: string }) => <div data-testid="bmc-cert-card">{profileID}</div>,
}));

vi.mock('@/components/features/bmc/bmc-accounts-card', () => ({
  BMCAccountsCard: ({ profileID }: { profileID: string }) => (
    <div data-testid="bmc-accounts-card">{profileID}</div>
  ),
}));

import BMCAccountsPage from './page';

afterEach(cleanup);

describe('BMCAccountsPage', () => {
  it('renders no BMC card before a profile ID is entered', () => {
    render(<BMCAccountsPage />);
    expect(screen.getByLabelText('BMC profile ID')).toBeTruthy();
    expect(screen.queryByTestId('bmc-cert-card')).toBeNull();
    expect(screen.queryByTestId('bmc-accounts-card')).toBeNull();
  });

  it('renders the certificate and users cards for the profile ID typed in', () => {
    render(<BMCAccountsPage />);
    fireEvent.change(screen.getByLabelText('BMC profile ID'), { target: { value: ' 1 ' } });
    expect(screen.getByTestId('bmc-cert-card').textContent).toBe('1');
    expect(screen.getByTestId('bmc-accounts-card').textContent).toBe('1');
  });

  it('remounts the cards when the profile ID changes', () => {
    render(<BMCAccountsPage />);
    const input = screen.getByLabelText('BMC profile ID');
    fireEvent.change(input, { target: { value: '1' } });
    fireEvent.change(input, { target: { value: '2' } });
    expect(screen.getByTestId('bmc-cert-card').textContent).toBe('2');
    expect(screen.getByTestId('bmc-accounts-card').textContent).toBe('2');
  });
});
