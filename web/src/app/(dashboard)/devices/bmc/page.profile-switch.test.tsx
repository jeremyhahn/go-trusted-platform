import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

// The system card mock keeps the profile it was first mounted with in
// state, so a card that is not remounted on a profile switch shows the old
// profile.
vi.mock('@/components/features/bmc/bmc-system-card', async () => {
  const react = await vi.importActual<typeof import('react')>('react');
  return {
    BMCSystemCard: ({ profileID }: { profileID: string }) => {
      const [first] = react.useState(profileID);
      return <div data-testid="bmc-system-card-first">{first}</div>;
    },
  };
});
vi.mock('@/components/features/bmc/bmc-power-card', () => ({
  BMCPowerCard: ({ profileID }: { profileID: string }) => <div data-testid="bmc-power-card">{profileID}</div>,
}));
vi.mock('@/components/features/bmc/bmc-boot-media-card', () => ({
  BMCBootMediaCard: ({ profileID }: { profileID: string }) => <div data-testid="bmc-boot-media-card">{profileID}</div>,
}));
vi.mock('@/components/features/bmc/bmc-provision-card', () => ({
  BMCProvisionCard: ({ profileID }: { profileID: string }) => <div data-testid="bmc-provision-card">{profileID}</div>,
}));
vi.mock('@/components/features/bmc/bmc-sensors-card', () => ({
  BMCSensorsCard: ({ profileID }: { profileID: string }) => <div data-testid="bmc-sensors-card">{profileID}</div>,
}));
vi.mock('@/components/features/bmc/bmc-web-cert-card', () => ({
  BMCWebCertCard: ({ profileID }: { profileID: string }) => <div data-testid="bmc-web-cert-card">{profileID}</div>,
}));

import BMCPage from './page';

afterEach(() => {
  cleanup();
});

describe('BMCPage profile switch', () => {
  it('remounts the cards when the profile ID changes', () => {
    render(<BMCPage />);
    const input = screen.getByLabelText('BMC profile ID');
    fireEvent.change(input, { target: { value: '1' } });
    expect(screen.getByTestId('bmc-system-card-first').textContent).toBe('1');

    fireEvent.change(input, { target: { value: '12' } });
    expect(screen.getByTestId('bmc-system-card-first').textContent).toBe('12');
  });
});
