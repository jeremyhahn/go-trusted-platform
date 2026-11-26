import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/components/features/bmc/bmc-system-card', () => ({
  BMCSystemCard: ({ profileID }: { profileID: string }) => <div data-testid="bmc-system-card">{profileID}</div>,
}));
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

const CARDS = [
  'bmc-system-card',
  'bmc-power-card',
  'bmc-boot-media-card',
  'bmc-provision-card',
  'bmc-sensors-card',
  'bmc-web-cert-card',
];

afterEach(() => {
  cleanup();
});

describe('BMCPage', () => {
  it('renders no BMC card before a profile ID is entered', () => {
    render(<BMCPage />);
    expect(screen.getByLabelText('BMC profile ID')).toBeTruthy();
    for (const id of CARDS) {
      expect(screen.queryByTestId(id)).toBeNull();
    }
  });

  it('renders the six BMC cards for the profile ID typed in', () => {
    render(<BMCPage />);
    fireEvent.change(screen.getByLabelText('BMC profile ID'), { target: { value: '1' } });
    for (const id of CARDS) {
      expect(screen.getByTestId(id).textContent).toBe('1');
    }
  });
});
