import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import CeremonyPage from './page';

// #2042: the ceremony page mounts every ceremony card, so officers can claim
// their certificate and their share from the console.

vi.mock('./ceremony-status-card', () => ({
  CeremonyStatusCard: () => <div data-testid="ceremony-status-card" />,
}));
vi.mock('./ceremony-init-card', () => ({
  CeremonyInitCard: () => <div data-testid="ceremony-init-card" />,
}));
vi.mock('./ceremony-sign-csr-card', () => ({
  CeremonySignCSRCard: () => <div data-testid="ceremony-sign-csr-card" />,
}));
vi.mock('./ceremony-claim-cert-card', () => ({
  CeremonyClaimCertCard: () => <div data-testid="ceremony-claim-cert-card" />,
}));
vi.mock('./ceremony-claim-share-card', () => ({
  CeremonyClaimShareCard: () => <div data-testid="ceremony-claim-share-card" />,
}));

describe('CeremonyPage', () => {
  afterEach(() => cleanup());

  it('mounts the status, init, sign-CSR, claim-certificate and claim-share cards', () => {
    render(<CeremonyPage />);
    for (const id of [
      'ceremony-status-card',
      'ceremony-init-card',
      'ceremony-sign-csr-card',
      'ceremony-claim-cert-card',
      'ceremony-claim-share-card',
    ]) {
      expect(screen.getByTestId(id)).toBeDefined();
    }
  });
});
