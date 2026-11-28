import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { KmsDigestCard } from './kms-digest-card';

vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-capabilities')>()),
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

// #2180 round 9: the backend makes a fresh MAC key per HMAC call, so a tag
// it computes never verifies. The card withholds Compute HMAC and Verify HMAC
// until the backend uses a stable MAC key, and says why.

describe('KmsDigestCard HMAC', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('withholds the HMAC controls and makes no HMAC request', () => {
    const sent = stubControlPlane({});
    render(withControlPlane(<KmsDigestCard />));

    expect(screen.queryByRole('button', { name: 'Compute HMAC' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Verify HMAC' })).toBeNull();
    expect(screen.queryByLabelText('Key name')).toBeNull();
    expect(screen.queryByLabelText('Tag (base64)')).toBeNull();
    expect(screen.getByTestId('kms-hmac-withheld').textContent).toContain('stable MAC key');
    expect(sent).toHaveLength(0);
  });
});
