import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import VMsPage from './page';

// #2044: the VM list's Create VM button sits behind the server's capability gate.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/compute/vms',
  useRouter: () => ({ push: vi.fn(), back: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const CREATE_OP = 'POST /api/v1/compute/vms';
const REASON = 'not-configured: compute';

describe('VMsPage Create VM', () => {
  it('disables Create VM when CreateVM is off', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': ok({
        capabilities: [{ op: CREATE_OP, kind: 'route', enabled: false, reason: REASON }],
        total: 1,
        enabled: 0,
      }),
      'GET /api/v1/compute/vms': ok({ vms: [] }),
    });
    render(withControlPlane(<VMsPage />));

    await waitFor(() => {
      const create = screen.getByRole('button', { name: /Create VM/ }) as HTMLButtonElement;
      expect(create.getAttribute('data-capability-op')).toBe(CREATE_OP);
      expect(create.getAttribute('data-capability-enabled')).toBe('false');
      expect(create.disabled).toBe(true);
      expect(create.title).toBe(REASON);
    });
  });
});
