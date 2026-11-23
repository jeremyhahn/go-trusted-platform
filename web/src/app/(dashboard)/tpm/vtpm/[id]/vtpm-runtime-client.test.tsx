import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Suspense } from 'react';
import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import VTPMRuntimeClient from './vtpm-runtime-client';

// #2072: the vTPM runtime page wraps each runtime control in the capability
// gate, so a control whose op the server does not offer is disabled with
// the server's reason as its tooltip.

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'b1' }),
  usePathname: () => '/tpm/vtpm/b1',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const VTPM_OPS = [
  'POST /api/v1/vtpm/bundles/{id}/start',
  'POST /api/v1/vtpm/bundles/{id}/stop',
  'POST /api/v1/vtpm/bundles/{id}/quote',
  'POST /api/v1/vtpm/bundles/{id}/seal',
  'POST /api/v1/vtpm/bundles/{id}/unseal',
  'GET /api/v1/vtpm/bundles/{id}/pcrs',
  'POST /api/v1/vtpm/bundles/{id}/pcrs/extend',
] as const;

// The control of each op, in VTPM_OPS order.
const CONTROLS = ['Start vTPM', 'Stop vTPM', 'Quote', 'Seal', 'Unseal', 'Read PCR', 'Extend PCR'] as const;

// The server's capabilities listing: every vTPM op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = VTPM_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: vtpm' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

async function renderPage(off: string[] = []) {
  stubControlPlane({
    'GET /api/v1/capabilities': caps(off),
    'GET /api/v1/vtpm/bundles/b1/state': ok({ bundle_id: 'b1', running: true, socket_path: '/run/x' }),
  });
  await act(async () => {
    render(
      withControlPlane(
        <Suspense fallback={null}>
          <VTPMRuntimeClient params={Promise.resolve({ id: 'b1' })} />
        </Suspense>,
      ),
    );
  });
  await screen.findByRole('heading', { level: 1, name: 'vTPM Runtime' });
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

describe('VTPMRuntimeClient capability gate', () => {
  it('each runtime control carries its server op', async () => {
    await renderPage();

    CONTROLS.forEach((name, i) => {
      expect(button(name).getAttribute('data-capability-op')).toBe(VTPM_OPS[i]);
    });
    await waitFor(() => expect(button('Start vTPM').getAttribute('data-capability-enabled')).toBe('true'));
    for (const name of CONTROLS) {
      expect(button(name).getAttribute('data-capability-enabled')).toBe('true');
    }
    for (const name of ['Start vTPM', 'Stop vTPM', 'Quote', 'Read PCR']) {
      expect(button(name).disabled).toBe(false);
    }
  });

  it('a control whose op the server does not offer is disabled with the reason', async () => {
    await renderPage([
      'POST /api/v1/vtpm/bundles/{id}/stop',
      'POST /api/v1/vtpm/bundles/{id}/seal',
      'POST /api/v1/vtpm/bundles/{id}/pcrs/extend',
    ]);
    // Fill the inputs so only the gate can disable Seal and Extend PCR.
    fireEvent.change(screen.getByLabelText('Data to seal'), { target: { value: 'hello' } });
    fireEvent.change(screen.getByLabelText('Data to extend (hex)'), { target: { value: '00ff' } });

    await waitFor(() => expect(button('Start vTPM').getAttribute('data-capability-enabled')).toBe('true'));
    for (const name of ['Stop vTPM', 'Seal', 'Extend PCR']) {
      expect(button(name).disabled).toBe(true);
      expect(button(name).getAttribute('title')).toBe('not-configured: vtpm');
    }
    for (const name of ['Start vTPM', 'Quote', 'Read PCR']) {
      expect(button(name).disabled).toBe(false);
      expect(button(name).getAttribute('data-capability-enabled')).toBe('true');
    }
  });

  it('the run-state badge shows the server state on load', async () => {
    await renderPage();
    await waitFor(() => expect(screen.getByTestId('vtpm-run-state').textContent).toBe('Running'));
  });
});
