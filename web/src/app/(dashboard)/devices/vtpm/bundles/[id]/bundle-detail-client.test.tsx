import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import BundleDetailClient from './bundle-detail-client';

// #1674 (Codex round 4): the bundle detail is keyed to the ID in the URL. When
// the page stays mounted and the ID changes, the previous bundle, its
// validation and its paths must not be shown for the new ID, and a late answer
// for the old ID must not land on the new one.

let currentId = 'bundle-a';

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: currentId }),
  usePathname: () => '/devices/vtpm/bundles/' + currentId,
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

function storedBundle(id: string): Answer {
  return ok({
    id,
    mode: 'pre-assigned',
    manifest: {
      version: '1',
      id,
      mode: 'pre-assigned',
      hostname: `host-${id}`,
      ek_algorithm: 'RSA',
      ek_handle: 0,
      secure_boot_enabled: false,
    },
  });
}

const bundlePath = (id: string) => `GET /api/v1/vtpm/bundles/${id}`;

// The Operations card's controls in order, with the server op each is gated on.
const CONTROLS = ['Validate bundle', 'Get bundle path', 'Get TPM socket path', 'Get NVRAM path'];
const BUNDLE_OPS = [
  'POST /api/v1/vtpm/bundles/{id}/validate',
  'GET /api/v1/vtpm/bundles/{id}/path',
  'GET /api/v1/vtpm/bundles/{id}/tpm-socket',
  'GET /api/v1/vtpm/bundles/{id}/nvram',
];

// The server's capabilities answer: every bundle op on except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = BUNDLE_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: vtpm' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

// The hook also reads the template and bundle lists; the gate reads the capabilities.
const LISTS: Record<string, Answer> = {
  'GET /api/v1/vtpm/templates': ok({ templates: [] }),
  'GET /api/v1/vtpm/bundles': ok({ bundles: [], total: 0 }),
  'GET /api/v1/capabilities': caps(),
};

const button = (name: string) => screen.getByRole('button', { name }) as HTMLButtonElement;

async function renderAndWaitFor(id: string) {
  const view = render(withControlPlane(<BundleDetailClient />));
  await screen.findByRole('heading', { level: 1, name: `vTPM bundle ${id}` });
  // The gate reads every op as off until the capabilities answer lands; wait
  // for it on Get bundle path, which every case leaves on.
  await waitFor(() => expect(button('Get bundle path').getAttribute('data-capability-enabled')).toBe('true'));
  return view;
}

describe('BundleDetailClient keyed to the bundle ID', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    currentId = 'bundle-a';
  });

  it('drops bundle A and its validation when B fails to load', async () => {
    stubControlPlane({
      ...LISTS,
      [bundlePath('bundle-a')]: storedBundle('bundle-a'),
      'POST /api/v1/vtpm/bundles/bundle-a/validate': ok({ valid: true }),
      [bundlePath('bundle-b')]: refused(404, 'bundle bundle-b not found'),
    });
    const view = await renderAndWaitFor('bundle-a');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Validate bundle' }));
    });
    expect(await screen.findByText('Valid')).toBeDefined();

    currentId = 'bundle-b';
    view.rerender(withControlPlane(<BundleDetailClient />));

    expect(await screen.findByText('Bundle bundle-b could not be loaded.')).toBeDefined();
    expect(screen.queryByText(/bundle-a/)).toBeNull();
    expect(screen.queryByTestId('vtpm-validate-result')).toBeNull();
  });

  // #2024 Codex round 5 P1: a failed recheck must not leave the earlier
  // verdict on screen as if it were the result of the recheck.
  it('a failed revalidation clears the earlier Valid verdict and shows the failure', async () => {
    const routes: Record<string, Answer> = {
      ...LISTS,
      [bundlePath('bundle-a')]: storedBundle('bundle-a'),
      'POST /api/v1/vtpm/bundles/bundle-a/validate': ok({ valid: true }),
    };
    stubControlPlane(routes);
    await renderAndWaitFor('bundle-a');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Validate bundle' }));
    });
    expect(await screen.findByText('Valid')).toBeDefined();

    routes['POST /api/v1/vtpm/bundles/bundle-a/validate'] = refused(500, 'validation backend down');
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Validate bundle' }));
    });

    expect(await screen.findByTestId('vtpm-validate-error')).toBeDefined();
    expect(screen.queryByText('Valid')).toBeNull();
    expect(screen.queryByTestId('vtpm-validate-result')).toBeNull();
  });

  it('does not carry A validation and paths over to B', async () => {
    stubControlPlane({
      ...LISTS,
      [bundlePath('bundle-a')]: storedBundle('bundle-a'),
      'POST /api/v1/vtpm/bundles/bundle-a/validate': ok({ valid: true }),
      'GET /api/v1/vtpm/bundles/bundle-a/path': ok({ path: '/var/lib/vtpm/bundles/bundle-a' }),
      [bundlePath('bundle-b')]: storedBundle('bundle-b'),
    });
    const view = await renderAndWaitFor('bundle-a');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Validate bundle' }));
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Get bundle path' }));
    });
    expect(await screen.findByTestId('vtpm-validate-result')).toBeDefined();
    expect(await screen.findByTestId('vtpm-bundle-path')).toBeDefined();

    currentId = 'bundle-b';
    view.rerender(withControlPlane(<BundleDetailClient />));

    expect(await screen.findByRole('heading', { level: 1, name: 'vTPM bundle bundle-b' })).toBeDefined();
    expect(screen.queryByTestId('vtpm-validate-result')).toBeNull();
    expect(screen.queryByTestId('vtpm-bundle-path')).toBeNull();
  });

  it('shows Loading for B while its lookup is pending, never A', async () => {
    stubControlPlane({
      ...LISTS,
      [bundlePath('bundle-a')]: storedBundle('bundle-a'),
      [bundlePath('bundle-b')]: storedBundle('bundle-b'),
    });
    // Hold GET bundle-b until the test releases it.
    const answer = globalThis.fetch;
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.pathname.endsWith('/bundles/bundle-b')) {
          await held;
        }
        return answer(input, init);
      })
    );

    const view = await renderAndWaitFor('bundle-a');

    currentId = 'bundle-b';
    view.rerender(withControlPlane(<BundleDetailClient />));

    expect(await screen.findByText('Loading bundle')).toBeDefined();
    expect(screen.queryByRole('heading', { name: 'vTPM bundle bundle-a' })).toBeNull();

    await act(async () => {
      release();
    });
    expect(await screen.findByRole('heading', { level: 1, name: 'vTPM bundle bundle-b' })).toBeDefined();
  });
});

describe('BundleDetailClient capability gate', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    currentId = 'bundle-a';
  });

  it('each operation carries its server op', async () => {
    stubControlPlane({
      ...LISTS,
      [bundlePath('bundle-a')]: storedBundle('bundle-a'),
    });
    await renderAndWaitFor('bundle-a');

    CONTROLS.forEach((name, i) => {
      expect(button(name).getAttribute('data-capability-op')).toBe(BUNDLE_OPS[i]);
    });
    for (const name of CONTROLS) {
      await waitFor(() => expect(button(name).getAttribute('data-capability-enabled')).toBe('true'));
    }
  });

  it('an op the server does not offer disables its control with the reason and sends nothing', async () => {
    const sent = stubControlPlane({
      ...LISTS,
      'GET /api/v1/capabilities': caps([
        'POST /api/v1/vtpm/bundles/{id}/validate',
        'GET /api/v1/vtpm/bundles/{id}/nvram',
      ]),
      [bundlePath('bundle-a')]: storedBundle('bundle-a'),
      'POST /api/v1/vtpm/bundles/bundle-a/validate': ok({ valid: true }),
    });
    await renderAndWaitFor('bundle-a');

    await waitFor(() => expect(button('Get bundle path').getAttribute('data-capability-enabled')).toBe('true'));
    expect(button('Get bundle path').disabled).toBe(false);
    for (const name of ['Validate bundle', 'Get NVRAM path']) {
      expect(button(name).disabled).toBe(true);
      expect(button(name).getAttribute('title')).toBe('not-configured: vtpm');
    }

    await act(async () => {
      fireEvent.click(button('Validate bundle'));
    });
    expect(sent.some((r) => r.method === 'POST' && r.path === '/api/v1/vtpm/bundles/bundle-a/validate')).toBe(false);
  });
});
