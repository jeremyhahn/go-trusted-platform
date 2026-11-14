import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
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

// The hook also reads the template and bundle lists.
const LISTS: Record<string, Answer> = {
  'GET /api/v1/vtpm/templates': ok({ templates: [] }),
  'GET /api/v1/vtpm/bundles': ok({ bundles: [], total: 0 }),
};

async function renderAndWaitFor(id: string) {
  const view = render(withControlPlane(<BundleDetailClient />));
  await screen.findByRole('heading', { level: 1, name: `vTPM bundle ${id}` });
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
