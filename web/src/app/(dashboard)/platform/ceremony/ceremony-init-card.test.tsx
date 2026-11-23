import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ok,
  refused,
  stubControlPlane,
  withControlPlane,
  type Answer,
  type SentRequest,
} from '@/test/control-plane-fetch';
import { CeremonyInitCard, parseSANs } from './ceremony-init-card';

// #2042: the ceremony page initializes the ceremony through
// useCeremony().init (CeremonyService.Init) after a confirm dialog, and shows
// the admin key from the reply once.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/platform/ceremony',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const INIT_PATH = 'POST /api/v1/ceremony/init';
const CERT_PEM = '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----';
// A placeholder, not key material.
const ADMIN_KEY = 'test-admin-key-placeholder';

const CAPS_PATH = 'GET /api/v1/capabilities';
const CEREMONY_OPS = [
  'POST /api/v1/ceremony/init',
  'GET /api/v1/ceremony/status',
  'POST /api/v1/ceremony/claim-cert/begin',
  'POST /api/v1/ceremony/claim-cert/complete',
  'POST /api/v1/ceremony/claim-share/begin',
  'POST /api/v1/ceremony/claim-share/complete',
  'POST /api/v1/ceremony/sign-csr',
] as const;

// The server's capabilities listing: every ceremony op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = CEREMONY_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: ceremony' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

// The requests the card sent, without the capability gate's read of the listing.
function writes(sent: SentRequest[]): SentRequest[] {
  return sent.filter((r) => !(r.method === 'GET' && r.path === '/api/v1/capabilities'));
}

// The capability gate marks a control off until the capabilities answer is
// in; wait until it no longer does (an ungated control carries no mark).
async function offered(btn: HTMLElement) {
  await waitFor(() => expect(btn.getAttribute('data-capability-enabled')).not.toBe('false'));
}

function input(label: string): HTMLInputElement {
  return screen.getByLabelText(label) as HTMLInputElement;
}

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function confirm() {
  const open = screen.getByRole('button', { name: 'Initialize' });
  await offered(open);
  fireEvent.click(open);
  const dialog = await screen.findByRole('dialog');
  fireEvent.click(within(dialog).getByRole('button', { name: 'Initialize' }));
}

describe('ceremony init helpers', () => {
  it('splits the SANs', () => {
    expect(parseSANs(' a.example, b.example\n\n')).toEqual(['a.example', 'b.example']);
    expect(parseSANs('')).toEqual([]);
  });
});

describe('CeremonyInitCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('keeps Initialize disabled until the SO PIN and threshold are set', async () => {
    stubControlPlane({ [CAPS_PATH]: caps() });
    render(withControlPlane(<CeremonyInitCard />));

    const button = screen.getByRole('button', { name: 'Initialize' }) as HTMLButtonElement;
    await offered(button);
    expect(button.disabled).toBe(true);
    fill('SO PIN', 'so-pin-test');
    expect(button.disabled).toBe(true);
    fill('Threshold', '3-of-5');
    expect(button.disabled).toBe(false);
  });

  it('keeps Initialize disabled and explains the format for a threshold that is not M-of-N', async () => {
    stubControlPlane({ [CAPS_PATH]: caps() });
    render(withControlPlane(<CeremonyInitCard />));

    const button = screen.getByRole('button', { name: 'Initialize' }) as HTMLButtonElement;
    await offered(button);
    const hint = 'Threshold must be M-of-N with M at least 2, for example 3-of-5';
    fill('SO PIN', 'so-pin-test');
    expect(screen.queryByText(hint)).toBeNull();
    // Upstream runs single-admin for a threshold below 2, so 1-of-N is refused.
    for (const bad of ['garbage', '3of5', '4-of-3', '0-of-3', '1-of-5', '1-of-1']) {
      fill('Threshold', bad);
      expect(button.disabled).toBe(true);
      expect(screen.getByText(hint)).toBeDefined();
    }
    fill('Threshold', '3-of-5');
    expect(button.disabled).toBe(false);
    expect(screen.queryByText(hint)).toBeNull();
  });

  it('initializes a single-admin ceremony only through the explicit checkbox', async () => {
    const sent = stubControlPlane({
      [CAPS_PATH]: caps(),
      [INIT_PATH]: refused(409, 'ceremony: already initialized'),
    });
    render(withControlPlane(<CeremonyInitCard />));

    const button = screen.getByRole('button', { name: 'Initialize' }) as HTMLButtonElement;
    await offered(button);
    fill('SO PIN', 'so-pin-test');
    expect(button.disabled).toBe(true);
    expect(input('Threshold').disabled).toBe(false);
    fireEvent.click(screen.getByRole('checkbox', { name: 'Single admin (no officer shares)' }));
    expect(input('Threshold').disabled).toBe(true);
    expect(button.disabled).toBe(false);
    await confirm();

    await screen.findByRole('alert');
    expect(writes(sent)).toHaveLength(1);
    expect(writes(sent)[0].body).toEqual({ soPin: 'so-pin-test' });
    expect(writes(sent)[0].body).not.toHaveProperty('threshold');
  });

  it('sends nothing when the confirm is cancelled', async () => {
    const sent = stubControlPlane({ [CAPS_PATH]: caps() });
    render(withControlPlane(<CeremonyInitCard />));

    fill('SO PIN', 'so-pin-test');
    fill('Threshold', '3-of-5');
    const open = screen.getByRole('button', { name: 'Initialize' });
    await offered(open);
    fireEvent.click(open);
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Initialize the ceremony?');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(writes(sent)).toEqual([]);
  });

  it('initializes after the confirm and shows the admin key once', async () => {
    const onInitialized = vi.fn();
    const sent = stubControlPlane({
      [CAPS_PATH]: caps(),
      [INIT_PATH]: ok({
        ceremonyId: 'c-1',
        state: 'CEREMONY_STATE_IN_PROGRESS',
        adminCertPem: CERT_PEM,
        adminKeyPem: ADMIN_KEY,
        spkiPin: 'pin-1',
      }),
    });
    render(withControlPlane(<CeremonyInitCard onInitialized={onInitialized} />));

    fill('SO PIN', 'so-pin-test');
    fill('User PIN', 'user-pin-test');
    fill('Threshold', '3-of-5');
    fill('Hostname', 'ca.example');
    fill('SANs', 'ca.example, ca2.example');
    await confirm();

    expect(await screen.findByText('Save the admin key now: the platform keeps no copy.')).toBeDefined();
    expect(writes(sent)).toEqual([
      {
        method: 'POST',
        path: '/api/v1/ceremony/init',
        body: {
          soPin: 'so-pin-test',
          userPin: 'user-pin-test',
          threshold: '3-of-5',
          hostname: 'ca.example',
          sans: ['ca.example', 'ca2.example'],
        },
      },
    ]);
    expect((screen.getByLabelText('Admin private key') as HTMLTextAreaElement).value).toBe(ADMIN_KEY);
    expect((screen.getByLabelText('Admin certificate') as HTMLTextAreaElement).value).toBe(CERT_PEM);
    expect(input('SO PIN').value).toBe('');
    expect(input('User PIN').value).toBe('');
    expect(onInitialized).toHaveBeenCalledTimes(1);
  });

  it('shows a refusal verbatim and keeps the inputs', async () => {
    const onInitialized = vi.fn();
    const sent = stubControlPlane({
      [CAPS_PATH]: caps(),
      [INIT_PATH]: refused(409, 'ceremony: already initialized'),
    });
    render(withControlPlane(<CeremonyInitCard onInitialized={onInitialized} />));

    fill('SO PIN', 'so-pin-test');
    fill('Threshold', '3-of-5');
    await confirm();

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe('Init refused: ceremony: already initialized');
    expect(writes(sent)[0].body).toEqual({ soPin: 'so-pin-test', threshold: '3-of-5' });
    expect(input('SO PIN').value).toBe('so-pin-test');
    expect(screen.queryByLabelText('Admin private key')).toBeNull();
    expect(onInitialized).not.toHaveBeenCalled();
  });
});
