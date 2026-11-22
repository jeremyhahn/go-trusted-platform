import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
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

function input(label: string): HTMLInputElement {
  return screen.getByLabelText(label) as HTMLInputElement;
}

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function confirm() {
  fireEvent.click(screen.getByRole('button', { name: 'Initialize' }));
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

  it('keeps Initialize disabled until the SO PIN and threshold are set', () => {
    stubControlPlane({});
    render(withControlPlane(<CeremonyInitCard />));

    const button = screen.getByRole('button', { name: 'Initialize' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fill('SO PIN', 'so-pin-test');
    expect(button.disabled).toBe(true);
    fill('Threshold', '3-of-5');
    expect(button.disabled).toBe(false);
  });

  it('sends nothing when the confirm is cancelled', async () => {
    const sent = stubControlPlane({});
    render(withControlPlane(<CeremonyInitCard />));

    fill('SO PIN', 'so-pin-test');
    fill('Threshold', '3-of-5');
    fireEvent.click(screen.getByRole('button', { name: 'Initialize' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Initialize the ceremony?');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(sent).toEqual([]);
  });

  it('initializes after the confirm and shows the admin key once', async () => {
    const onInitialized = vi.fn();
    const sent = stubControlPlane({
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
    expect(sent).toEqual([
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
    const sent = stubControlPlane({ [INIT_PATH]: refused(409, 'ceremony: already initialized') });
    render(withControlPlane(<CeremonyInitCard onInitialized={onInitialized} />));

    fill('SO PIN', 'so-pin-test');
    fill('Threshold', '3-of-5');
    await confirm();

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe('Init refused: ceremony: already initialized');
    expect(sent[0].body).toEqual({ soPin: 'so-pin-test', threshold: '3-of-5' });
    expect(input('SO PIN').value).toBe('so-pin-test');
    expect(screen.queryByLabelText('Admin private key')).toBeNull();
    expect(onInitialized).not.toHaveBeenCalled();
  });
});
