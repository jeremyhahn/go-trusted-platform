import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import TPMPCRsPage from './page';

// The PCR page's Extend PCR control (#2069) runs through the SDK client only
// after the confirm dialog, and is gated on the server's capabilities
// listing: a server that does not offer POST /tpm/pcrs/extend disables it
// with the reason and nothing is sent.

const EXTEND_PATH = 'POST /api/v1/tpm/pcrs/extend';
const PCRS = 'POST /api/v1/tpm/pcrs';

function caps(off: string[] = []): Answer {
  const capabilities = [EXTEND_PATH, 'GET /api/v1/tpm/pcrs'].map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: tpm' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(off: string[] = []): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    'GET /api/v1/tpm/pcrs': ok({ pcrs: [] }),
    [EXTEND_PATH]: ok({}),
  };
}

function renderPage() {
  render(withControlPlane(<TPMPCRsPage />));
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

/** Renders the page and waits for the capability gate to read the server's capabilities. */
async function mount(extendAnswer: Answer = ok({ status: { success: true } })): Promise<SentRequest[]> {
  const sent = stubControlPlane({
    [PCRS]: ok({ pcrValues: [] }),
    [EXTEND_PATH]: extendAnswer,
    'GET /api/v1/capabilities': caps(),
  });
  renderPage();
  await waitFor(() => expect(extendButton().getAttribute('data-capability-enabled')).toBe('true'));
  return sent;
}

function sentTo(sent: SentRequest[], route: string): SentRequest[] {
  return sent.filter((r) => `${r.method} ${r.path}` === route);
}

function fill(index: string, data: string) {
  fireEvent.change(screen.getByLabelText('PCR index'), { target: { value: index } });
  fireEvent.change(screen.getByLabelText('Data'), { target: { value: data } });
}

function extendButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: 'Extend PCR' }) as HTMLButtonElement;
}

/** Clicks Extend PCR and, when the confirm dialog opens, Confirm. */
async function tryExtend() {
  await act(async () => {
    fireEvent.click(extendButton());
  });
  const confirm = screen.queryByRole('button', { name: 'Confirm' });
  if (confirm) {
    await act(async () => {
      fireEvent.click(confirm);
    });
  }
}

describe('TPMPCRsPage Extend PCR', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('extends PCR 16 only after the confirm', async () => {
    const sent = stubControlPlane(routes());
    renderPage();

    fireEvent.change(screen.getByLabelText('Data'), { target: { value: 'measure-me' } });
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Extend PCR' }).getAttribute('data-capability-enabled')).toBe('true'),
    );
    await click('Extend PCR');
    await screen.findByText('Extend PCR 16?');
    expect(sent.some((r) => r.path === '/api/v1/tpm/pcrs/extend')).toBe(false);

    await click('Confirm');

    await waitFor(() => {
      const extend = sent.find((r) => r.method === 'POST' && r.path === '/api/v1/tpm/pcrs/extend');
      expect(extend?.body).toMatchObject({ index: 16, hashAlg: 'sha256', data: 'bWVhc3VyZS1tZQ==' });
    });
  });

  it('withholds Extend PCR when the server does not offer it', async () => {
    const sent = stubControlPlane(routes([EXTEND_PATH]));
    renderPage();

    fireEvent.change(screen.getByLabelText('Data'), { target: { value: 'measure-me' } });
    await waitFor(() => {
      const button = screen.getByRole('button', { name: 'Extend PCR' }) as HTMLButtonElement;
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
      expect(button.getAttribute('title')).toBe('not-configured: tpm');
      expect(button.disabled).toBe(true);
    });
    await click('Extend PCR');

    expect(screen.queryByText('Extend PCR 16?')).toBeNull();
    expect(sent.some((r) => r.path === '/api/v1/tpm/pcrs/extend')).toBe(false);
  });
});

describe('TPMPCRsPage Extend PCR input guards', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('posts {index, hashAlg, data} to /v1/tpm/pcrs/extend, toasts and reloads the PCRs', async () => {
    const sent = await mount();
    await waitFor(() => expect(sentTo(sent, PCRS)).toHaveLength(1));

    fill('16', 'boot-ok');
    await click('Extend PCR');
    await click('Confirm');

    expect(await screen.findByText(/^PCR extended:/)).toBeDefined();
    expect(sentTo(sent, EXTEND_PATH).map((r) => r.body)).toEqual([
      { index: 16, hashAlg: 'sha256', data: btoa('boot-ok') },
    ]);
    await waitFor(() => expect(sentTo(sent, PCRS).length).toBeGreaterThanOrEqual(2));
  });

  it('sends nothing when the operator cancels the confirm dialog', async () => {
    const sent = await mount();
    await waitFor(() => expect(sentTo(sent, PCRS)).toHaveLength(1));

    fill('16', 'boot-ok');
    await click('Extend PCR');
    await click('Cancel');

    await waitFor(() => expect(screen.queryByRole('button', { name: 'Confirm' })).toBeNull());
    expect(sentTo(sent, EXTEND_PATH)).toEqual([]);
  });

  it('shows the server refusal in the Extend PCR failed toast', async () => {
    await mount(refused(400, 'pcr index out of range'));

    fill('16', 'boot-ok');
    await click('Extend PCR');
    await click('Confirm');

    const toast = await screen.findByText(/^Extend PCR failed:/);
    expect(toast.textContent).toContain('pcr index out of range');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });

  it('refuses index 24: the button is disabled and no extend is sent', async () => {
    const sent = await mount();
    await waitFor(() => expect(sentTo(sent, PCRS)).toHaveLength(1));

    fill('24', 'boot-ok');
    expect(extendButton().disabled).toBe(true);
    await tryExtend();

    expect(sentTo(sent, EXTEND_PATH)).toEqual([]);
    expect(screen.getByText('PCR index is a whole number from 0 to 23')).toBeDefined();
  });

  it('refuses index 1.5: the button is disabled', async () => {
    const sent = await mount();
    await waitFor(() => expect(sentTo(sent, PCRS)).toHaveLength(1));

    fill('1.5', 'boot-ok');
    expect(extendButton().disabled).toBe(true);
    await tryExtend();

    expect(sentTo(sent, EXTEND_PATH)).toEqual([]);
  });
});
