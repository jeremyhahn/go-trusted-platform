import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import TPMPCRsPage from './page';

const PCRS = 'POST /api/v1/tpm/pcrs';
const EXTEND = 'POST /api/v1/tpm/pcrs/extend';
const CAPS_ON = ok({ capabilities: ['POST /api/v1/tpm/pcrs/extend', 'POST /api/v1/tpm/make-credential', 'POST /api/v1/tpm/activate-credential', 'POST /api/v1/tpm/random'].map((op) => ({ op, kind: 'route', enabled: true })) });

/** Renders the page and waits for the capability gate to read the server's capabilities. */
async function mount(extendAnswer: Answer = ok({ status: { success: true } })): Promise<SentRequest[]> {
  const sent = stubControlPlane({
    [PCRS]: ok({ pcrValues: [] }),
    [EXTEND]: extendAnswer,
    'GET /api/v1/capabilities': CAPS_ON,
  });
  render(withControlPlane(<TPMPCRsPage />));
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

async function clickButton(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
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

  it('posts {index, hashAlg, data} to /v1/tpm/pcrs/extend, toasts and reloads the PCRs', async () => {
    const sent = await mount();
    await waitFor(() => expect(sentTo(sent, PCRS)).toHaveLength(1));

    fill('16', 'boot-ok');
    await clickButton('Extend PCR');
    await clickButton('Confirm');

    expect(await screen.findByText(/^PCR extended:/)).toBeDefined();
    expect(sentTo(sent, EXTEND).map((r) => r.body)).toEqual([
      { index: 16, hashAlg: 'sha256', data: btoa('boot-ok') },
    ]);
    await waitFor(() => expect(sentTo(sent, PCRS).length).toBeGreaterThanOrEqual(2));
  });

  it('sends nothing when the operator cancels the confirm dialog', async () => {
    const sent = await mount();
    await waitFor(() => expect(sentTo(sent, PCRS)).toHaveLength(1));

    fill('16', 'boot-ok');
    await clickButton('Extend PCR');
    await clickButton('Cancel');

    await waitFor(() => expect(screen.queryByRole('button', { name: 'Confirm' })).toBeNull());
    expect(sentTo(sent, EXTEND)).toEqual([]);
  });

  it('shows the server refusal in the Extend PCR failed toast', async () => {
    await mount(refused(400, 'pcr index out of range'));

    fill('16', 'boot-ok');
    await clickButton('Extend PCR');
    await clickButton('Confirm');

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

    expect(sentTo(sent, EXTEND)).toEqual([]);
    expect(screen.getByText('PCR index is a whole number from 0 to 23')).toBeDefined();
  });

  it('refuses index 1.5: the button is disabled', async () => {
    const sent = await mount();
    await waitFor(() => expect(sentTo(sent, PCRS)).toHaveLength(1));

    fill('1.5', 'boot-ok');
    expect(extendButton().disabled).toBe(true);
    await tryExtend();

    expect(sentTo(sent, EXTEND)).toEqual([]);
  });
});
