import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import TPMProvisionPage from './provision/page';
import TPMQuotePage from './quote/page';

// The TPM provisioning and quote pages follow the server's capabilities
// (#2068): Provision TPM, Clear TPM, Create AK, Generate Quote and Verify
// Quote are each wrapped in the capability gate, so a server that does not
// offer the operation leaves the control disabled with the server's reason as
// its title, and a click sends nothing.

const PROVISION = 'POST /api/v1/tpm/provision';
const CLEAR = 'POST /api/v1/tpm/clear';
const CREATE_AK = 'POST /api/v1/tpm/ak';
const QUOTE = 'POST /api/v1/tpm/quote';
const VERIFY = 'POST /api/v1/tpm/quote/verify';

const TPM_OPS = [PROVISION, CLEAR, CREATE_AK, 'GET /api/v1/tpm/ak', QUOTE, VERIFY];

const REASON = 'not-configured: tpm';

function caps(off: string[] = []): Answer {
  const capabilities = TPM_OPS.map((op) =>
    off.includes(op) ? { op, kind: 'route', enabled: false, reason: REASON } : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

const PLATFORM: Answer = ok({
  device: '/dev/tpmrm0',
  manufacturer: 'IBM',
  isFips: false,
  isSimulator: true,
  canSeal: true,
  pcrExtended: false,
  ek: { handle: 2164260865, algorithm: 'RSA' },
  srk: { handle: 2164260866, algorithm: 'RSA' },
});

const TPM_CAPABILITIES: Answer = ok({
  algorithms: ['RSA', 'ECC', 'SHA256'],
  commands: ['TPM2_Quote', 'TPM2_Clear'],
  eccCurves: ['NIST_P256'],
});

function button(name: string | RegExp): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

async function expectWithheld(name: string | RegExp) {
  await waitFor(() => expect(button(name).getAttribute('title')).toBe(REASON));
  expect(button(name).disabled).toBe(true);
  expect(button(name).getAttribute('data-capability-enabled')).toBe('false');
}

async function click(name: string | RegExp) {
  await act(async () => {
    fireEvent.click(button(name));
  });
}

function fillVerify(container: HTMLElement) {
  const field = (id: string) => {
    const el = container.querySelector(`#${id}`);
    if (!el) throw new Error(`no field #${id}`);
    return el;
  };
  fireEvent.change(field('vquote'), { target: { value: 'cXVvdGU=' } });
  fireEvent.change(field('vsig'), { target: { value: 'c2ln' } });
  fireEvent.change(field('vnonce'), { target: { value: '00112233' } });
}

describe('TPM provisioning and quote pages capability gate', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('withholds Provision TPM and Clear TPM when the server does not offer them', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/tpm/platform': PLATFORM,
      'GET /api/v1/tpm/capabilities': TPM_CAPABILITIES,
      'GET /api/v1/capabilities': caps([PROVISION, CLEAR]),
    });
    render(withControlPlane(<TPMProvisionPage />));
    await screen.findByTestId('platform-device');

    await expectWithheld('Provision TPM');
    await expectWithheld('Clear TPM…');
    expect(button('Provision TPM').getAttribute('data-capability-op')).toBe(PROVISION);
    expect(button('Clear TPM…').getAttribute('data-capability-op')).toBe(CLEAR);

    await click('Provision TPM');
    await click('Clear TPM…');
    expect(screen.queryByText('Clear the TPM?')).toBeNull();
    expect(sent.some((s) => s.path === '/api/v1/tpm/provision' || s.path === '/api/v1/tpm/clear')).toBe(false);
  });

  it('offers Provision TPM when the server enables it', async () => {
    stubControlPlane({
      'GET /api/v1/tpm/platform': PLATFORM,
      'GET /api/v1/tpm/capabilities': TPM_CAPABILITIES,
      'GET /api/v1/capabilities': caps(),
    });
    render(withControlPlane(<TPMProvisionPage />));
    await screen.findByTestId('platform-device');

    await waitFor(() => expect(button('Provision TPM').getAttribute('data-capability-enabled')).toBe('true'));
    expect(button('Provision TPM').getAttribute('data-capability-op')).toBe(PROVISION);
    expect(button('Provision TPM').disabled).toBe(false);
  });

  it('withholds Create AK, Generate Quote and Verify Quote when the server does not offer them', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/tpm/ak': refused(404, 'not found'),
      'GET /api/v1/capabilities': caps([CREATE_AK, QUOTE, VERIFY]),
    });
    const { container } = render(withControlPlane(<TPMQuotePage />));
    await screen.findByRole('button', { name: /Create AK/ });
    fillVerify(container);

    await expectWithheld(/Create AK/);
    await expectWithheld(/Generate Quote/);
    await expectWithheld(/Verify Quote/);
    expect(button(/Generate Quote/).getAttribute('data-capability-op')).toBe(QUOTE);

    await click(/Create AK/);
    await click(/Generate Quote/);
    await click(/Verify Quote/);
    expect(sent.some((s) => s.method === 'POST')).toBe(false);
  });

  it('offers Generate Quote when the server enables it', async () => {
    stubControlPlane({
      'GET /api/v1/tpm/ak': refused(404, 'not found'),
      'GET /api/v1/capabilities': caps(),
    });
    render(withControlPlane(<TPMQuotePage />));
    await screen.findByRole('heading', { level: 1, name: 'Quote / Attestation' });

    await waitFor(() => expect(button(/Generate Quote/).getAttribute('data-capability-enabled')).toBe('true'));
    expect(button(/Generate Quote/).disabled).toBe(false);
  });
});
