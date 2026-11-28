import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import TPMCredentialPage from './credential/page';
import TPMPCRsPage from './pcrs/page';

// The TPM pages follow the server's capabilities (#2069): Extend PCR, Make
// Credential, Activate Credential and Get Random are each wrapped in the
// capability gate, so a server that does not offer the operation leaves the
// control disabled with the server's reason as its title.

const TPM_OPS = [
  'POST /api/v1/tpm/pcrs',
  'POST /api/v1/tpm/pcrs/extend',
  'POST /api/v1/tpm/make-credential',
  'POST /api/v1/tpm/activate-credential',
  'POST /api/v1/tpm/random',
  'GET /api/v1/tpm/eventlog',
];

const REASON = 'not-configured: tpm';

function caps(off: string[] = []): Answer {
  const capabilities = TPM_OPS.map((op) =>
    off.includes(op) ? { op, kind: 'route', enabled: false, reason: REASON } : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

async function expectWithheld(name: string) {
  await waitFor(() => expect(button(name).getAttribute('title')).toBe(REASON));
  expect(button(name).disabled).toBe(true);
  expect(button(name).getAttribute('data-capability-enabled')).toBe('false');
}

describe('TPM pages capability gate', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('withholds Extend PCR when the server does not offer POST /api/v1/tpm/pcrs/extend', async () => {
    stubControlPlane({
      'POST /api/v1/tpm/pcrs': ok({ pcrValues: [] }),
      'GET /api/v1/capabilities': caps(['POST /api/v1/tpm/pcrs/extend']),
    });
    render(withControlPlane(<TPMPCRsPage />));

    fireEvent.change(screen.getByLabelText('PCR index'), { target: { value: '16' } });
    fireEvent.change(screen.getByLabelText('Data'), { target: { value: 'boot-ok' } });

    await expectWithheld('Extend PCR');
  });

  it('withholds Make credential, Activate and Get random when the server does not offer them', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps([
        'POST /api/v1/tpm/make-credential',
        'POST /api/v1/tpm/activate-credential',
        'POST /api/v1/tpm/random',
      ]),
    });
    render(withControlPlane(<TPMCredentialPage />));

    fireEvent.change(screen.getByLabelText('AK name (base64)'), { target: { value: 'YWs=' } });
    fireEvent.change(screen.getByLabelText('Number of bytes'), { target: { value: '16' } });

    for (const name of ['Make Credential', 'Activate Credential', 'Get Random']) {
      await expectWithheld(name);
    }
  });

  it('enables the TPM controls the server offers', async () => {
    stubControlPlane({
      'POST /api/v1/tpm/pcrs': ok({ pcrValues: [] }),
      'GET /api/v1/capabilities': caps(),
    });
    render(
      withControlPlane(
        <>
          <TPMPCRsPage />
          <TPMCredentialPage />
        </>,
      ),
    );

    for (const name of ['Extend PCR', 'Make Credential', 'Activate Credential', 'Get Random']) {
      await waitFor(() => expect(button(name).getAttribute('data-capability-enabled')).toBe('true'));
    }
  });
});
