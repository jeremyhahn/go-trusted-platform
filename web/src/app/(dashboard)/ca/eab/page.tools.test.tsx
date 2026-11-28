import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import EABCredentialsPage from './page';

// #2050: the EAB page reaches GetCredentialByKeyID and ValidateCredential
// through the SDK client (client.eab.getByKeyId, .validate), each control
// behind the capability gate.

const EAB_OPS = [
  'GET /api/v1/eab/credentials',
  'POST /api/v1/eab/credentials',
  'POST /api/v1/eab/credentials/validate',
  'GET /api/v1/eab/credentials/key/{key}',
  'GET /api/v1/eab/credentials/{id:[0-9]+}',
  'DELETE /api/v1/eab/credentials/{id:[0-9]+}',
  'POST /api/v1/eab/credentials/{id:[0-9]+}/revoke',
  'GET /api/v1/eab/credentials/{id:[0-9]+}/qrcode',
  'GET /api/v1/eab/credentials/{id:[0-9]+}/url',
] as const;

// The server's capabilities listing: every EAB op enabled except those left out.
function caps(leaveOut: string[] = []): Answer {
  const capabilities = EAB_OPS.filter((op) => !leaveOut.includes(op)).map((op) => ({ op, kind: 'route', enabled: true }));
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.length });
}

const CREDENTIAL = {
  id: '7',
  keyId: 'kid-seven',
  profileId: '1',
  tenantId: 'tenant-a',
  status: 'EAB_CREDENTIAL_STATUS_ACTIVE',
  expiresAt: '2026-12-01T00:00:00Z',
};

function shared(): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'GET /api/v1/eab/credentials': ok({ credentials: [CREDENTIAL], totalCount: 1 }),
  };
}

async function renderLoaded() {
  render(withControlPlane(<EABCredentialsPage />));
  await screen.findByText('kid-seven');
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe('EABCredentialsPage tools', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('finds a credential by key ID', async () => {
    const sent = stubControlPlane({
      ...shared(),
      'GET /api/v1/eab/credentials/key/kid-seven': ok({ credential: CREDENTIAL }),
    });
    await renderLoaded();

    type('Key ID', 'kid-seven');
    await click('Find by key ID');

    const result = within(await screen.findByTestId('eab-tool-result'));
    expect(await result.findByText(/Found kid-seven/)).toBeTruthy();
    expect(result.getByText(/Active/)).toBeTruthy();
    expect(sent.some((r) => r.method === 'GET' && r.path === '/api/v1/eab/credentials/key/kid-seven')).toBe(true);
  });

  it('validates a key ID and HMAC key, valid and invalid', async () => {
    const sent = stubControlPlane({
      ...shared(),
      'POST /api/v1/eab/credentials/validate': ok({ valid: true, credential: CREDENTIAL }),
    });
    await renderLoaded();

    type('Key ID', 'kid-seven');
    type('HMAC key', 'c2VjcmV0');
    await click('Validate');

    const result = within(await screen.findByTestId('eab-tool-result'));
    expect(await result.findByText('Valid')).toBeTruthy();
    const post = sent.find((r) => r.method === 'POST' && r.path === '/api/v1/eab/credentials/validate');
    expect(post?.body).toEqual({ keyId: 'kid-seven', hmacKey: 'c2VjcmV0' });

    cleanup();
    vi.unstubAllGlobals();
    stubControlPlane({
      ...shared(),
      'POST /api/v1/eab/credentials/validate': ok({ valid: false, errorMessage: 'eab: HMAC key does not match' }),
    });
    await renderLoaded();
    type('Key ID', 'kid-seven');
    type('HMAC key', 'd3Jvbmc=');
    await click('Validate');

    const invalid = within(await screen.findByTestId('eab-tool-result'));
    expect(await invalid.findByText('Invalid: eab: HMAC key does not match')).toBeTruthy();
  });

  it('withholds the controls the server does not offer', async () => {
    stubControlPlane({
      ...shared(),
      'GET /api/v1/capabilities': caps([
        'GET /api/v1/eab/credentials/key/{key}',
        'POST /api/v1/eab/credentials/validate',
        'POST /api/v1/eab/credentials/{id:[0-9]+}/revoke',
        'DELETE /api/v1/eab/credentials/{id:[0-9]+}',
      ]),
    });
    await renderLoaded();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Find by key ID' }).getAttribute('data-capability-enabled')).toBe(
        'false',
      );
    });
    for (const name of ['Find by key ID', 'Validate', 'Revoke', 'Delete']) {
      const button = screen.getByRole('button', { name }) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
    }
    const details = screen.getByRole('button', { name: 'Details kid-seven' });
    expect(details.getAttribute('data-capability-enabled')).toBe('true');
  });
});
