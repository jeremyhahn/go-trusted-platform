import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { EABCredentialDetail } from './eab-credential-detail';

// #2050: GetCredential, GetCredentialQRCode and GetEnrollmentURL reach the
// console through the SDK client (client.eab.get, .getQRCode, .getEnrollmentURL).

const QR = 'iVBORw0KGgo=';

function answers() {
  return {
    'GET /api/v1/eab/credentials/7': ok({
      credential: {
        id: '7',
        keyId: 'kid-seven',
        profileId: '1',
        tenantId: 'tenant-a',
        status: 'EAB_CREDENTIAL_STATUS_ACTIVE',
        expiresAt: '2026-12-01T00:00:00Z',
        createdAt: '2026-11-01T00:00:00Z',
      },
    }),
    'GET /api/v1/eab/credentials/7/qrcode': ok({ qrCode: QR, contentType: 'image/png' }),
    'GET /api/v1/eab/credentials/7/url': ok({
      url: 'https://acme.example/enroll?kid=kid-seven',
      expiresAt: '2026-12-01T00:00:00Z',
    }),
  };
}

describe('EABCredentialDetail', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('EABCredentialDetail reads the credential, its QR code and enrolment URL', async () => {
    const sent = stubControlPlane(answers());
    render(withControlPlane(<EABCredentialDetail id={7} />));

    const detail = within(await screen.findByTestId('eab-credential-detail'));
    expect(await detail.findByText('kid-seven')).toBeTruthy();
    expect(detail.getByText('Active')).toBeTruthy();
    const img = (await detail.findByRole('img', { name: 'QR code for kid-seven' })) as HTMLImageElement;
    expect(img.getAttribute('src')).toBe(`data:image/png;base64,${QR}`);
    expect(await detail.findByText('https://acme.example/enroll?kid=kid-seven')).toBeTruthy();

    const paths = sent.filter((r) => r.method === 'GET').map((r) => r.path);
    expect(paths).toContain('/api/v1/eab/credentials/7');
    expect(paths).toContain('/api/v1/eab/credentials/7/qrcode');
    expect(paths).toContain('/api/v1/eab/credentials/7/url');
  });

  it('shows a refused read', async () => {
    stubControlPlane({
      ...answers(),
      'GET /api/v1/eab/credentials/7': refused(404, 'eab: credential 7 not found'),
    });
    render(withControlPlane(<EABCredentialDetail id={7} />));

    expect((await screen.findByRole('alert')).textContent).toContain('eab: credential 7 not found');
  });
});
