import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { CertificateDetail } from '@/types/security';
import { CertDetail } from './cert-detail';

const DAY = 24 * 60 * 60 * 1000;

function inDays(days: number): string {
  return new Date(Date.now() + days * DAY).toISOString();
}

function detail(overrides: Partial<CertificateDetail> = {}): CertificateDetail {
  return {
    id: 'leaf',
    subject: 'CN=device-7',
    issuer: 'CN=Intermediate CA',
    serialNumber: '0a:1b:2c',
    type: 'leaf',
    status: 'active',
    notBefore: inDays(-10),
    notAfter: inDays(355),
    publicKeyAlgorithm: 'ECDSA P-256',
    signatureAlgorithm: 'ECDSA-SHA256',
    publicKey: 'PUBLIC-KEY-BYTES',
    extensions: [],
    chain: [],
    pemEncoded: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----',
    derEncoded: 'AAAA',
    ...overrides,
  };
}

describe('CertDetail', () => {
  afterEach(() => cleanup());

  it('shows the certificate fields', () => {
    const cert = detail();
    render(<CertDetail certificate={cert} />);
    expect(screen.getByRole('heading', { name: 'CN=device-7' })).toBeDefined();
    expect(screen.getByText('CN=Intermediate CA')).toBeDefined();
    expect(screen.getByText('0a:1b:2c')).toBeDefined();
    expect(screen.getByText('active')).toBeDefined();
    expect(screen.getAllByText('leaf')).toHaveLength(2);
    expect(screen.getByText('ECDSA P-256')).toBeDefined();
    expect(screen.getByText('ECDSA-SHA256')).toBeDefined();
    expect(screen.getByText('PUBLIC-KEY-BYTES')).toBeDefined();
    expect(screen.getByText(/BEGIN CERTIFICATE/)).toBeDefined();
    expect(screen.getByText(new Date(cert.notBefore).toLocaleString())).toBeDefined();
    expect(screen.getByText(new Date(cert.notAfter).toLocaleString())).toBeDefined();
    expect(screen.queryByText(/\(Expired\)/)).toBeNull();
  });

  it('renders no action buttons without handlers', () => {
    render(<CertDetail certificate={detail()} />);
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('calls each handler from its button', () => {
    const onDownloadPEM = vi.fn();
    const onDownloadDER = vi.fn();
    const onRevoke = vi.fn();
    render(
      <CertDetail
        certificate={detail()}
        onDownloadPEM={onDownloadPEM}
        onDownloadDER={onDownloadDER}
        onRevoke={onRevoke}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: 'PEM' }));
    fireEvent.click(screen.getByRole('button', { name: 'DER' }));
    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    expect(onDownloadPEM).toHaveBeenCalledTimes(1);
    expect(onDownloadDER).toHaveBeenCalledTimes(1);
    expect(onRevoke).toHaveBeenCalledTimes(1);
  });

  it('offers no Revoke for a revoked certificate', () => {
    render(<CertDetail certificate={detail({ status: 'revoked' })} onRevoke={vi.fn()} />);
    expect(screen.queryByRole('button', { name: 'Revoke' })).toBeNull();
    expect(screen.getByText('revoked')).toBeDefined();
  });

  it('offers no Revoke for an expired certificate and marks it expired', () => {
    const cert = detail({ notAfter: inDays(-1) });
    render(<CertDetail certificate={cert} onRevoke={vi.fn()} />);
    expect(screen.queryByRole('button', { name: 'Revoke' })).toBeNull();
    const until = screen.getByText(/\(Expired\)/);
    expect(until.textContent).toBe(`${new Date(cert.notAfter).toLocaleString()} (Expired)`);
    expect(until.className).toContain('text-destructive');
  });

  it('hides the Extensions card when there are none', () => {
    render(<CertDetail certificate={detail()} />);
    expect(screen.queryByText('Extensions')).toBeNull();
  });

  it('lists extensions and marks critical ones', () => {
    render(
      <CertDetail
        certificate={detail({
          extensions: [
            { name: 'Basic Constraints', oid: '2.5.29.19', value: 'CA:FALSE', critical: true },
            { name: 'Subject Key Identifier', oid: '2.5.29.14', value: 'ab:cd', critical: false },
          ],
        })}
      />
    );
    expect(screen.getByText('Extensions')).toBeDefined();
    expect(screen.getByText('Basic Constraints')).toBeDefined();
    expect(screen.getByText('2.5.29.19')).toBeDefined();
    expect(screen.getByText('CA:FALSE')).toBeDefined();
    expect(screen.getByText('Subject Key Identifier')).toBeDefined();
    expect(screen.getAllByText('Critical')).toHaveLength(1);
  });
});
