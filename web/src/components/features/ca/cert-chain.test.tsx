import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import type { Certificate } from '@/types/security';
import { CertChain } from './cert-chain';

const DAY = 24 * 60 * 60 * 1000;

function inDays(days: number): string {
  return new Date(Date.now() + days * DAY).toISOString();
}

function cert(overrides: Partial<Certificate> = {}): Certificate {
  return {
    id: 'root',
    subject: 'CN=Root CA',
    issuer: 'CN=Root CA',
    serialNumber: '01',
    type: 'root',
    status: 'active',
    notBefore: inDays(-365),
    notAfter: inDays(3650),
    publicKeyAlgorithm: 'ECDSA',
    signatureAlgorithm: 'ECDSA-SHA256',
    ...overrides,
  };
}

const chain: Certificate[] = [
  cert(),
  cert({ id: 'int', subject: 'CN=Intermediate CA', issuer: 'CN=Root CA', serialNumber: '02', type: 'intermediate' }),
  cert({ id: 'leaf', subject: 'CN=device-7', issuer: 'CN=Intermediate CA', serialNumber: '03', type: 'leaf' }),
];

describe('CertChain', () => {
  afterEach(() => cleanup());

  it('says no chain is available for an empty chain', () => {
    render(<CertChain chain={[]} />);
    expect(screen.getByText('No certificate chain available')).toBeDefined();
    expect(screen.queryByText('Certificate Chain')).toBeNull();
  });

  it('lists every certificate from root to leaf in order', () => {
    const { container } = render(<CertChain chain={chain} />);
    expect(screen.getByText('Certificate Chain')).toBeDefined();
    const subjects = ['CN=Root CA', 'CN=Intermediate CA', 'CN=device-7'].map((s) =>
      screen.getAllByText(s).find((el) => el.className.includes('font-medium'))
    );
    subjects.forEach((el) => expect(el).toBeDefined());
    const text = container.textContent ?? '';
    expect(text.indexOf('CN=Root CA')).toBeLessThan(text.indexOf('CN=Intermediate CA'));
    expect(text.indexOf('CN=Intermediate CA')).toBeLessThan(text.indexOf('CN=device-7'));
    expect(screen.getByText('Issuer: CN=Intermediate CA')).toBeDefined();
    expect(screen.getByText('03')).toBeDefined();
    expect(screen.getByText('leaf')).toBeDefined();
  });

  it('draws a connector between certificates but not after the last', () => {
    const { container } = render(<CertChain chain={chain} />);
    expect(container.querySelectorAll('svg').length).toBe(chain.length - 1);
  });

  it('draws no connector for a single certificate', () => {
    const { container } = render(<CertChain chain={[cert()]} />);
    expect(container.querySelectorAll('svg').length).toBe(0);
  });

  it('marks only the current certificate', () => {
    render(<CertChain chain={chain} currentCertId="int" />);
    expect(screen.getAllByText('Current')).toHaveLength(1);
    const card = screen.getByText('CN=Intermediate CA', { selector: '.font-medium' }).closest('.rounded-lg');
    expect(card?.className).toContain('border-primary');
  });

  it('marks nothing when the current id matches no certificate', () => {
    render(<CertChain chain={chain} currentCertId="missing" />);
    expect(screen.queryByText('Current')).toBeNull();
  });

  it('flags a certificate expiring within 30 days', () => {
    render(<CertChain chain={[cert({ notAfter: inDays(10) })]} />);
    expect(screen.getByText('Expiring soon')).toBeDefined();
  });

  it('shows an expired certificate in red without the expiring-soon note', () => {
    const notAfter = inDays(-1);
    render(<CertChain chain={[cert({ notAfter, status: 'expired' })]} />);
    expect(screen.queryByText('Expiring soon')).toBeNull();
    const date = screen.getByText(new Date(notAfter).toLocaleDateString());
    expect(date.className).toContain('text-destructive');
    expect(screen.getByText('expired')).toBeDefined();
  });

  it('shows a far-off expiry plainly', () => {
    render(<CertChain chain={[cert()]} />);
    expect(screen.queryByText('Expiring soon')).toBeNull();
  });

  it('shows the revoked status', () => {
    render(<CertChain chain={[cert({ status: 'revoked' })]} />);
    expect(screen.getByText('revoked')).toBeDefined();
  });
});
