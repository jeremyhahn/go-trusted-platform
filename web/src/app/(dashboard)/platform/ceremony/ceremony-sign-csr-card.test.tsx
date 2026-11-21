import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { CEREMONY_OFFICER_ROLES, CeremonySignCSRCard, officerRoleLabel } from './ceremony-sign-csr-card';

// #2042: the ceremony page signs an officer CSR through
// useCeremony().signCSR (CeremonyService.SignCSR).

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/platform/ceremony',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const SIGN_PATH = 'POST /api/v1/ceremony/sign-csr';
const CSR = '-----BEGIN CERTIFICATE REQUEST-----\nTEST\n-----END CERTIFICATE REQUEST-----';
const CERT_PEM = '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----';
const CHAIN_PEM = '-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----';

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function fillAll() {
  fill('Username', ' officer1 ');
  fill('SO PIN', 'so-pin-test');
  fill('CSR (PEM)', `${CSR}\n`);
}

describe('ceremony sign-CSR helpers', () => {
  it('labels the officer roles', () => {
    expect(CEREMONY_OFFICER_ROLES).toEqual([
      'CEREMONY_OFFICER_ROLE_SO',
      'CEREMONY_OFFICER_ROLE_ADMIN',
      'CEREMONY_OFFICER_ROLE_USER',
    ]);
    expect(officerRoleLabel('CEREMONY_OFFICER_ROLE_SO')).toBe('Security officer');
    expect(officerRoleLabel('CEREMONY_OFFICER_ROLE_ADMIN')).toBe('Admin');
    expect(officerRoleLabel('CEREMONY_OFFICER_ROLE_USER')).toBe('User');
    expect(officerRoleLabel('CEREMONY_OFFICER_ROLE_UNSPECIFIED')).toBe('Unspecified');
  });
});

describe('CeremonySignCSRCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('keeps Sign CSR disabled until username, SO PIN and CSR are set', () => {
    stubControlPlane({});
    render(withControlPlane(<CeremonySignCSRCard />));

    const button = screen.getByRole('button', { name: 'Sign CSR' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fill('Username', 'officer1');
    fill('SO PIN', 'so-pin-test');
    fill('CSR (PEM)', '   ');
    expect(button.disabled).toBe(true);
    fill('CSR (PEM)', CSR);
    expect(button.disabled).toBe(false);
  });

  it('signs a CSR with the chosen role', async () => {
    const sent = stubControlPlane({ [SIGN_PATH]: ok({ certificatePem: CERT_PEM, chainPem: CHAIN_PEM }) });
    render(withControlPlane(<CeremonySignCSRCard />));

    fillAll();
    fill('Role', 'CEREMONY_OFFICER_ROLE_ADMIN');
    fireEvent.click(screen.getByRole('button', { name: 'Sign CSR' }));

    const cert = (await screen.findByLabelText('Certificate')) as HTMLTextAreaElement;
    expect(sent).toEqual([
      {
        method: 'POST',
        path: '/api/v1/ceremony/sign-csr',
        body: { username: 'officer1', soPin: 'so-pin-test', csrPem: CSR, role: 'CEREMONY_OFFICER_ROLE_ADMIN' },
      },
    ]);
    expect(cert.value).toBe(CERT_PEM);
    expect((screen.getByLabelText('Chain') as HTMLTextAreaElement).value).toBe(CHAIN_PEM);
    expect((screen.getByLabelText('SO PIN') as HTMLInputElement).value).toBe('');
  });

  it('defaults the role to user', async () => {
    const sent = stubControlPlane({ [SIGN_PATH]: ok({ certificatePem: CERT_PEM, chainPem: CHAIN_PEM }) });
    render(withControlPlane(<CeremonySignCSRCard />));

    fillAll();
    fireEvent.click(screen.getByRole('button', { name: 'Sign CSR' }));

    await screen.findByLabelText('Certificate');
    expect((sent[0].body as { role: string }).role).toBe('CEREMONY_OFFICER_ROLE_USER');
  });

  it('shows a refusal verbatim', async () => {
    stubControlPlane({ [SIGN_PATH]: refused(403, 'ceremony: wrong SO PIN') });
    render(withControlPlane(<CeremonySignCSRCard />));

    fillAll();
    fireEvent.click(screen.getByRole('button', { name: 'Sign CSR' }));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe('Sign CSR refused: ceremony: wrong SO PIN');
    expect(screen.queryByLabelText('Certificate')).toBeNull();
  });
});
