import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_POST_ENROLLMENT_NETWORK } from 'trusted-platform-sdk';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import CreateProfileClient from './create-profile-client';

// #413: every input the create-from-template page collects reaches the
// POST /device/templates/{id}/create-profile body. A field the route cannot
// carry (the old Hostname input) is not rendered at all.

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: '42' }),
  usePathname: () => '/devices/templates/42/create-profile',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const CREATE_PATH = '/api/v1/device/templates/42/create-profile';

async function renderPage() {
  const sent = stubControlPlane({
    'GET /api/v1/device/templates/42': ok({ id: 42, name: 'edge-node', role: 'edge' }),
    [`POST ${CREATE_PATH}`]: ok({ id: 9 }),
  });
  const { container } = render(withControlPlane(<CreateProfileClient />));
  await screen.findByRole('heading', { level: 1, name: 'Create Profile from Template' });
  return { sent, form: container.querySelector('form') as HTMLFormElement };
}

describe('CreateProfileClient request body', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('sends every value the form collects', async () => {
    const { sent, form } = await renderPage();

    // A distinct value per input, so each one can be found in the body.
    const inputs = Array.from(form.querySelectorAll('input'));
    expect(inputs.map((input) => input.id).sort()).toEqual(['ekSerial', 'macAddress', 'staticIp']);
    for (const input of inputs) {
      fireEvent.change(input, { target: { value: `value-of-${input.id}` } });
    }

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Create Profile' }));
    });
    await screen.findByRole('heading', { name: 'Profile Created' });

    const create = sent.find((r) => r.method === 'POST' && r.path === CREATE_PATH);
    expect(create?.body).toEqual({
      templateId: '42',
      overrides: {
        ek_serial: 'value-of-ekSerial',
        mac_address: 'value-of-macAddress',
        networks: { [DEFAULT_POST_ENROLLMENT_NETWORK]: { static_ip: 'value-of-staticIp' } },
        post_enrollment_network: DEFAULT_POST_ENROLLMENT_NETWORK,
      },
    });
    const body = JSON.stringify(create?.body);
    for (const input of inputs) {
      expect(body).toContain(`value-of-${input.id}`);
    }
  });

  it('renders no Hostname input, which the route has no field for', async () => {
    await renderPage();

    expect(screen.queryByLabelText('Hostname')).toBeNull();
    expect(screen.getByLabelText('Static IP Address')).toBeDefined();
  });
});
