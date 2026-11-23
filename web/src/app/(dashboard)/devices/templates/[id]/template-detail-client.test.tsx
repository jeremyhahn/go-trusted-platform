import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';

const { off, push } = vi.hoisted(() => ({ off: new Set<string>(), push: vi.fn() }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: 'not-configured: device' } : { enabled: true },
  }),
}));

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: vi.fn(), back: vi.fn() }),
  useParams: () => ({ id: '7101' }),
  usePathname: () => '/devices/templates/7101',
}));

import TemplateDetailClient from './template-detail-client';

const UPDATE_OP = 'PUT /api/v1/device/templates/{id:[0-9]+}';
const PROFILE_OP = 'POST /api/v1/device/templates/{id:[0-9]+}/create-profile';
const DELETE_OP = 'DELETE /api/v1/device/templates/{id:[0-9]+}';

const workers = {
  id: '7101',
  name: 'workers',
  description: 'd',
  role: 'worker',
  created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-01T00:00:00Z',
};

async function mount() {
  stubControlPlane({ 'GET /api/v1/device/templates/7101': ok(workers) });
  render(withControlPlane(<TemplateDetailClient />));
  await screen.findByRole('heading', { name: 'workers' });
}

const button = (name: string) => screen.getByRole('button', { name }) as HTMLButtonElement;

function expectGatedOff(el: HTMLButtonElement, op: string) {
  expect(el.getAttribute('data-capability-op')).toBe(op);
  expect(el.getAttribute('data-capability-enabled')).toBe('false');
  expect(el.disabled).toBe(true);
  expect(el.getAttribute('title')).toBe('not-configured: device');
}

beforeEach(() => {
  push.mockReset();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  off.clear();
});

describe('TemplateDetailClient', () => {
  it('opens the Edit template dialog from Edit Template without navigating', async () => {
    await mount();

    const edit = button('Edit Template');
    expect(edit.getAttribute('data-capability-op')).toBe(UPDATE_OP);
    fireEvent.click(edit);

    expect(await screen.findByText('Edit template')).toBeTruthy();
    expect(push).not.toHaveBeenCalled();
  });

  it('withholds Edit Template when the update is not offered', async () => {
    off.add(UPDATE_OP);
    await mount();

    expectGatedOff(button('Edit Template'), UPDATE_OP);
  });

  it('withholds Create Profile from Template when the create-profile is not offered', async () => {
    off.add(PROFILE_OP);
    await mount();

    const el = button('Create Profile from Template');
    expectGatedOff(el, PROFILE_OP);
    fireEvent.click(el);
    expect(push).not.toHaveBeenCalled();
  });

  it('withholds the delete button when the delete is not offered', async () => {
    off.add(DELETE_OP);
    await mount();

    const el = button('Delete template');
    expectGatedOff(el, DELETE_OP);
    fireEvent.click(el);
    expect(screen.queryByText('Delete Template')).toBeNull();
  });
});
