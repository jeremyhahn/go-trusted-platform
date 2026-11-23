import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { DeviceTemplate } from 'trusted-platform-sdk';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';

const { off } = vi.hoisted(() => ({ off: new Set<string>() }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: 'not-configured: device' } : { enabled: true },
  }),
}));

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn() }),
  usePathname: () => '/devices/templates/7101',
  useParams: () => ({ id: '7101' }),
}));

import { TemplateEditDialog } from './template-edit-dialog';

const UPDATE_OP = 'PUT /api/v1/device/templates/{id:[0-9]+}';

const template = {
  id: '7101',
  name: 'workers',
  description: 'd',
  role: 'worker',
  created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-01T00:00:00Z',
} as unknown as DeviceTemplate;

function mount(onSaved = vi.fn()) {
  render(
    withControlPlane(
      <TemplateEditDialog template={template} open onOpenChange={vi.fn()} onSaved={onSaved} />
    )
  );
  return onSaved;
}

const save = () => screen.getByRole('button', { name: 'Save template' }) as HTMLButtonElement;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  off.clear();
});

describe('TemplateEditDialog', () => {
  it('saves the edited name, description and role through PUT /device/templates/{id}', async () => {
    const sent = stubControlPlane({
      'PUT /api/v1/device/templates/7101': ok({ ...template, name: 'workers-v2' }),
    });
    const onSaved = mount();

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'workers-v2' } });
    fireEvent.click(save());

    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
    const put = sent.find((r) => r.method === 'PUT');
    expect(put?.path).toBe('/api/v1/device/templates/7101');
    expect(put?.body).toEqual({ id: '7101', name: 'workers-v2', description: 'd', role: 'worker' });
    expect(await screen.findByText(/Template saved/)).toBeTruthy();
  });

  it('keeps Save disabled while the name is blank', () => {
    stubControlPlane({});
    mount();

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: '   ' } });
    expect(save().disabled).toBe(true);
  });

  it('shows a refused save as a destructive toast and keeps the dialog open', async () => {
    stubControlPlane({ 'PUT /api/v1/device/templates/7101': refused(409, 'name taken') });
    const onSaved = mount();

    fireEvent.click(save());

    const toast = await screen.findByText(/name taken/);
    expect(toast.closest('[data-testid="toast"]')?.getAttribute('data-variant')).toBe('destructive');
    expect(toast.textContent).toContain('Error saving template');
    expect(onSaved).not.toHaveBeenCalled();
    expect(screen.getByText('Edit template')).toBeTruthy();
  });

  it('withholds Save when the server does not offer the update', () => {
    off.add(UPDATE_OP);
    const sent = stubControlPlane({});
    mount();

    const el = save();
    expect(el.getAttribute('data-capability-op')).toBe(UPDATE_OP);
    expect(el.disabled).toBe(true);
    expect(el.getAttribute('title')).toBe('not-configured: device');
    fireEvent.click(el);
    expect(sent.some((r) => r.method === 'PUT')).toBe(false);
  });
});
