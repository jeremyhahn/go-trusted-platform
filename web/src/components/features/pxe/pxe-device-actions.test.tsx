import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { PXEDeviceActions } from './pxe-device-actions';

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/networking/pxe',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const AUTHORIZE = 'POST /api/v1/pxe/devices/{id}/authorize';
const QUARANTINE = 'POST /api/v1/pxe/devices/{id}/quarantine';
const RETRY = 'POST /api/v1/pxe/devices/{id}/retry';
const REMOVE = 'DELETE /api/v1/pxe/devices/{id}';
const ENROLLED = 'POST /api/v1/pxe/devices/{id}/enrolled';
const PXE_OPS = [AUTHORIZE, QUARANTINE, RETRY, REMOVE, ENROLLED];

function caps(off: string[] = []): Answer {
  const capabilities = PXE_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: pxe' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(extra: Record<string, Answer> = {}, off: string[] = []): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    'POST /api/v1/pxe/devices/d1/authorize': ok({ deviceId: 'd1', state: 'AUTHORIZED' }),
    'POST /api/v1/pxe/devices/d1/quarantine': ok({ deviceId: 'd1', state: 'QUARANTINED' }),
    'POST /api/v1/pxe/devices/d1/retry': ok({ deviceId: 'd1', state: 'DISCOVERED' }),
    'DELETE /api/v1/pxe/devices/d1': ok({ deviceId: 'd1' }),
    'POST /api/v1/pxe/devices/d1/enrolled': ok({ deviceId: 'd1', state: 'ENROLLED' }),
    ...extra,
  };
}

function renderActions(onChanged: () => void) {
  render(
    withControlPlane(
      <PXEDeviceActions
        device={{ id: 'd1', macAddress: '02:00:00:00:00:01', state: 'ENROLLED' }}
        onChanged={onChanged}
      />,
    ),
  );
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function writes(sent: { method: string; path: string }[]) {
  return sent.filter((r) => r.path.startsWith('/api/v1/pxe/'));
}

async function capabilitiesLoaded(sent: { method: string; path: string }[]) {
  await waitFor(() => expect(sent.some((r) => r.path === '/api/v1/capabilities')).toBe(true));
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Retry d1' }).getAttribute('data-capability-op')).toBe(RETRY),
  );
}

describe('PXEDeviceActions', () => {
  it('authorizes the device with the target VLAN', async () => {
    const sent = stubControlPlane(routes());
    const onChanged = vi.fn();
    renderActions(onChanged);
    await capabilitiesLoaded(sent);

    await click('Authorize d1');
    type('Target VLAN', '20');
    await click('Authorize');

    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
    expect(writes(sent)).toEqual([
      { method: 'POST', path: '/api/v1/pxe/devices/d1/authorize', body: { targetVlan: 20 } },
    ]);
    await waitFor(() =>
      expect(screen.getAllByTestId('toast').map((t) => t.getAttribute('data-variant'))).toContain('success'),
    );
  });

  it('refuses to authorize without a valid target VLAN', async () => {
    const sent = stubControlPlane(routes());
    const onChanged = vi.fn();
    renderActions(onChanged);
    await capabilitiesLoaded(sent);

    await click('Authorize d1');
    expect(screen.getByRole('dialog').textContent).not.toContain('optional');
    const confirm = () => screen.getByRole('button', { name: 'Authorize' }) as HTMLButtonElement;
    expect(confirm().disabled).toBe(true);
    await click('Authorize');
    for (const bad of ['0', '4095', '65556', '2.5']) {
      type('Target VLAN', bad);
      expect(confirm().disabled).toBe(true);
      await click('Authorize');
    }
    expect(writes(sent)).toEqual([]);
    expect(onChanged).not.toHaveBeenCalled();

    type('Target VLAN', '20');
    expect(confirm().disabled).toBe(false);
  });

  it('quarantines the device with a reason', async () => {
    const sent = stubControlPlane(routes());
    const onChanged = vi.fn();
    renderActions(onChanged);
    await capabilitiesLoaded(sent);

    await click('Quarantine d1');
    type('Quarantine reason', 'tamper');
    await click('Quarantine');

    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
    expect(writes(sent)).toEqual([
      { method: 'POST', path: '/api/v1/pxe/devices/d1/quarantine', body: { reason: 'tamper' } },
    ]);
  });

  it('refuses to quarantine without a reason', async () => {
    const sent = stubControlPlane(routes());
    const onChanged = vi.fn();
    renderActions(onChanged);
    await capabilitiesLoaded(sent);

    await click('Quarantine d1');
    const confirm = () => screen.getByRole('button', { name: 'Quarantine' }) as HTMLButtonElement;
    expect(confirm().disabled).toBe(true);
    await click('Quarantine');
    type('Quarantine reason', '   ');
    expect(confirm().disabled).toBe(true);
    await click('Quarantine');
    expect(writes(sent)).toEqual([]);
    expect(onChanged).not.toHaveBeenCalled();

    type('Quarantine reason', 'tamper');
    expect(confirm().disabled).toBe(false);
  });

  it('retries the device', async () => {
    const sent = stubControlPlane(routes());
    const onChanged = vi.fn();
    renderActions(onChanged);
    await capabilitiesLoaded(sent);

    await click('Retry d1');

    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
    expect(writes(sent).map((r) => `${r.method} ${r.path}`)).toEqual(['POST /api/v1/pxe/devices/d1/retry']);
  });

  it('removes the device only after the confirm', async () => {
    const sent = stubControlPlane(routes());
    const onChanged = vi.fn();
    renderActions(onChanged);
    await capabilitiesLoaded(sent);

    await click('Remove d1');
    expect(writes(sent)).toEqual([]);
    expect(screen.getByText('Remove device')).toBeTruthy();

    await click('Remove');

    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
    expect(writes(sent).map((r) => `${r.method} ${r.path}`)).toEqual(['DELETE /api/v1/pxe/devices/d1']);
  });

  it('withholds each action the server does not offer and shows a refused write', async () => {
    const offSent = stubControlPlane(routes({}, [RETRY, REMOVE]));
    renderActions(vi.fn());
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Retry d1' }).getAttribute('data-capability-enabled')).toBe('false'),
    );
    for (const name of ['Retry d1', 'Remove d1']) {
      const button = screen.getByRole('button', { name }) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      expect(button.getAttribute('title')).toBe('not-configured: pxe');
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
    }
    for (const name of ['Authorize d1', 'Quarantine d1']) {
      const button = screen.getByRole('button', { name }) as HTMLButtonElement;
      expect(button.disabled).toBe(false);
      expect(button.getAttribute('data-capability-enabled')).toBe('true');
    }
    expect(writes(offSent)).toEqual([]);
    cleanup();
    vi.unstubAllGlobals();

    const sent = stubControlPlane(
      routes({ 'POST /api/v1/pxe/devices/d1/retry': refused(409, 'device busy') }),
    );
    const onChanged = vi.fn();
    renderActions(onChanged);
    await capabilitiesLoaded(sent);

    await click('Retry d1');

    await waitFor(() => {
      const failed = screen
        .getAllByTestId('toast')
        .filter((t) => t.getAttribute('data-variant') === 'destructive');
      expect(failed.map((t) => t.textContent).join(' ')).toContain('device busy');
    });
    expect(onChanged).not.toHaveBeenCalled();
  });

  it('marks the device enrolled with the certificate serial', async () => {
    const sent = stubControlPlane(routes());
    const onChanged = vi.fn();
    renderActions(onChanged);
    await capabilitiesLoaded(sent);

    await click('Mark enrolled d1');
    type('Certificate serial', '0A1B2C');
    await click('Mark enrolled');

    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
    expect(writes(sent)).toEqual([
      { method: 'POST', path: '/api/v1/pxe/devices/d1/enrolled', body: { certificateSerial: '0A1B2C' } },
    ]);
    await waitFor(() =>
      expect(screen.getAllByTestId('toast').map((t) => t.getAttribute('data-variant'))).toContain('success'),
    );
  });

  it('withholds Mark enrolled when the server does not offer it and needs a serial', async () => {
    const offSent = stubControlPlane(routes({}, [ENROLLED]));
    renderActions(vi.fn());
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Mark enrolled d1' }).getAttribute('data-capability-enabled')).toBe(
        'false',
      ),
    );
    const enrolled = screen.getByRole('button', { name: 'Mark enrolled d1' }) as HTMLButtonElement;
    expect(enrolled.disabled).toBe(true);
    expect(enrolled.getAttribute('title')).toBe('not-configured: pxe');
    const authorize = screen.getByRole('button', { name: 'Authorize d1' }) as HTMLButtonElement;
    expect(authorize.disabled).toBe(false);
    expect(authorize.getAttribute('data-capability-enabled')).toBe('true');
    expect(writes(offSent)).toEqual([]);
    cleanup();
    vi.unstubAllGlobals();

    const sent = stubControlPlane(routes());
    const onChanged = vi.fn();
    renderActions(onChanged);
    await capabilitiesLoaded(sent);

    await click('Mark enrolled d1');
    type('Certificate serial', '   ');
    const submit = screen.getByRole('button', { name: 'Mark enrolled' }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    await act(async () => {
      fireEvent.click(submit);
    });
    expect(writes(sent).filter((r) => r.path.endsWith('/enrolled'))).toEqual([]);
    expect(onChanged).not.toHaveBeenCalled();
  });
});
