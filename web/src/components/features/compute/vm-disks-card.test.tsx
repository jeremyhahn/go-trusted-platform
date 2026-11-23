import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import type { VMDisk } from '@/types/infrastructure';
import { VMDisksCard } from './vm-disks-card';

// #2044: the VM disks card lists a VM's disks and sends AttachDisk,
// ResizeDisk and DetachDisk through the SDK ComputeService, each control
// behind the server's capability gate; a refusal reaches the operator as a
// destructive toast.

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'vm-1' }),
  usePathname: () => '/compute/vms/vm-1',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const ATTACH_OP = 'POST /api/v1/compute/vms/{id}/disks';
const RESIZE_OP = 'PATCH /api/v1/compute/vms/{id}/disks/{diskId}';
const DETACH_OP = 'DELETE /api/v1/compute/vms/{id}/disks/{diskId}';

const ATTACH_PATH = 'POST /api/v1/compute/vms/vm-1/disks';
const RESIZE_PATH = 'PATCH /api/v1/compute/vms/vm-1/disks/disk-1';
const DETACH_PATH = 'DELETE /api/v1/compute/vms/vm-1/disks/disk-1';

const REASON = 'not-configured: compute';

// The server's capabilities listing: the three disk ops enabled unless off.
function caps(off = false): Answer {
  const capabilities = [ATTACH_OP, RESIZE_OP, DETACH_OP].map((op) =>
    off ? { op, kind: 'route', enabled: false, reason: REASON } : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

const disks: VMDisk[] = [
  { id: 'disk-1', path: '/var/lib/vms/web-1.qcow2', sizeMB: 20480, type: 'disk', readonly: false },
];

function renderCard(onChanged: () => void) {
  render(withControlPlane(<VMDisksCard vmId="vm-1" disks={disks} onChanged={onChanged} />));
}

async function enabledButton(name: string) {
  await waitFor(() => {
    expect(screen.getByRole('button', { name }).getAttribute('data-capability-enabled')).toBe('true');
  });
  return screen.getByRole('button', { name });
}

async function click(el: HTMLElement) {
  await act(async () => {
    fireEvent.click(el);
  });
}

async function expectToast(variant: string, text?: string) {
  await waitFor(() => {
    const toasts = screen.getAllByTestId('toast');
    expect(
      toasts.some(
        (t) => t.getAttribute('data-variant') === variant && (text === undefined || t.textContent?.includes(text)),
      ),
    ).toBe(true);
  });
}

describe('VMDisksCard', () => {
  it('lists each disk with its path and size in GB', () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps() });
    renderCard(vi.fn());

    expect(screen.getByText('/var/lib/vms/web-1.qcow2')).toBeDefined();
    expect(screen.getByText('20 GB')).toBeDefined();
  });

  it('attaches a disk through POST /compute/vms/{id}/disks', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [ATTACH_PATH]: ok({ diskId: 'disk-2' }),
    });
    const onChanged = vi.fn();
    renderCard(onChanged);

    await click(await enabledButton('Attach disk'));
    fireEvent.change(screen.getByLabelText('Disk path'), { target: { value: '/var/lib/vms/data.qcow2' } });
    fireEvent.change(screen.getByLabelText('Size (GB)'), { target: { value: '10' } });
    await click(await enabledButton('Attach'));

    await waitFor(() => {
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/compute/vms/vm-1/disks',
        body: { disk: { path: '/var/lib/vms/data.qcow2', sizeGb: 10 } },
      });
    });
    await expectToast('success');
    expect(onChanged).toHaveBeenCalledTimes(1);
  });

  it('sends nothing for an empty path or a size that is not a positive integer', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [ATTACH_PATH]: ok({ diskId: 'disk-2' }),
    });
    renderCard(vi.fn());

    await click(await enabledButton('Attach disk'));
    fireEvent.change(screen.getByLabelText('Size (GB)'), { target: { value: '10' } });
    await click(await enabledButton('Attach'));
    fireEvent.change(screen.getByLabelText('Disk path'), { target: { value: '/var/lib/vms/data.qcow2' } });
    fireEvent.change(screen.getByLabelText('Size (GB)'), { target: { value: '0' } });
    await click(await enabledButton('Attach'));

    expect(sent.some((r) => r.method === 'POST' && r.path === '/api/v1/compute/vms/vm-1/disks')).toBe(false);
  });

  it('resizes a disk through PATCH .../disks/{diskId}', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [RESIZE_PATH]: ok({ newSizeGb: 40 }),
    });
    const onChanged = vi.fn();
    renderCard(onChanged);

    const resize = await enabledButton('Resize');
    fireEvent.change(screen.getByLabelText('New size (GB) for disk-1'), { target: { value: '40' } });
    await click(resize);

    await waitFor(() => {
      expect(sent).toContainEqual({
        method: 'PATCH',
        path: '/api/v1/compute/vms/vm-1/disks/disk-1',
        body: { newSizeGb: 40 },
      });
    });
    await expectToast('success');
    expect(onChanged).toHaveBeenCalledTimes(1);
  });

  it('detaches a disk only after the confirm click', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [DETACH_PATH]: ok({}),
    });
    const onChanged = vi.fn();
    renderCard(onChanged);

    await click(await enabledButton('Detach'));
    expect(sent.some((r) => r.method === 'DELETE')).toBe(false);

    await click(await enabledButton('Confirm detach'));
    await waitFor(() => {
      expect(sent).toContainEqual({
        method: 'DELETE',
        path: '/api/v1/compute/vms/vm-1/disks/disk-1',
        body: undefined,
      });
    });
    await expectToast('success');
    expect(onChanged).toHaveBeenCalledTimes(1);
  });

  it('shows a refusal as a destructive toast and does not call onChanged', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [ATTACH_PATH]: refused(409, 'disk busy'),
    });
    const onChanged = vi.fn();
    renderCard(onChanged);

    await click(await enabledButton('Attach disk'));
    fireEvent.change(screen.getByLabelText('Disk path'), { target: { value: '/var/lib/vms/data.qcow2' } });
    fireEvent.change(screen.getByLabelText('Size (GB)'), { target: { value: '10' } });
    await click(await enabledButton('Attach'));

    await expectToast('destructive', 'disk busy');
    expect(onChanged).not.toHaveBeenCalled();
  });

  it('disables each control whose op is off', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps(true) });
    renderCard(vi.fn());

    const expected: Array<[string, string]> = [
      ['Attach disk', ATTACH_OP],
      ['Resize', RESIZE_OP],
      ['Detach', DETACH_OP],
    ];
    await waitFor(() => {
      for (const [name, op] of expected) {
        const button = screen.getByRole('button', { name }) as HTMLButtonElement;
        expect(button.getAttribute('data-capability-op')).toBe(op);
        expect(button.getAttribute('data-capability-enabled')).toBe('false');
        expect(button.getAttribute('title')).toBe(REASON);
        expect(button.disabled).toBe(true);
      }
    });
  });
});
