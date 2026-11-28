import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { VMDisksCard } from './vm-disks-card';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const VM_PATH = '/api/v1/compute/vms/vm-1';
const DISKS_PATH = '/api/v1/compute/vms/vm-1/disks';

function vmAnswer(disks: unknown[] = [
  { id: 'd1', path: '/var/lib/vms/web-1.qcow2', type: 'DISK_TYPE_QCOW2', bus: 'DISK_BUS_VIRTIO', sizeGb: '20' },
]): Answer {
  return ok({ vm: { id: 'vm-1', state: 'VM_STATE_RUNNING', config: { name: 'web-1', disks } } });
}

function renderCard(routes: Record<string, Answer> = {}) {
  const sent = stubControlPlane({ [`GET ${VM_PATH}`]: vmAnswer(), ...routes });
  render(withControlPlane(<VMDisksCard vmId="vm-1" />));
  return sent;
}

const count = (sent: { method: string; path: string }[], key: string) =>
  sent.filter((r) => `${r.method} ${r.path}` === key).length;

describe('VMDisksCard', () => {
  it('lists the disks', async () => {
    renderCard();
    const row = await screen.findByTestId('vm-disk-d1');
    expect(row.textContent).toContain('/var/lib/vms/web-1.qcow2');
    expect(row.textContent).toContain('QCOW2');
    expect(row.textContent).toContain('VIRTIO');
    expect(row.textContent).toContain('20 GB');
    cleanup();
    vi.unstubAllGlobals();

    stubControlPlane({ [`GET ${VM_PATH}`]: vmAnswer([]) });
    render(withControlPlane(<VMDisksCard vmId="vm-1" />));
    expect((await screen.findByTestId('vm-disks-empty')).textContent).toContain('No disks attached.');
  });

  it('attaches a disk and re-reads the list', async () => {
    const sent = renderCard({ [`POST ${DISKS_PATH}`]: ok({ status: { success: true } }) });
    await screen.findByTestId('vm-disk-d1');
    fireEvent.change(screen.getByTestId('vm-disk-path'), { target: { value: '/var/lib/vms/data.qcow2' } });
    fireEvent.change(screen.getByTestId('vm-disk-size'), { target: { value: '10' } });
    fireEvent.click(screen.getByTestId('vm-disk-attach'));
    await waitFor(() => expect(count(sent, `GET ${VM_PATH}`)).toBe(2));
    const posts = sent.filter((r) => r.method === 'POST' && r.path === DISKS_PATH);
    expect(posts).toHaveLength(1);
    const body = posts[0].body as { disk: { sizeGb: number; type: string; path: string } };
    expect(body.disk.sizeGb).toBe(10);
    expect(body.disk.type).toBe('DISK_TYPE_QCOW2');
    expect(body.disk.path).toBe('/var/lib/vms/data.qcow2');
  });

  it('refuses a bad form without a request', async () => {
    const sent = renderCard();
    await screen.findByTestId('vm-disk-d1');
    fireEvent.click(screen.getByTestId('vm-disk-attach'));
    expect(await screen.findByTestId('vm-disk-form-error')).toBeTruthy();
    expect(count(sent, `POST ${DISKS_PATH}`)).toBe(0);

    fireEvent.change(screen.getByTestId('vm-disk-resize-d1'), { target: { value: '10' } });
    fireEvent.click(screen.getByTestId('vm-disk-resize-apply-d1'));
    await waitFor(() => expect(screen.getByTestId('vm-disk-form-error').textContent).toContain('A disk can only grow.'));
    expect(sent.filter((r) => r.method === 'PATCH')).toHaveLength(0);
  });

  it('resizes a disk', async () => {
    const sent = renderCard({ [`PATCH ${DISKS_PATH}/d1`]: ok({ status: { success: true } }) });
    await screen.findByTestId('vm-disk-d1');
    fireEvent.change(screen.getByTestId('vm-disk-resize-d1'), { target: { value: '40' } });
    fireEvent.click(screen.getByTestId('vm-disk-resize-apply-d1'));
    await waitFor(() => expect(count(sent, `PATCH ${DISKS_PATH}/d1`)).toBe(1));
    expect(sent.find((r) => r.method === 'PATCH')?.body).toEqual({ newSizeGb: 40 });
  });

  it('detaches only after the confirm', async () => {
    const sent = renderCard({ [`DELETE ${DISKS_PATH}/d1`]: ok({ status: { success: true } }) });
    await screen.findByTestId('vm-disk-d1');
    fireEvent.click(screen.getByTestId('vm-disk-detach-d1'));
    const dialog = await screen.findByTestId('vm-disk-detach-dialog');
    expect(count(sent, `DELETE ${DISKS_PATH}/d1`)).toBe(0);
    expect(within(dialog).getByText('Detach this disk?')).toBeTruthy();
    expect(dialog.textContent).toContain('/var/lib/vms/web-1.qcow2');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByTestId('vm-disk-detach-dialog')).toBeNull());
    expect(count(sent, `DELETE ${DISKS_PATH}/d1`)).toBe(0);

    fireEvent.click(screen.getByTestId('vm-disk-detach-d1'));
    fireEvent.click(await screen.findByTestId('vm-disk-detach-confirm'));
    await waitFor(() => expect(count(sent, `DELETE ${DISKS_PATH}/d1`)).toBe(1));
  });

  it("shows the server's refusal", async () => {
    renderCard({ [`POST ${DISKS_PATH}`]: refused(409, 'compute: disk path already attached') });
    await screen.findByTestId('vm-disk-d1');
    fireEvent.change(screen.getByTestId('vm-disk-path'), { target: { value: '/var/lib/vms/web-1.qcow2' } });
    fireEvent.change(screen.getByTestId('vm-disk-size'), { target: { value: '10' } });
    fireEvent.click(screen.getByTestId('vm-disk-attach'));
    expect((await screen.findByTestId('vm-disks-error')).textContent).toContain('already attached');
  });
});
