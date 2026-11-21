import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { BMCBootMediaCard } from './bmc-boot-media-card';

// #2039: the BMC boot-media card reads and sets the boot device and reads,
// mounts and (after a confirm) unmounts virtual media through the SDK client;
// a refusal reaches the operator verbatim as a destructive toast.

const BOOT_GET = 'GET /api/v1/bmc/42/boot-device';
const BOOT_POST = 'POST /api/v1/bmc/42/boot-device';
const MEDIA_GET = 'GET /api/v1/bmc/42/virtual-media';
const MEDIA_POST = 'POST /api/v1/bmc/42/virtual-media';
const MEDIA_DELETE = 'DELETE /api/v1/bmc/42/virtual-media';
const MOUNTED = ok({ mounted: true, image_url: 'https://images.example/os.iso', media_type: 'iso' });

function baseRoutes(): Record<string, Answer> {
  return {
    [BOOT_GET]: ok({ device: 'disk' }),
    [MEDIA_GET]: ok({ mounted: false }),
  };
}

function renderCard() {
  render(withControlPlane(<BMCBootMediaCard profileID="42" />));
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function count(sent: { method: string; path: string }[], method: string, path: string) {
  return sent.filter((r) => r.method === method && r.path === path).length;
}

async function waitForFirstRead() {
  await waitFor(() => {
    expect(screen.getByTestId('bmc-boot-current').textContent).toContain('Disk');
  });
}

describe('BMCBootMediaCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads the boot device and the virtual media on mount', async () => {
    stubControlPlane(baseRoutes());
    renderCard();

    await waitForFirstRead();
    await waitFor(() => {
      expect(screen.getByTestId('bmc-media-status').textContent).toContain('No image mounted');
    });
    const select = screen.getByLabelText('Boot device') as HTMLSelectElement;
    expect(select.value).toBe('disk');
    expect(Array.from(select.options).map((o) => o.textContent)).toEqual([
      'PXE',
      'Disk',
      'CD-ROM',
      'Virtual media',
      'None',
    ]);
  });

  it('sets a persistent boot device and re-reads it', async () => {
    const sent = stubControlPlane({
      ...baseRoutes(),
      [BOOT_POST]: ok({ status: 'ok', device: 'cdrom' }),
    });
    renderCard();
    await waitForFirstRead();

    fireEvent.change(screen.getByLabelText('Boot device'), { target: { value: 'cdrom' } });
    fireEvent.click(screen.getByRole('checkbox', { name: 'Persistent' }));
    await click('Set boot device');

    const toast = await screen.findByText('Boot device set: CD-ROM at the next boot');
    expect(toast.getAttribute('data-variant')).toBe('success');
    const post = sent.find((r) => r.method === 'POST' && r.path === '/api/v1/bmc/42/boot-device');
    expect(post?.body).toEqual({ device: 'cdrom', persistent: true });
    await waitFor(() => {
      expect(count(sent, 'GET', '/api/v1/bmc/42/boot-device')).toBe(2);
    });
  });

  it('shows the invalid boot device refusal', async () => {
    stubControlPlane({
      ...baseRoutes(),
      [BOOT_POST]: refused(400, 'bmc: invalid boot device: none'),
    });
    renderCard();
    await waitForFirstRead();

    fireEvent.change(screen.getByLabelText('Boot device'), { target: { value: 'none' } });
    await click('Set boot device');

    const toast = await screen.findByText('Set boot device failed: bmc: invalid boot device: none');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });

  it('mounts a trimmed ISO URL', async () => {
    const sent = stubControlPlane({
      ...baseRoutes(),
      [MEDIA_POST]: ok({ status: 'ok', iso_url: 'https://images.example/os.iso' }),
    });
    renderCard();
    await waitForFirstRead();
    await waitFor(() => {
      expect(screen.getByTestId('bmc-media-status').textContent).toContain('No image mounted');
    });

    expect((screen.getByRole('button', { name: 'Mount ISO' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('ISO URL'), { target: { value: ' https://images.example/os.iso ' } });
    await click('Mount ISO');

    const toast = await screen.findByText('ISO mounted: https://images.example/os.iso');
    expect(toast.getAttribute('data-variant')).toBe('success');
    const post = sent.find((r) => r.method === 'POST' && r.path === '/api/v1/bmc/42/virtual-media');
    expect(post?.body).toEqual({ iso_url: 'https://images.example/os.iso' });
    await waitFor(() => {
      expect(count(sent, 'GET', '/api/v1/bmc/42/virtual-media')).toBe(2);
    });
  });

  it('asks before unmounting and sends nothing on Cancel', async () => {
    const sent = stubControlPlane({ ...baseRoutes(), [MEDIA_GET]: MOUNTED });
    renderCard();

    await waitFor(() => {
      expect(screen.getByTestId('bmc-media-status').textContent).toContain(
        'Mounted: https://images.example/os.iso'
      );
    });
    await click('Unmount');
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Unmount the virtual media?');
    await click('Cancel');

    expect(count(sent, 'DELETE', '/api/v1/bmc/42/virtual-media')).toBe(0);
  });

  it('unmounts after the confirm', async () => {
    const sent = stubControlPlane({
      ...baseRoutes(),
      [MEDIA_GET]: MOUNTED,
      [MEDIA_DELETE]: ok({ status: 'ok' }),
    });
    renderCard();

    await waitFor(() => {
      expect(screen.getByTestId('bmc-media-status').textContent).toContain(
        'Mounted: https://images.example/os.iso'
      );
    });
    await click('Unmount');
    await screen.findByRole('dialog');
    await click('Confirm');

    const toast = await screen.findByText('ISO unmounted: BMC profile 42');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(count(sent, 'DELETE', '/api/v1/bmc/42/virtual-media')).toBe(1);
  });

  it('shows an unknown profile on the first read', async () => {
    stubControlPlane({
      [BOOT_GET]: refused(404, 'bmc: profile 42 not found'),
      [MEDIA_GET]: refused(404, 'bmc: profile 42 not found'),
    });
    renderCard();

    const boot = await screen.findByText('Boot device unavailable: bmc: profile 42 not found');
    expect(boot.getAttribute('data-variant')).toBe('destructive');
    const media = await screen.findByText('Virtual media unavailable: bmc: profile 42 not found');
    expect(media.getAttribute('data-variant')).toBe('destructive');
    expect(screen.getByTestId('bmc-boot-current').textContent).toContain('unknown');
  });
});
