import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import {
  BMC_BOOT_DEVICES,
  bmcBootDeviceLabel,
  bmcPath,
  isBMCBootDevice,
  useBMCBootMedia,
} from './use-bmc-boot-media';

// #2039: the BMC boot-media hook drives SetBootDevice, GetBootDevice,
// MountISO, UnmountISO and VirtualMediaStatus through the SDK API client on
// /api/v1/bmc/{profileID}/boot-device and /virtual-media
// (pkg/webservice/v1/bmc/handler.go).

function renderBootMedia(profileID = '42') {
  return renderHook(() => useBMCBootMedia(profileID), {
    wrapper: ({ children }) => withControlPlane(children),
  });
}

describe('useBMCBootMedia', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads the boot device', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/bmc/42/boot-device': ok({ device: 'pxe' }) });
    const { result } = renderBootMedia();
    let res: Awaited<ReturnType<typeof result.current.getBootDevice>> | undefined;
    await act(async () => {
      res = await result.current.getBootDevice();
    });
    expect(res?.data).toEqual({ device: 'pxe' });
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/bmc/42/boot-device', body: undefined }]);
  });

  it('sets a one-shot and a persistent boot device', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/bmc/42/boot-device': ok({ status: 'ok', device: 'disk' }),
    });
    const { result } = renderBootMedia();
    let first: Awaited<ReturnType<typeof result.current.setBootDevice>> | undefined;
    await act(async () => {
      first = await result.current.setBootDevice('disk');
    });
    await act(async () => {
      await result.current.setBootDevice('cdrom', true);
    });
    expect(sent.map((s) => s.body)).toEqual([
      { device: 'disk', persistent: false },
      { device: 'cdrom', persistent: true },
    ]);
    expect(first?.data?.status).toBe('ok');
  });

  it('surfaces the invalid boot device refusal', async () => {
    stubControlPlane({
      'POST /api/v1/bmc/42/boot-device': refused(400, 'bmc: invalid boot device: floppy'),
    });
    const { result } = renderBootMedia();
    let res: Awaited<ReturnType<typeof result.current.setBootDevice>> | undefined;
    await act(async () => {
      res = await result.current.setBootDevice('pxe');
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(400);
    expect(res?.error?.message).toBe('bmc: invalid boot device: floppy');
  });

  it('mounts and unmounts an ISO', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/bmc/42/virtual-media': ok({ status: 'ok', iso_url: 'https://images.test/os.iso' }),
      'DELETE /api/v1/bmc/42/virtual-media': ok({ status: 'ok' }),
    });
    const { result } = renderBootMedia();
    let mounted: Awaited<ReturnType<typeof result.current.mountISO>> | undefined;
    await act(async () => {
      mounted = await result.current.mountISO(' https://images.test/os.iso ');
    });
    expect(sent[0]?.body).toEqual({ iso_url: 'https://images.test/os.iso' });
    expect(mounted?.data?.iso_url).toBe('https://images.test/os.iso');

    let unmounted: Awaited<ReturnType<typeof result.current.unmountISO>> | undefined;
    await act(async () => {
      unmounted = await result.current.unmountISO();
    });
    expect(unmounted?.success).toBe(true);
    expect(sent[1]).toMatchObject({ method: 'DELETE', path: '/api/v1/bmc/42/virtual-media' });
  });

  it('reads the virtual media status', async () => {
    stubControlPlane({
      'GET /api/v1/bmc/42/virtual-media': ok({
        mounted: true,
        image_url: 'https://images.test/os.iso',
        media_type: 'iso',
      }),
    });
    const { result } = renderBootMedia();
    let res: Awaited<ReturnType<typeof result.current.getVirtualMedia>> | undefined;
    await act(async () => {
      res = await result.current.getVirtualMedia();
    });
    expect(res?.data?.mounted).toBe(true);
    expect(res?.data?.media_type).toBe('iso');
  });

  it('surfaces an unknown profile', async () => {
    stubControlPlane({
      'GET /api/v1/bmc/42/virtual-media': refused(404, 'bmc: profile 42 not found'),
    });
    const { result } = renderBootMedia();
    let res: Awaited<ReturnType<typeof result.current.getVirtualMedia>> | undefined;
    await act(async () => {
      res = await result.current.getVirtualMedia();
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(404);
    expect(res?.error?.message).toContain('not found');
  });

  it('knows the boot devices and escapes the profile id', () => {
    expect(BMC_BOOT_DEVICES).toEqual(['pxe', 'disk', 'cdrom', 'virtual_media', 'none']);
    expect(isBMCBootDevice('virtual_media')).toBe(true);
    expect(isBMCBootDevice('floppy')).toBe(false);
    expect(bmcBootDeviceLabel('cdrom')).toBe('CD-ROM');
    expect(bmcBootDeviceLabel('virtual_media')).toBe('Virtual media');
    expect(bmcPath('7', 'boot-device')).toBe('/v1/bmc/7/boot-device');
    expect(bmcPath('a/b', 'virtual-media')).toBe('/v1/bmc/a%2Fb/virtual-media');
  });
});
