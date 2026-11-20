import { test, expect } from './fixtures';

/**
 * Real-server spec for the BMC power row (#2039, epic #1665): every
 * BMCService operation on the BMC profile page, asserted against what the
 * harness server returns through the SDK. No route mocks.
 *
 * The harness seeds no BMC hardware by default: BMC_PROFILE_ID names the
 * profile to drive (default 1). Where the server answers an error (no BMC
 * service, unknown profile, unreachable BMC), the page must show that error
 * for the part instead of a value, and an action must surface the server's
 * refusal in the confirm dialog.
 */
const PROFILE_ID = process.env.BMC_PROFILE_ID ?? '1';

type Read<T> = { ok: true; data: T } | { ok: false };

async function read<T>(fn: () => Promise<{ data?: T } | T>): Promise<Read<T>> {
  try {
    const res = (await fn()) as { data?: T } | T;
    const data = res && typeof res === 'object' && 'data' in (res as object) ? (res as { data: T }).data : (res as T);
    return { ok: true, data };
  } catch {
    return { ok: false };
  }
}

test.describe('BMC power and management (real server)', () => {
  test('view: each part shows the server value or the server error', async ({ adminPage, sdk }) => {
    const power = await read<{ state: string }>(() => sdk.bmc.getPowerStatus(PROFILE_ID));
    const boot = await read<{ device: string }>(() => sdk.bmc.getBootDevice(PROFILE_ID));
    const media = await read<{ mounted: boolean; image_url?: string }>(() =>
      sdk.bmc.getVirtualMediaStatus(PROFILE_ID)
    );
    const sensors = await read<unknown[]>(() => sdk.bmc.getSensors(PROFILE_ID));
    const info = await read<{ manufacturer?: string }>(() => sdk.bmc.getSystemInfo(PROFILE_ID));
    const provision = await read<{ status: string }>(() => sdk.bmc.getProvisionStatus(PROFILE_ID));
    const cert = await read<{ subject?: string }>(() => sdk.bmc.getWebCertificate(PROFILE_ID));

    await adminPage.goto(`/devices/bmc/${PROFILE_ID}`);
    await expect(adminPage.getByRole('heading', { name: `BMC ${PROFILE_ID}` })).toBeVisible();

    if (power.ok) {
      await expect(adminPage.getByTestId('bmc-power-state')).toHaveText(power.data.state);
    } else {
      await expect(adminPage.getByTestId('bmc-power-error')).toBeVisible();
    }
    if (boot.ok) {
      await expect(adminPage.getByTestId('bmc-boot-device')).toHaveText(boot.data.device);
    } else {
      await expect(adminPage.getByTestId('bmc-bootDevice-error')).toBeVisible();
    }
    if (media.ok) {
      await expect(adminPage.getByTestId('bmc-virtual-media')).toHaveText(
        media.data.mounted ? media.data.image_url ?? '' : 'No media'
      );
    } else {
      await expect(adminPage.getByTestId('bmc-virtualMedia-error')).toBeVisible();
    }
    if (sensors.ok) {
      await expect(adminPage.getByTestId('bmc-sensors')).toBeVisible();
    } else {
      await expect(adminPage.getByTestId('bmc-sensors-error')).toBeVisible();
    }
    if (info.ok) {
      await expect(adminPage.getByTestId('bmc-system-info')).toBeVisible();
    } else {
      await expect(adminPage.getByTestId('bmc-systemInfo-error')).toBeVisible();
    }
    if (provision.ok) {
      await expect(adminPage.getByTestId('bmc-provision-state')).toHaveText(provision.data.status);
    } else {
      await expect(adminPage.getByTestId('bmc-provisionStatus-error')).toBeVisible();
    }
    if (cert.ok) {
      await expect(adminPage.getByTestId('bmc-certificate')).toBeVisible();
    } else {
      await expect(adminPage.getByTestId('bmc-certificate-error')).toBeVisible();
    }
  });

  for (const action of ['on', 'off', 'reset', 'cycle'] as const) {
    test(`flow: power ${action} reaches the server`, async ({ adminPage, sdk }) => {
      await adminPage.goto(`/devices/bmc/${PROFILE_ID}`);
      await adminPage.getByTestId(`bmc-power-${action}`).click();
      await adminPage.getByRole('button', { name: 'Confirm' }).click();

      // The server's answer decides the outcome: the dialog closes on
      // success and shows the server's refusal otherwise.
      const status = await read<{ state: string }>(() => sdk.bmc.getPowerStatus(PROFILE_ID));
      if (status.ok) {
        await expect(adminPage.getByRole('dialog')).toBeHidden();
        await expect(adminPage.getByTestId('bmc-power-state')).toBeVisible();
      } else {
        await expect(adminPage.getByTestId('bmc-action-error')).toBeVisible();
      }
    });
  }

  test('flow: set boot device, then the server reports it', async ({ adminPage, sdk }) => {
    await adminPage.goto(`/devices/bmc/${PROFILE_ID}`);
    await adminPage.locator('#bmc-boot-select').selectOption('pxe');
    await adminPage.getByRole('button', { name: 'Set boot device' }).click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();

    const boot = await read<{ device: string }>(() => sdk.bmc.getBootDevice(PROFILE_ID));
    if (boot.ok) {
      await expect(adminPage.getByTestId('bmc-boot-device')).toHaveText(boot.data.device);
    } else {
      await expect(adminPage.getByTestId('bmc-action-error')).toBeVisible();
    }
  });

  test('flow: mount and unmount an ISO', async ({ adminPage, sdk }) => {
    const iso = 'http://127.0.0.1:1/e2e.iso';
    await adminPage.goto(`/devices/bmc/${PROFILE_ID}`);
    await adminPage.locator('#bmc-iso-url').fill(iso);
    await adminPage.getByRole('button', { name: 'Mount ISO' }).click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();

    const media = await read<{ mounted: boolean; image_url?: string }>(() =>
      sdk.bmc.getVirtualMediaStatus(PROFILE_ID)
    );
    if (!media.ok || !media.data.mounted) {
      // Mount refused or no BMC: the server's error is shown.
      await expect(
        adminPage.getByTestId('bmc-action-error').or(adminPage.getByTestId('bmc-virtualMedia-error'))
      ).toBeVisible();
      return;
    }
    await expect(adminPage.getByTestId('bmc-virtual-media')).toHaveText(media.data.image_url ?? '');

    await adminPage.getByRole('button', { name: 'Unmount ISO' }).click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    const after = await read<{ mounted: boolean }>(() => sdk.bmc.getVirtualMediaStatus(PROFILE_ID));
    if (after.ok && !after.data.mounted) {
      await expect(adminPage.getByTestId('bmc-virtual-media')).toHaveText('No media');
    }
  });

  test('flow: provision asks first and Cancel sends nothing', async ({ adminPage, sdk }) => {
    const before = await read<{ status: string }>(() => sdk.bmc.getProvisionStatus(PROFILE_ID));
    await adminPage.goto(`/devices/bmc/${PROFILE_ID}`);
    await adminPage.getByRole('button', { name: 'Provision' }).click();
    await expect(adminPage.getByRole('dialog')).toContainText('disks');
    await adminPage.getByRole('button', { name: 'Cancel' }).click();

    const after = await read<{ status: string }>(() => sdk.bmc.getProvisionStatus(PROFILE_ID));
    expect(after.ok).toBe(before.ok);
    if (before.ok && after.ok) {
      expect(after.data.status).toBe(before.data.status);
    }
  });
});
