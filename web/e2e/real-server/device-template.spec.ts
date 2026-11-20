/**
 * Real-server spec for the device-template row (#2049, epic #1665):
 * CreateTemplate, GetTemplate, UpdateTemplate, DeleteTemplate,
 * CreateProfileFromTemplate, FindConfigForDevice, AssignProfileToDevice and
 * UnassignProfileFromDevice. State is seeded through the SDK client against
 * the harness server, never through route mocks, and every assertion reads
 * what the server returns.
 */
import type { Page } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

interface Fixtures {
  adminPage: Page;
  sdk: PlatformClient;
}

/** A name no other spec run uses, so parallel runs never collide. */
function uniqueName(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
}

/** A locally administered MAC unique to this run. */
function uniqueMac(): string {
  const byte = () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
  return `02:${byte()}:${byte()}:${byte()}:${byte()}:${byte()}`;
}

async function seedTemplate(sdk: PlatformClient, name: string): Promise<string> {
  const res = await sdk.device.createTemplate({
    name,
    description: 'seeded by the real-server spec',
    role: 'gateway',
  });
  expect(res.data?.id).toBeTruthy();
  return String(res.data!.id);
}

async function seedProfile(sdk: PlatformClient, templateId: string, ekSerial: string, macAddress: string): Promise<string> {
  const res = await sdk.device.createProfileFromTemplate({
    templateId,
    overrides: { name: uniqueName('profile'), ek_serial: ekSerial, mac_address: macAddress },
  });
  expect(res.data?.id).toBeTruthy();
  return String(res.data!.id);
}

test.describe('device templates (real server)', () => {
  test('CreateTemplate: a template created in the dialog is stored by the server', async ({ adminPage, sdk }: Fixtures) => {
    const name = uniqueName('tmpl-create');
    await adminPage.goto('/devices/templates');
    await adminPage.getByRole('button', { name: /create template/i }).first().click();
    await adminPage.getByPlaceholder('e.g., Production Edge Gateway Template').fill(name);
    await adminPage.getByRole('dialog').getByRole('button', { name: /create/i }).last().click();
    await expect(adminPage.getByText(name)).toBeVisible();

    const list = await sdk.device.listTemplates();
    const names = (list.data ?? []).map((t) => t.name);
    expect(names).toContain(name);
  });

  test('GetTemplate: the detail page shows the template the server returns', async ({ adminPage, sdk }: Fixtures) => {
    const name = uniqueName('tmpl-get');
    const id = await seedTemplate(sdk, name);
    const got = await sdk.device.getTemplate(id);
    expect(got.data?.name).toBe(name);

    await adminPage.goto(`/devices/templates/${id}`);
    await expect(adminPage.getByText(name).first()).toBeVisible();
  });

  test('UpdateTemplate: a renamed template reads back renamed', async ({ adminPage, sdk }: Fixtures) => {
    const id = await seedTemplate(sdk, uniqueName('tmpl-upd'));
    const renamed = uniqueName('tmpl-renamed');
    await sdk.device.updateTemplate({ id, name: renamed, role: 'gateway' });

    const got = await sdk.device.getTemplate(id);
    expect(got.data?.name).toBe(renamed);
    await adminPage.goto(`/devices/templates/${id}`);
    await expect(adminPage.getByText(renamed).first()).toBeVisible();
  });

  test('DeleteTemplate: deleting from the detail page removes it on the server', async ({ adminPage, sdk }: Fixtures) => {
    const name = uniqueName('tmpl-del');
    const id = await seedTemplate(sdk, name);

    await adminPage.goto(`/devices/templates/${id}`);
    await adminPage.getByRole('button', { name: /delete/i }).first().click();
    await adminPage.getByRole('dialog').getByRole('button', { name: /delete/i }).last().click();
    await expect(adminPage).toHaveURL(/\/devices\/templates\/?$/);

    const list = await sdk.device.listTemplates();
    expect((list.data ?? []).map((t) => String(t.id))).not.toContain(id);
  });

  test('CreateProfileFromTemplate: the create-profile page makes a profile from the template', async ({ adminPage, sdk }: Fixtures) => {
    const id = await seedTemplate(sdk, uniqueName('tmpl-prof'));
    await adminPage.goto(`/devices/templates/${id}/create-profile`);
    await expect(adminPage.getByRole('heading').first()).toBeVisible();

    const ek = uniqueName('ek');
    const profileId = await seedProfile(sdk, id, ek, uniqueMac());
    // The new profile carries the template's binding for this EK serial.
    const found = await sdk.device.findConfigForDevice({ ekSerial: ek });
    expect(String(found.data?.id)).toBe(profileId);
  });
});

test.describe('profile assignment panel (real server)', () => {
  test('FindConfigForDevice: Find Config shows the profile the server matches', async ({ adminPage, sdk }: Fixtures) => {
    const templateId = await seedTemplate(sdk, uniqueName('tmpl-find'));
    const ek = uniqueName('ek-find');
    const mac = uniqueMac();
    const profileId = await seedProfile(sdk, templateId, ek, mac);

    const server = await sdk.device.findConfigForDevice({ ekSerial: ek, macAddress: mac });
    expect(String(server.data?.id)).toBe(profileId);

    await adminPage.goto('/devices/templates');
    const panel = adminPage.getByTestId('profile-assignment');
    await panel.getByLabel('EK Serial Number').fill(ek);
    await panel.getByLabel('MAC Address').fill(mac);
    await panel.getByRole('button', { name: 'Find Config' }).click();
    await expect(panel.getByTestId('find-config-result')).toContainText(`ID ${profileId}`);
    await expect(panel.getByLabel('Profile ID')).toHaveValue(profileId);
  });

  test('FindConfigForDevice: an unknown device shows no match', async ({ adminPage }: Fixtures) => {
    await adminPage.goto('/devices/templates');
    const panel = adminPage.getByTestId('profile-assignment');
    await panel.getByLabel('EK Serial Number').fill(uniqueName('ek-none'));
    await panel.getByRole('button', { name: 'Find Config' }).click();
    await expect(panel.getByTestId('find-config-result')).toHaveText('No profile matches this device');
  });

  test('AssignProfileToDevice and UnassignProfileFromDevice: the binding round-trips on the server', async ({ adminPage, sdk }: Fixtures) => {
    const templateId = await seedTemplate(sdk, uniqueName('tmpl-assign'));
    const profileId = await seedProfile(sdk, templateId, uniqueName('ek-seed'), uniqueMac());
    const ek = uniqueName('ek-assign');
    const mac = uniqueMac();

    await adminPage.goto('/devices/templates');
    const panel = adminPage.getByTestId('profile-assignment');
    await panel.getByLabel('EK Serial Number').fill(ek);
    await panel.getByLabel('MAC Address').fill(mac);
    await panel.getByLabel('Profile ID').fill(profileId);
    await panel.getByRole('button', { name: 'Assign Profile' }).click();
    await expect(adminPage.getByText('Profile assigned').first()).toBeVisible();

    const bound = await sdk.device.findConfigForDevice({ ekSerial: ek });
    expect(String(bound.data?.id)).toBe(profileId);

    await panel.getByRole('button', { name: 'Unassign Profile' }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Unassign' }).click();
    await expect(adminPage.getByText('Profile unassigned').first()).toBeVisible();

    await expect(sdk.device.findConfigForDevice({ ekSerial: ek })).rejects.toMatchObject({ status: 404 });
  });
});
