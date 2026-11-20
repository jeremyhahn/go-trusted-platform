/**
 * Real-server spec for the DNS operations (row #2060, epic #1665).
 *
 * Every test seeds its zone through the SDK client from the harness, drives
 * the dashboard as the seeded admin, then reads the result back from the
 * server through the SDK. No route mocks.
 */
import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';

function uniqueZone(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}.e2e.test`;
}

async function seedZone(sdk: PlatformClient, name: string, ttl = 3600): Promise<void> {
  const res = await sdk.dns.createZone({ name, ttl, description: 'seeded by dns.spec.ts' });
  expect(res.success, JSON.stringify(res.error)).toBe(true);
}

async function dropZone(sdk: PlatformClient, name: string): Promise<void> {
  await sdk.dns.deleteZone(name).catch(() => undefined);
}

async function aRecordsOf(sdk: PlatformClient, zone: string) {
  const res = await sdk.dns.listRecords({ zoneName: zone, type: 'A' });
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  return (res.data?.records ?? []).map((r) => r.a).filter((a) => a !== undefined);
}

function zonePath(zone: string): string {
  return `/networking/dns/${encodeURIComponent(zone)}`;
}

test.describe('DNS zone detail (real server)', () => {
  test('GetZone: the detail page shows the zone the server returns', async ({ adminPage, sdk }) => {
    const zone = uniqueZone('get');
    await seedZone(sdk, zone, 1800);
    try {
      const got = await sdk.dns.getZone(zone);
      expect(got.success).toBe(true);
      await adminPage.goto(zonePath(zone));
      await expect(adminPage.getByRole('heading', { name: zone })).toBeVisible();
      await expect(adminPage.getByTestId('dns-zone-ttl')).toHaveValue(String(got.data?.zone.ttl));
    } finally {
      await dropZone(sdk, zone);
    }
  });

  test('UpdateZone: saving zone settings changes TTL and description on the server', async ({ adminPage, sdk }) => {
    const zone = uniqueZone('upd');
    await seedZone(sdk, zone, 3600);
    try {
      await adminPage.goto(zonePath(zone));
      await adminPage.getByTestId('dns-zone-ttl').fill('7200');
      await adminPage.getByTestId('dns-zone-description').fill('updated by e2e');
      await adminPage.getByRole('button', { name: 'Save zone settings' }).click();
      await expect(adminPage.getByText('Zone updated')).toBeVisible();

      const got = await sdk.dns.getZone(zone);
      expect(got.data?.zone.ttl).toBe(7200);
      expect(got.data?.zone.description).toBe('updated by e2e');
    } finally {
      await dropZone(sdk, zone);
    }
  });

  test('AddRecord: an A record added in the page is stored on the server', async ({ adminPage, sdk }) => {
    const zone = uniqueZone('add');
    await seedZone(sdk, zone);
    try {
      await adminPage.goto(zonePath(zone));
      await adminPage.getByTestId('dns-record-add-type').selectOption('A');
      await adminPage.getByTestId('dns-record-add-name').fill('www');
      await adminPage.getByTestId('dns-record-add-value').fill('192.0.2.10');
      await adminPage.getByTestId('dns-record-add-ttl').fill('300');
      await adminPage.getByRole('button', { name: 'Add record' }).click();
      await expect(adminPage.getByText('Record added')).toBeVisible();

      const records = await aRecordsOf(sdk, zone);
      expect(records.some((a) => a?.value === '192.0.2.10' && a?.name.startsWith('www'))).toBe(true);
    } finally {
      await dropZone(sdk, zone);
    }
  });

  test('ListRecords: the records panel lists server records and filters by type', async ({ adminPage, sdk }) => {
    const zone = uniqueZone('list');
    await seedZone(sdk, zone);
    try {
      await sdk.dns.addRecord({ zoneName: zone, record: { type: 'A', a: { name: 'app', value: '192.0.2.20', ttl: 300 } } });
      await sdk.dns.addRecord({ zoneName: zone, record: { type: 'TXT', txt: { name: 'note', value: 'hello-e2e', ttl: 300 } } });

      await adminPage.goto(zonePath(zone));
      const list = adminPage.getByTestId('dns-records-list');
      await expect(list).toContainText('192.0.2.20');
      await expect(list).toContainText('hello-e2e');

      await adminPage.getByTestId('dns-records-type').selectOption('A');
      await expect(list).toContainText('192.0.2.20');
      await expect(list).not.toContainText('hello-e2e');

      const onlyA = await sdk.dns.listRecords({ zoneName: zone, type: 'A' });
      expect((onlyA.data?.records ?? []).every((r) => String(r.type).endsWith('A'))).toBe(true);
    } finally {
      await dropZone(sdk, zone);
    }
  });

  test('UpdateRecord: editing an A record replaces its value on the server', async ({ adminPage, sdk }) => {
    const zone = uniqueZone('edit');
    await seedZone(sdk, zone);
    try {
      await sdk.dns.addRecord({ zoneName: zone, record: { type: 'A', a: { name: 'api', value: '192.0.2.30', ttl: 300 } } });

      await adminPage.goto(zonePath(zone));
      const row = adminPage.getByTestId('dns-records-list').getByRole('row', { name: /192\.0\.2\.30/ });
      await row.getByRole('button', { name: 'Edit' }).click();
      await adminPage.getByTestId('dns-record-edit-value').fill('192.0.2.31');
      await adminPage.getByRole('button', { name: 'Save record' }).click();
      await expect(adminPage.getByText('Record updated')).toBeVisible();

      const values = (await aRecordsOf(sdk, zone)).map((a) => a?.value);
      expect(values).toContain('192.0.2.31');
      expect(values).not.toContain('192.0.2.30');
    } finally {
      await dropZone(sdk, zone);
    }
  });

  test('DeleteRecord: deleting an A record removes it from the server', async ({ adminPage, sdk }) => {
    const zone = uniqueZone('del');
    await seedZone(sdk, zone);
    try {
      await sdk.dns.addRecord({ zoneName: zone, record: { type: 'A', a: { name: 'old', value: '192.0.2.40', ttl: 300 } } });

      await adminPage.goto(zonePath(zone));
      const row = adminPage.getByTestId('dns-records-list').getByRole('row', { name: /192\.0\.2\.40/ });
      await row.getByRole('button', { name: 'Delete' }).click();
      await adminPage.getByRole('button', { name: 'Confirm delete' }).click();
      await expect(adminPage.getByText('Record deleted')).toBeVisible();

      const values = (await aRecordsOf(sdk, zone)).map((a) => a?.value);
      expect(values).not.toContain('192.0.2.40');
    } finally {
      await dropZone(sdk, zone);
    }
  });

  test('GetDNSSECStatus + SignZone: the DNSSEC card shows the status and signs the zone', async ({ adminPage, sdk }) => {
    const zone = uniqueZone('sec');
    await seedZone(sdk, zone);
    try {
      await adminPage.goto(zonePath(zone));
      const status = adminPage.getByTestId('dns-dnssec-status');
      await expect(status).toBeVisible();

      const before = await sdk.dns.getDNSSECStatus(zone);
      const sign = adminPage.getByRole('button', { name: 'Sign zone' });
      if (!before.success) {
        // The server has no DNSSEC signer configured: the control is gated off with the reason.
        await expect(sign).toBeDisabled();
        await expect(adminPage.getByTestId('dns-dnssec-reason')).toBeVisible();
        return;
      }
      await expect(status).toContainText(before.data?.status.zoneSigned ? 'Signed' : 'Unsigned');

      await sign.click();
      await expect(adminPage.getByText('Zone signed')).toBeVisible();
      const after = await sdk.dns.getDNSSECStatus(zone);
      expect(after.data?.status.zoneSigned).toBe(true);
      await expect(status).toContainText('Signed');
    } finally {
      await dropZone(sdk, zone);
    }
  });
});

test.describe('DNS register and resolve (real server)', () => {
  test('Register then Resolve: a registered name resolves to its IP', async ({ adminPage, sdk }) => {
    const zone = uniqueZone('reg');
    await seedZone(sdk, zone);
    const fqdn = `host1.${zone}`;
    try {
      await adminPage.goto('/networking/dns');
      await adminPage.getByTestId('dns-register-fqdn').fill(fqdn);
      await adminPage.getByTestId('dns-register-ip').fill('192.0.2.50');
      await adminPage.getByRole('button', { name: 'Register' }).click();
      await expect(adminPage.getByText('Name registered')).toBeVisible();

      const resolved = await sdk.dns.resolve({ fqdn, type: 'A' });
      expect(resolved.success, JSON.stringify(resolved.error)).toBe(true);
      expect((resolved.data?.records ?? []).some((r) => r.a?.value === '192.0.2.50')).toBe(true);

      await adminPage.getByTestId('dns-resolve-fqdn').fill(fqdn);
      await adminPage.getByTestId('dns-resolve-type').selectOption('A');
      await adminPage.getByRole('button', { name: 'Resolve' }).click();
      await expect(adminPage.getByTestId('dns-resolve-results')).toContainText('192.0.2.50');
    } finally {
      await dropZone(sdk, zone);
    }
  });
});
