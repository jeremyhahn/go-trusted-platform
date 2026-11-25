import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';

/**
 * IAM roles and users list gates against the real platformd (#2033, epic #1665).
 *
 * Each page reads the capabilities from the daemon itself. When the list op
 * is off, the page shows a not-enabled card with the daemon's reason and does
 * not list; when it is on, the Add button carries the create op's answer.
 * The spec only reads: it never clicks a control and makes no write call.
 */

interface CapabilityEntry {
  op: string;
  enabled: boolean;
  reason?: string;
}

async function capabilityList(sdk: PlatformClient): Promise<CapabilityEntry[]> {
  const res = await sdk.capabilities.list();
  expect(res.success, `capabilities.list: ${JSON.stringify(res.error)}`).toBeTruthy();
  return res.data?.capabilities ?? [];
}

function entry(caps: CapabilityEntry[], op: string): CapabilityEntry {
  const found = caps.find((c) => c.op === op);
  expect(found, `the capabilities list has no entry for ${op}`).toBeDefined();
  return found!;
}

const IAM_LISTS = [
  {
    path: '/iam/roles',
    listOp: 'GET /api/v1/iam/tenants/{tenant}/roles',
    createOp: 'POST /api/v1/iam/tenants/{tenant}/roles',
    card: 'roles-not-enabled',
    add: 'Add Role',
  },
  {
    path: '/iam/users',
    listOp: 'GET /api/v1/iam/tenants/{tenant}/users',
    createOp: 'POST /api/v1/iam/tenants/{tenant}/users',
    card: 'users-not-enabled',
    add: 'Add User',
  },
];

test.describe('IAM list gates against the real platformd', () => {
  for (const page of IAM_LISTS) {
    test(`${page.path} follows the server's answer for its list and create ops`, async ({
      adminPage,
      sdk,
    }) => {
      const caps = await capabilityList(sdk);
      const list = entry(caps, page.listOp);

      await adminPage.goto(page.path);
      if (!list.enabled) {
        const card = adminPage.getByTestId(page.card);
        await expect(card).toBeVisible();
        if (list.reason) {
          await expect(card).toContainText(list.reason);
        }
        return;
      }

      const create = entry(caps, page.createOp);
      const add = adminPage.getByRole('button', { name: page.add, exact: true });
      await expect(add).toHaveAttribute('data-capability-op', page.createOp);
      await expect(add).toHaveAttribute('data-capability-enabled', String(create.enabled));
    });
  }
});
