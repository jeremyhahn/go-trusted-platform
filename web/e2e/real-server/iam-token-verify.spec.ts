/**
 * Real-server checks of the Verify a token card on /iam/tokens (#2053): the
 * card sends the pasted token through `sdk.iam.verifyToken`
 * (POST /api/v1/iam/tokens/verify) and shows the server's verdict, and its
 * Verify button carries the server's capability answer for that op.
 */
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

const verifyOp = 'POST /api/v1/iam/tokens/verify';

/** The server's capability answer for the verify op. */
async function verifyOffered(sdk: PlatformClient): Promise<boolean> {
  const res = await sdk.capabilities.list();
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  const caps = res.data?.capabilities ?? [];
  return caps.find((c) => c.op === verifyOp)?.enabled ?? false;
}

test.describe('IAM token verify (real server)', () => {
  test('a malformed token is reported invalid', async ({ adminPage, sdk }) => {
    const res = await sdk.iam.verifyToken({ token: 'not-a-token' });
    await adminPage.goto('/iam/tokens');
    const verify = adminPage.getByRole('button', { name: /^Verify$/ });
    if (!res.success) {
      // The server refuses the op: the card must not offer it.
      await expect(verify).toHaveAttribute('data-capability-op', verifyOp);
      await expect(verify).toHaveAttribute('data-capability-enabled', 'false');
      await expect(verify).toBeDisabled();
      return;
    }
    expect(res.data?.valid).toBe(false);

    await adminPage.getByLabel('Token').fill('not-a-token');
    await verify.click();
    await expect(adminPage.getByText('Invalid', { exact: true })).toBeVisible();
  });

  test("the Verify button carries the server's capability answer", async ({ adminPage, sdk }) => {
    const offered = await verifyOffered(sdk);
    await adminPage.goto('/iam/tokens');
    const verify = adminPage.getByRole('button', { name: /^Verify$/ });
    await expect(verify).toHaveAttribute('data-capability-op', verifyOp);
    await expect(verify).toHaveAttribute('data-capability-enabled', String(offered));
  });
});
