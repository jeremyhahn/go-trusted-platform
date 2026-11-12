import { test } from '@playwright/test';

// Tenant lifecycle, quotas, sync and tenant DEK rotation (#1758, slice 30 of #1665).
test.describe('Tenant lifecycle', () => {
  test.fixme('GetTenantByName looks a tenant up by name', async () => {});
  test.fixme('UpdateTenant saves the display name', async () => {});
  test.fixme('DeleteTenant asks for confirmation first', async () => {});
  test.fixme('SuspendTenant asks for confirmation first', async () => {});
  test.fixme('ResumeTenant resumes a suspended tenant', async () => {});
  test.fixme('UpdateQuotas saves new quota limits', async () => {});
  test.fixme('CheckQuota reports whether a request fits', async () => {});
  test.fixme('Sync triggers a tenant sync', async () => {});
  test.fixme('RotateTenantDEK asks for confirmation first', async () => {});
  test.fixme('GetTenantDEKStatus shows the DEK version', async () => {});
});
