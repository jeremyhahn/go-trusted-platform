import { test } from '@playwright/test';

/**
 * TPM operations e2e (slice 32 of #1665, issue #1725): GetEventLog,
 * ExtendPCR, MakeCredential, ActivateCredential and GetRandom.
 */
test.describe('TPM operations', () => {
  test.fixme('GetEventLog: event log page lists events', async () => {});
  test.fixme('ExtendPCR: PCRs page extends a PCR', async () => {});
  test.fixme('MakeCredential: credential page makes a credential', async () => {});
  test.fixme('ActivateCredential: credential page activates after confirm', async () => {});
  test.fixme('GetRandom: credential page returns random bytes', async () => {});
});
