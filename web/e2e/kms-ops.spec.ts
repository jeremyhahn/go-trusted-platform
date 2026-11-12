import { test } from '@playwright/test';

/**
 * KMS crypto operations page (#1734, slice 20 of #1665).
 * Every REST operation of the slice is reachable from /kms/operations.
 */
test.describe('KMS crypto operations', () => {
  test.fixme('ImportKey imports key material', async () => {});
  test.fixme('UpdateKeyStatus disables a key behind a confirm dialog', async () => {});
  test.fixme('GetKeyVersions lists the versions of a key', async () => {});
  test.fixme('BatchEncrypt encrypts several plaintexts', async () => {});
  test.fixme('BatchDecrypt decrypts several ciphertexts', async () => {});
  test.fixme('Hash digests data', async () => {});
  test.fixme('HMAC computes a MAC', async () => {});
  test.fixme('VerifyHMAC verifies a MAC', async () => {});
  test.fixme('GenerateRandom returns random bytes', async () => {});
  test.fixme('GenerateDataKey returns a data key', async () => {});
  test.fixme('GenerateWrappedDataKey returns a wrapped data key', async () => {});
  test.fixme('BackendStatus shows the backend status', async () => {});
});
