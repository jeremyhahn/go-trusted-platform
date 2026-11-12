import { test } from '@playwright/test';

/**
 * TPM key lifecycle page (#1735, slice 31 of #1665): provision, clear,
 * capabilities, platform attributes, EK/SRK/AK and quote operations.
 */
test.describe('TPM Keys operations', () => {
  test.fixme('Provision posts to /tpm/provision', async () => {});
  test.fixme('Clear asks for confirmation and posts to /tpm/clear', async () => {});
  test.fixme('GetCapabilities shows /tpm/capabilities', async () => {});
  test.fixme('GetPlatformAttributes shows /tpm/platform', async () => {});
  test.fixme('CreateEK posts to /tpm/ek', async () => {});
  test.fixme('ImportEKCertificate posts to /tpm/ek/certificate', async () => {});
  test.fixme('DeleteEK asks for confirmation and deletes /tpm/ek', async () => {});
  test.fixme('CreateSRK posts to /tpm/srk', async () => {});
  test.fixme('DeleteSRK asks for confirmation and deletes /tpm/srk', async () => {});
  test.fixme('CreateAK posts to /tpm/ak', async () => {});
  test.fixme('GetAK shows /tpm/ak', async () => {});
  test.fixme('DeleteAK asks for confirmation and deletes /tpm/ak', async () => {});
  test.fixme('Quote posts to /tpm/quote', async () => {});
  test.fixme('VerifyQuote posts to /tpm/quote/verify', async () => {});
  test.fixme('Certify posts to /tpm/certify', async () => {});
});
