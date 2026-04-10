import { Page } from '@playwright/test';

/**
 * Mock WebAuthn API for CI testing
 * This provides a fake implementation of the WebAuthn API that simulates
 * successful credential creation and authentication without requiring
 * actual biometric hardware or authenticators.
 */

export interface WebAuthnMockOptions {
  userHandle?: string;
  credentialId?: string;
  publicKey?: string;
}

/**
 * Install WebAuthn mocks in the browser context.
 * This should be called before navigating to pages that use WebAuthn.
 *
 * @param page - Playwright page object
 * @param options - Configuration options for the mock
 */
export async function mockWebAuthn(
  page: Page,
  options: WebAuthnMockOptions = {}
) {
  const {
    userHandle = 'mock-user-handle',
    credentialId = 'mock-credential-id',
    publicKey = 'mock-public-key',
  } = options;

  await page.addInitScript((opts) => {
    // Mock credential creation
    if (!window.PublicKeyCredential) {
      (window as any).PublicKeyCredential = class {
        static isUserVerifyingPlatformAuthenticatorAvailable() {
          return Promise.resolve(true);
        }
        static isConditionalMediationAvailable() {
          return Promise.resolve(true);
        }
      };
    }

    // Mock navigator.credentials.create
    const originalCreate = navigator.credentials.create;
    navigator.credentials.create = async function (options: any) {
      if (options.publicKey) {
        // Return a mock credential
        return {
          id: opts.credentialId,
          rawId: new TextEncoder().encode(opts.credentialId).buffer,
          type: 'public-key',
          response: {
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.create',
              challenge: btoa('mock-challenge'),
              origin: window.location.origin,
            })).buffer,
            attestationObject: new TextEncoder().encode('mock-attestation').buffer,
            getTransports: () => ['internal'],
            getAuthenticatorData: () => new Uint8Array(0).buffer,
            getPublicKey: () => new TextEncoder().encode(opts.publicKey).buffer,
            getPublicKeyAlgorithm: () => -7,
          },
          getClientExtensionResults: () => ({}),
        };
      }
      return originalCreate.call(this, options);
    };

    // Mock navigator.credentials.get
    const originalGet = navigator.credentials.get;
    navigator.credentials.get = async function (options: any) {
      if (options.publicKey) {
        // Return a mock credential
        return {
          id: opts.credentialId,
          rawId: new TextEncoder().encode(opts.credentialId).buffer,
          type: 'public-key',
          response: {
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.get',
              challenge: btoa('mock-challenge'),
              origin: window.location.origin,
            })).buffer,
            authenticatorData: new Uint8Array([1, 2, 3, 4]).buffer,
            signature: new Uint8Array([5, 6, 7, 8]).buffer,
            userHandle: new TextEncoder().encode(opts.userHandle).buffer,
          },
          getClientExtensionResults: () => ({}),
        };
      }
      return originalGet.call(this, options);
    };
  }, { userHandle, credentialId, publicKey });
}

/**
 * Reset WebAuthn mocks (useful between tests)
 *
 * @param page - Playwright page object
 */
export async function resetWebAuthnMock(page: Page) {
  await page.evaluate(() => {
    // Reload to clear any mocks
    location.reload();
  });
}
