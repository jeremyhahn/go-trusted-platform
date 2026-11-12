import { describe, expect, it } from 'vitest';

import { appEditConstraint } from './app-detail-client';

// Codex round 4 (#1740): the backend keeps an app's redirect URIs or grant
// types when an update sends an empty list (the SDK omits empty slices and
// UpdateApp only replaces non-empty lists), so the editor must refuse to
// clear either list instead of reporting a success that changed nothing.
describe('appEditConstraint', () => {
  it('accepts a name with redirect URIs and grant types', () => {
    expect(appEditConstraint('Billing', ['app://cb'], ['authorization_code'])).toBeNull();
  });

  it('refuses an empty redirect URI list', () => {
    expect(appEditConstraint('Billing', [], ['authorization_code'])).toBe(
      'At least one redirect URI is required; the server cannot clear the list.',
    );
  });

  it('refuses an empty grant type list', () => {
    expect(appEditConstraint('Billing', ['app://cb'], [])).toBe(
      'At least one grant type is required; the server cannot clear the list.',
    );
  });

  it('refuses an empty name', () => {
    expect(appEditConstraint('', ['app://cb'], ['authorization_code'])).toBe('A name is required.');
  });
});
