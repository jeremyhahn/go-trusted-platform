import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TokenOperationsCard, tokenRouteReason } from './token-operations-card';

describe('TokenOperationsCard', () => {
  it('gates CreateToken, VerifyToken and RevokeToken off with the missing-route reason', () => {
    render(<TokenOperationsCard />);
    for (const [name, op] of [
      ['Create token', 'CreateToken'],
      ['Verify token', 'VerifyToken'],
      ['Revoke token', 'RevokeToken'],
    ] as const) {
      const button = screen.getByRole('button', { name }) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      expect(button.getAttribute('title')).toBe(tokenRouteReason(op));
    }
  });

  it('names the operation in the reason', () => {
    expect(tokenRouteReason('CreateToken')).toMatch(/^Not available: .*CreateToken/);
  });
});
