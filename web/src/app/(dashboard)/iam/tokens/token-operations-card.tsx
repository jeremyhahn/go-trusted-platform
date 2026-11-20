'use client';

import { KeyRound, ShieldCheck, ShieldOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export type TokenOperation = 'CreateToken' | 'VerifyToken' | 'RevokeToken';

/**
 * PlatformIAMService.CreateToken, VerifyToken and RevokeToken have no REST
 * route in pkg/webservice/v1 (the SDK's /auth/token, /auth/token/verify and
 * /auth/token/revoke are not served), so their controls stay gated off
 * (#2053).
 */
export function tokenRouteReason(op: TokenOperation): string {
  return `Not available: the server has no REST route for PlatformIAMService.${op} yet`;
}

const OPERATIONS: { op: TokenOperation; label: string; icon: typeof KeyRound }[] = [
  { op: 'CreateToken', label: 'Create token', icon: KeyRound },
  { op: 'VerifyToken', label: 'Verify token', icon: ShieldCheck },
  { op: 'RevokeToken', label: 'Revoke token', icon: ShieldOff },
];

/** IAM access-token operations, each gated off with its reason. */
export function TokenOperationsCard() {
  return (
    <Card data-testid="token-operations">
      <CardHeader>
        <CardTitle>Access tokens</CardTitle>
        <CardDescription>Issue, verify and revoke IAM access tokens</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap gap-4">
        {OPERATIONS.map(({ op, label, icon: Icon }) => (
          <span key={op} className="inline-flex flex-col items-start gap-1">
            <Button type="button" variant="outline" disabled title={tokenRouteReason(op)} aria-describedby={`token-op-${op}`}>
              <Icon className="h-4 w-4 mr-2" aria-hidden="true" />
              {label}
            </Button>
            <p id={`token-op-${op}`} className="text-xs text-muted-foreground">
              {tokenRouteReason(op)}
            </p>
          </span>
        ))}
      </CardContent>
    </Card>
  );
}
