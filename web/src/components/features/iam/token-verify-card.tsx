"use client";

/**
 * Verifies a pasted IAM token through the SDK's iam.verifyToken
 * (POST /api/v1/iam/tokens/verify, #2053) and shows the server's verdict.
 * Verify is gated on the server's capability for that op.
 */

import React, { useState } from "react";
import { KeyRound, Loader2 } from "lucide-react";
import type { VerifyIAMTokenResponse } from "trusted-platform-sdk";
import { useIAM, useMutation } from "@/hooks";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Gated } from "@/components/features/capabilities/gated";

export function TokenVerifyCard() {
  const iam = useIAM();
  const [token, setToken] = useState("");
  // The token the shown verdict belongs to: a verdict is shown only while
  // the textarea still holds that token.
  const [verified, setVerified] = useState<string | null>(null);
  const verify = useMutation((value: string) => iam.verifyToken({ token: value }));

  const trimmed = token.trim();
  const data = verify.data as VerifyIAMTokenResponse | undefined;
  const result =
    data && verified !== null && !verify.isLoading && !verify.error && verified === trimmed ? data : undefined;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-5 w-5 text-muted-foreground" /> Verify a token
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          className="space-y-4"
          onSubmit={(e: React.FormEvent) => {
            e.preventDefault();
            if (trimmed) {
              setVerified(trimmed);
              verify.mutate(trimmed);
            }
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="token-verify-input">Token</Label>
            <textarea
              id="token-verify-input"
              aria-label="Token"
              rows={3}
              className="w-full rounded-md border bg-background px-3 py-2 font-mono text-sm"
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
          </div>
          <Gated op="POST /api/v1/iam/tokens/verify">
            <Button type="submit" disabled={verify.isLoading || !trimmed}>
              {verify.isLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Verify
            </Button>
          </Gated>
        </form>
        {verify.error && (
          <p role="status" className="text-sm text-destructive">
            Verify failed: {verify.error.message}
          </p>
        )}
        {result && (
          <div role="status" className="space-y-2 text-sm">
            <div>
              {result.valid ? <Badge>Valid</Badge> : <Badge variant="destructive">Invalid</Badge>}
            </div>
            <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1">
              {result.userId && (
                <>
                  <dt className="text-muted-foreground">Subject</dt>
                  <dd>{result.userId}</dd>
                </>
              )}
              {result.tenantId && (
                <>
                  <dt className="text-muted-foreground">Tenant</dt>
                  <dd>{result.tenantId}</dd>
                </>
              )}
              {result.scopes && result.scopes.length > 0 && (
                <>
                  <dt className="text-muted-foreground">Scopes</dt>
                  <dd>{result.scopes.join(", ")}</dd>
                </>
              )}
              {result.roles && result.roles.length > 0 && (
                <>
                  <dt className="text-muted-foreground">Roles</dt>
                  <dd>{result.roles.join(", ")}</dd>
                </>
              )}
              {result.expiresAt && (
                <>
                  <dt className="text-muted-foreground">Expires</dt>
                  <dd>{new Date(result.expiresAt).toLocaleString()}</dd>
                </>
              )}
              {result.reason && (
                <>
                  <dt className="text-muted-foreground">Reason</dt>
                  <dd>{result.reason}</dd>
                </>
              )}
            </dl>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
