"use client";

import { Loader2, RefreshCw } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useCallerPolicy } from "@/hooks/use-caller-policy";

function Flag({ label, on }: { label: string; on: boolean }) {
  return (
    <p className="flex items-center gap-2 text-sm">
      {label}: <Badge variant={on ? "default" : "secondary"}>{on ? "yes" : "no"}</Badge>
    </p>
  );
}

/** DescribeCallerPolicy (#2038): which callers the attestation API admits. */
export default function CallerPolicyPage() {
  const { policy, error, loading, reload } = useCallerPolicy();

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Caller policy</h1>
          <p className="text-muted-foreground">
            The compiled policy that decides which callers the attestation API admits
          </p>
        </div>
        <Button variant="outline" onClick={() => reload()} disabled={loading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      <Card data-testid="caller-policy">
        <CardHeader>
          <CardTitle>Policy</CardTitle>
          <CardDescription>As the server describes it</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {loading && !policy && !error && (
            <p className="flex items-center text-sm">
              <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading caller policy...
            </p>
          )}
          {error && (
            <Alert variant="destructive">
              <AlertTitle>Caller policy unavailable</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {policy && (
            <>
              {policy.admits_nobody && (
                <Alert variant="destructive">
                  <AlertTitle>No caller is admitted</AlertTitle>
                  <AlertDescription>The compiled policy admits no caller at all.</AlertDescription>
                </Alert>
              )}
              <p className="text-sm">Strategy: {policy.strategy}</p>
              <Flag label="Identity list valid" on={policy.list_valid} />
              <Flag label="Trust anchors configured" on={policy.anchors_configured} />
              <Flag label="Attested peers available" on={policy.attested_peers_available} />
              {policy.identities_source && (
                <p className="text-sm">Identities from: {policy.identities_source}</p>
              )}
              {policy.anchor_source && <p className="text-sm">Anchors from: {policy.anchor_source}</p>}
              <div className="text-sm">
                Identities:
                {policy.identities.length === 0 ? (
                  <span className="ml-1 text-muted-foreground">none</span>
                ) : (
                  <ul className="ml-4 list-disc font-mono text-xs">
                    {policy.identities.map((id) => (
                      <li key={id}>{id}</li>
                    ))}
                  </ul>
                )}
              </div>
              {policy.invalid_entries && policy.invalid_entries.length > 0 && (
                <div className="text-sm text-destructive">
                  Invalid entries:
                  <ul className="ml-4 list-disc font-mono text-xs">
                    {policy.invalid_entries.map((e) => (
                      <li key={e}>{e}</li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
