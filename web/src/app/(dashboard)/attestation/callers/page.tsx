"use client";

import { RefreshCw } from "lucide-react";
import type { CallerPolicyDescription } from "trusted-platform-sdk";
import { PageHeader } from "@/components/layout/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useApi, useAttestation } from "@/hooks";
import { useCapabilities } from "@/hooks/use-capabilities";
import { Gated } from "@/components/features/capabilities/gated";

const OP = "GET /api/v1/attestation/callers";

function yesNo(v: boolean | undefined): string {
  return v ? "yes" : "no";
}

function PolicyDetails({ policy }: { policy: CallerPolicyDescription }) {
  const identities = policy.identities ?? [];
  const invalid = policy.invalid_entries ?? [];
  return (
    <dl className="grid grid-cols-2 gap-2 text-sm max-w-2xl">
      <dt className="text-muted-foreground">Strategy</dt>
      <dd className="font-mono">{policy.strategy}</dd>
      <dt className="text-muted-foreground">Identities</dt>
      <dd>
        {identities.length === 0 ? (
          <span className="text-muted-foreground">none</span>
        ) : (
          <ul className="space-y-1">
            {identities.map((id) => (
              <li key={id} className="font-mono break-all">
                {id}
              </li>
            ))}
          </ul>
        )}
      </dd>
      <dt className="text-muted-foreground">Identities source</dt>
      <dd>{policy.identities_source || "-"}</dd>
      <dt className="text-muted-foreground">List valid</dt>
      <dd>{yesNo(policy.list_valid)}</dd>
      <dt className="text-muted-foreground">Invalid entries</dt>
      <dd>
        {invalid.length === 0 ? (
          <span className="text-muted-foreground">none</span>
        ) : (
          <ul className="space-y-1">
            {invalid.map((entry) => (
              <li key={entry} className="font-mono break-all">
                {entry}
              </li>
            ))}
          </ul>
        )}
      </dd>
      <dt className="text-muted-foreground">Anchors configured</dt>
      <dd>{yesNo(policy.anchors_configured)}</dd>
      <dt className="text-muted-foreground">Anchor source</dt>
      <dd>{policy.anchor_source || "-"}</dd>
      <dt className="text-muted-foreground">Attested peers available</dt>
      <dd>{yesNo(policy.attested_peers_available)}</dd>
    </dl>
  );
}

// CallerPolicyPage shows the node's machine-caller admission policy
// (AttestationService.DescribeCallerPolicy), read only when the server
// offers GET /api/v1/attestation/callers.
export default function CallerPolicyPage() {
  const attestation = useAttestation();
  const { loading: capsLoading, capability } = useCapabilities();
  const cap = capability(OP);
  const policy = useApi(() => attestation.describeCallers(), [attestation], {
    enabled: !capsLoading && cap.enabled,
  });

  return (
    <div className="container mx-auto py-6 space-y-6">
      <PageHeader title="Caller policy" description="Which machine callers this node admits">
        <Gated op={OP}>
          <Button variant="outline" size="sm" onClick={() => void policy.refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </Gated>
      </PageHeader>

      {!capsLoading && !cap.enabled ? (
        <Card data-testid="caller-policy-not-enabled">
          <CardHeader>
            <CardTitle>The caller policy is not offered by this server</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{cap.reason}</p>
          </CardContent>
        </Card>
      ) : policy.error ? (
        <Card data-testid="caller-policy-error">
          <CardHeader>
            <CardTitle>Could not read the caller policy</CardTitle>
          </CardHeader>
          <CardContent>
            <p role="alert" className="text-sm text-destructive">
              {policy.error.message}
            </p>
          </CardContent>
        </Card>
      ) : policy.data ? (
        <>
          {policy.data.admits_nobody ? (
            <Alert variant="destructive" data-testid="caller-admits-nobody">
              <AlertTitle>This node admits no machine caller</AlertTitle>
              <AlertDescription>
                No identity, anchor or attested peer can pass the current policy.
              </AlertDescription>
            </Alert>
          ) : null}
          <Card data-testid="caller-policy">
            <CardHeader>
              <CardTitle>Policy</CardTitle>
            </CardHeader>
            <CardContent>
              <PolicyDetails policy={policy.data} />
            </CardContent>
          </Card>
        </>
      ) : null}
    </div>
  );
}
