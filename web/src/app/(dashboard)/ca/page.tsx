"use client";

import Link from "next/link";
import { AlertCircle, FileSignature, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useCA, useApi } from "@/hooks";

/** A chain entry as the REST layer sends it (camelCase or snake_case). */
interface CertSummaryWire {
  serial?: string;
  commonName?: string;
  common_name?: string;
  issuer?: string;
}

/** The CA info as the REST layer sends it (camelCase or snake_case). */
interface CAInfoWire {
  commonName?: string;
  common_name?: string;
  isIntermediate?: boolean;
  is_intermediate?: boolean;
  rootCert?: CertSummaryWire;
  root_cert?: CertSummaryWire;
  intermediates?: CertSummaryWire[];
  defaultAlgorithm?: string;
  default_algorithm?: string;
  defaultValidityDays?: number;
  default_validity_days?: number;
}

const nameOf = (c: CertSummaryWire): string => c.commonName ?? c.common_name ?? c.serial ?? "Unknown";

/**
 * CA overview: GET /v1/ca/info (identity, default algorithm and validity,
 * chain summaries), with links to the sign-CSR and verify pages.
 */
export default function CAOverviewPage() {
  const ca = useCA();
  const { data, isLoading, error } = useApi(() => ca.getInfo(), []);

  const wire = (data as unknown as { caInfo?: CAInfoWire; ca_info?: CAInfoWire } | undefined) ?? {};
  const info: CAInfoWire = wire.caInfo ?? wire.ca_info ?? {};
  const root = info.rootCert ?? info.root_cert;
  const intermediates = info.intermediates ?? [];
  const validity = info.defaultValidityDays ?? info.default_validity_days;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Certificate Authority</h1>
          <p className="text-muted-foreground">The platform CA&apos;s identity, defaults and chain</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" asChild>
            <Link href="/ca/sign" data-testid="ca-sign-link">
              <FileSignature className="mr-2 h-4 w-4" />
              Sign CSR
            </Link>
          </Button>
          <Button variant="outline" asChild>
            <Link href="/ca/verify" data-testid="ca-verify-link">
              <ShieldCheck className="mr-2 h-4 w-4" />
              Verify Certificate
            </Link>
          </Button>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-4 bg-destructive/10 border border-destructive rounded-lg">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <p className="text-sm text-destructive">{error.message}</p>
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Identity</CardTitle>
          <CardDescription>{isLoading ? "Loading..." : "As reported by the CA"}</CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-2 text-sm">
            <dt className="text-muted-foreground">Common name</dt>
            <dd data-testid="ca-common-name">{info.commonName ?? info.common_name ?? ""}</dd>
            <dt className="text-muted-foreground">Type</dt>
            <dd>{(info.isIntermediate ?? info.is_intermediate) ? "Intermediate" : "Root"}</dd>
            <dt className="text-muted-foreground">Default algorithm</dt>
            <dd data-testid="ca-default-algorithm">{info.defaultAlgorithm ?? info.default_algorithm ?? ""}</dd>
            <dt className="text-muted-foreground">Default validity</dt>
            <dd data-testid="ca-default-validity">{validity !== undefined ? `${validity} days` : ""}</dd>
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Chain</CardTitle>
          <CardDescription>Root and intermediate certificates</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2 text-sm">
          <div data-testid="ca-root-cert">
            <span className="text-muted-foreground">Root: </span>
            {root ? `${nameOf(root)} (serial ${root.serial ?? "?"})` : "None"}
          </div>
          <ul data-testid="ca-intermediates" className="list-disc pl-5">
            {intermediates.map((c) => (
              <li key={c.serial ?? nameOf(c)}>
                {nameOf(c)} (serial {c.serial ?? "?"}), issued by {c.issuer ?? "Unknown"}
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
