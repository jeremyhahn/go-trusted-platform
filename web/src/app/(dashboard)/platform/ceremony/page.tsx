"use client";

import * as React from "react";

import { PageHeader } from "@/components/layout/page-header";

import { CeremonyClaimCertCard } from "./ceremony-claim-cert-card";
import { CeremonyClaimShareCard } from "./ceremony-claim-share-card";
import { CeremonyInitCard } from "./ceremony-init-card";
import { CeremonySignCSRCard } from "./ceremony-sign-csr-card";
import { CeremonyStatusCard } from "./ceremony-status-card";

export default function CeremonyPage() {
  // Bumped after a successful init so the status card fetches again; the
  // init card stays mounted, so the admin key it shows once stays on screen.
  const [statusVersion, setStatusVersion] = React.useState(0);
  return (
    <div>
      <PageHeader
        title="Bootstrap ceremony"
        description="State of the platform bootstrap ceremony, its initialization and officer CSR signing."
      />
      <CeremonyStatusCard refreshKey={statusVersion} />
      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <CeremonyInitCard onInitialized={() => setStatusVersion((v) => v + 1)} />
        <CeremonySignCSRCard />
      </div>
      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <CeremonyClaimCertCard />
        <CeremonyClaimShareCard />
      </div>
    </div>
  );
}
