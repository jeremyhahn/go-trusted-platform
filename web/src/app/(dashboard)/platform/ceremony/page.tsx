"use client";

import { PageHeader } from "@/components/layout/page-header";

import { CeremonyInitCard } from "./ceremony-init-card";
import { CeremonySignCSRCard } from "./ceremony-sign-csr-card";
import { CeremonyStatusCard } from "./ceremony-status-card";

export default function CeremonyPage() {
  return (
    <div>
      <PageHeader
        title="Bootstrap ceremony"
        description="State of the platform bootstrap ceremony, its initialization and officer CSR signing."
      />
      <CeremonyStatusCard />
      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <CeremonyInitCard />
        <CeremonySignCSRCard />
      </div>
    </div>
  );
}
