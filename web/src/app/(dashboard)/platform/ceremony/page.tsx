"use client";

import { PageHeader } from "@/components/layout/page-header";

import { CeremonyInitCard } from "./ceremony-init-card";
import { CeremonyStatusCard } from "./ceremony-status-card";

export default function CeremonyPage() {
  return (
    <div>
      <PageHeader
        title="Bootstrap ceremony"
        description="State of the platform bootstrap ceremony."
      />
      <CeremonyStatusCard />
      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <CeremonyInitCard />
      </div>
    </div>
  );
}
