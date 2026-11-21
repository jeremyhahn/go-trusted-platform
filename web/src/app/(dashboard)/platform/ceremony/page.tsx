"use client";

import { PageHeader } from "@/components/layout/page-header";

import { CeremonyStatusCard } from "./ceremony-status-card";

export default function CeremonyPage() {
  return (
    <div>
      <PageHeader
        title="Bootstrap ceremony"
        description="State of the platform bootstrap ceremony."
      />
      <CeremonyStatusCard />
    </div>
  );
}
