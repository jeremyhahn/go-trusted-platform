'use client';

import { TenantDirectoryCard } from '@/components/features/tenant/tenant-directory-card';
import { PageHeader } from '@/components/layout/page-header';

export default function TenantDirectoryPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Tenant directory"
        description="List, create, rename, suspend, resume, delete, find and sync tenants"
      />
      <TenantDirectoryCard />
    </div>
  );
}
