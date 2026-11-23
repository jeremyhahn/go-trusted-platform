'use client';

import { TenantBarrierCard } from '@/components/features/tenant/tenant-barrier-card';
import { TenantDEKCard } from '@/components/features/tenant/tenant-dek-card';
import { PageHeader } from '@/components/layout/page-header';
import { useAuth } from '@/contexts/AuthContext';

export default function TenantBarrierPage() {
  const { tenantId } = useAuth();

  return (
    <div className="space-y-6">
      <PageHeader title="Tenant keys" description="The tenant's key barrier and data encryption key" />
      {tenantId ? (
        <>
          <TenantBarrierCard tenantId={tenantId} />
          <TenantDEKCard tenantId={tenantId} />
        </>
      ) : (
        <p className="text-sm text-muted-foreground">No tenant selected</p>
      )}
    </div>
  );
}
