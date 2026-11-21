'use client';

/**
 * KMS data keys page: GenerateDataKey (`POST /api/v1/kms/data-keys`) and
 * GenerateWrappedDataKey (`POST /api/v1/kms/data-keys/wrapped`) on the
 * useKMSDataKeys hook. Refusals are shown verbatim; the plaintext data key
 * is shown once and never stored, logged or toasted.
 */

import { PageHeader } from '@/components/layout/page-header';

import { DataKeyCard } from './data-key-card';
import { WrappedDataKeyCard } from './wrapped-data-key-card';

export default function DataKeysPage() {
  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="Data keys" description="Generate envelope data keys under a KMS key." />
      <DataKeyCard />
      <WrappedDataKeyCard />
    </div>
  );
}
