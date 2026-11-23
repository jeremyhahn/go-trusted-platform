import { Suspense } from 'react';
import SnapshotDetailClient from './snapshot-detail-client';

export function generateStaticParams() {
  return [{ snapshotId: '__placeholder__' }];
}

// useSearchParams in the client needs a Suspense boundary in the static export.
export default function Page() {
  return (
    <Suspense fallback={null}>
      <SnapshotDetailClient />
    </Suspense>
  );
}
