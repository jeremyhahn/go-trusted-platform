import PXEDeviceDetailClient from './pxe-device-detail-client';

export function generateStaticParams() {
  return [{ id: '__placeholder__' }];
}

export default function Page() {
  return <PXEDeviceDetailClient />;
}
