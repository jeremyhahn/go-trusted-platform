import PXEDeviceClient from "./pxe-device-client";

export function generateStaticParams() {
  return [{ mac: '__placeholder__' }];
}

export default function Page() {
  return <PXEDeviceClient />;
}
