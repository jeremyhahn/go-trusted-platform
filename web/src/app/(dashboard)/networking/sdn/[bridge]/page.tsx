import SDNBridgeDetailClient from "./sdn-bridge-detail-client";

export function generateStaticParams() {
  return [{ bridge: '__placeholder__' }];
}

export default function Page() {
  return <SDNBridgeDetailClient />;
}
