import DNSZoneDetailClient from "./dns-zone-detail-client";

export function generateStaticParams() {
  return [{ zone: '__placeholder__' }];
}

export default function Page() {
  return <DNSZoneDetailClient />;
}
