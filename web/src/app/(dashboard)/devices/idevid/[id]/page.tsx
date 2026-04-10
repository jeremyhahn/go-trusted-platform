import IDevIDDetailClient from "./idevid-detail-client";

export function generateStaticParams() {
  return [{ id: '__placeholder__' }];
}

export default function Page() {
  return <IDevIDDetailClient />;
}
