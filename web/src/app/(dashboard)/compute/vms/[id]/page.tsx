import VMDetailClient from "./vm-detail-client";

export function generateStaticParams() {
  return [{ id: '__placeholder__' }];
}

export default function Page() {
  return <VMDetailClient />;
}
