import PolicyDetailClient from "./policy-detail-client";

export function generateStaticParams() {
  return [{ name: '__placeholder__' }];
}

export default function Page() {
  return <PolicyDetailClient />;
}
