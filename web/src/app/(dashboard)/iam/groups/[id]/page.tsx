import GroupDetailClient from "./group-detail-client";

export function generateStaticParams() {
  return [{ id: '__placeholder__' }];
}

export default function Page() {
  return <GroupDetailClient />;
}
