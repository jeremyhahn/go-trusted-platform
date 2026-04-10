import RoleDetailClient from "./role-detail-client";

export function generateStaticParams() {
  return [{ id: '__placeholder__' }];
}

export default function Page() {
  return <RoleDetailClient />;
}
