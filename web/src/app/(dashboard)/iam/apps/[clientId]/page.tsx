import AppDetailClient from "./app-detail-client";

export function generateStaticParams() {
  return [{ clientId: '__placeholder__' }];
}

export default function Page() {
  return <AppDetailClient />;
}
