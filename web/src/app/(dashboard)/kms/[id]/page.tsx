import KeyDetailClient from "./key-detail-client";

export function generateStaticParams() {
  return [{ id: '__placeholder__' }];
}

export default function Page({ params }: { params: Promise<{ id: string }> }) {
  return <KeyDetailClient params={params} />;
}
