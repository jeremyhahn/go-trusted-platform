import CertDetailClient from "./cert-detail-client";

export function generateStaticParams() {
  return [{ id: '__placeholder__' }];
}

export default function Page({ params }: { params: Promise<{ id: string }> }) {
  return <CertDetailClient params={params} />;
}
