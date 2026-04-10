import AttestationDetailClient from "./attestation-detail-client";

export function generateStaticParams() {
  return [{ id: '__placeholder__' }];
}

export default function Page({ params }: { params: Promise<{ id: string }> }) {
  return <AttestationDetailClient params={params} />;
}
