import InvitationDetailClient from "./invitation-detail-client";

export function generateStaticParams() {
  return [{ id: '__placeholder__' }];
}

export default function Page({ params }: { params: Promise<{ id: string }> }) {
  return <InvitationDetailClient params={params} />;
}
