import InviteAcceptClient from "./invite-accept-client";

export function generateStaticParams() {
  return [{ token: '__placeholder__' }];
}

export default function Page({ params }: { params: Promise<{ token: string }> }) {
  return <InviteAcceptClient params={params} />;
}
