import SessionDetailClient from './session-detail-client';

export function generateStaticParams() {
  return [{ sessionId: '__placeholder__' }];
}

export default function Page() {
  return <SessionDetailClient />;
}
