import ContainerDetailClient from './container-detail-client';

export function generateStaticParams() {
  return [{ id: '__placeholder__' }];
}

export default function Page() {
  return <ContainerDetailClient />;
}
