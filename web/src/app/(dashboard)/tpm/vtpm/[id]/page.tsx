import VTPMRuntimeClient from "./vtpm-runtime-client";

export function generateStaticParams() {
  return [{ id: '__placeholder__' }];
}

export default function Page({ params }: { params: Promise<{ id: string }> }) {
  return <VTPMRuntimeClient params={params} />;
}
