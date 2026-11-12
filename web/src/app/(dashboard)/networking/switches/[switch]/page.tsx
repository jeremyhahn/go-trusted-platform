import SwitchPortsClient from "./switch-ports-client";

export function generateStaticParams() {
  return [{ switch: '__placeholder__' }];
}

export default function Page() {
  return <SwitchPortsClient />;
}
