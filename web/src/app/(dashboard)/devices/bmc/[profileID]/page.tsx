import BMCProfileClient from "./bmc-profile-client";

export function generateStaticParams() {
  return [{ profileID: "__placeholder__" }];
}

export default function Page() {
  return <BMCProfileClient />;
}
