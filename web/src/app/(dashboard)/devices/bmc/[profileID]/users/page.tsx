import BMCUsersClient from "./bmc-users-client";

export function generateStaticParams() {
  return [{ profileID: '__placeholder__' }];
}

export default function Page() {
  return <BMCUsersClient />;
}
