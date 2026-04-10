import CreateProfileClient from './create-profile-client';

export function generateStaticParams() {
  return [{ id: '__placeholder__' }];
}

export default function Page() {
  return <CreateProfileClient />;
}
