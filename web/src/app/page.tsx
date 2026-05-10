'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

// Root landing page. The platform exports this site as a static
// build (`next build` with `output: 'export'`), where Next.js's
// server-side `redirect()` from `next/navigation` is a no-op — it
// only fires inside a server component during a real Node render,
// which never happens for static-exported sites. The previously
// shipped server `redirect()` therefore produced `index.html` as the
// `__next_error__` template, which is what surfaced as a "blank
// page" at https://cp.example.com:8443/ until the user manually
// navigated to /ui (which falls through to client-side routing
// after a brief 404 flash).
//
// Use a client-side replace via the App Router instead. This:
//   1. Renders synchronously into the static index.html.
//   2. Fires immediately on hydration, before the user sees a flash.
//   3. Uses `router.replace` (not push) so the back button doesn't
//      land back on `/` and re-trigger the redirect loop.
//
// When real auth status is wired through, branch on a hook here
// (e.g. `useAuth().isAuthenticated`) and replace to `/dashboard`
// for signed-in users, `/auth/webauthn` for anonymous.
export default function Home() {
  const router = useRouter();

  useEffect(() => {
    router.replace('/auth/webauthn');
  }, [router]);

  return null;
}
