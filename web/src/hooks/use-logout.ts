"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useOptionalAuth } from "@/contexts/AuthContext";
import { clearSession, revokeSession } from "@/utils/session";

/**
 * useLogout returns the console's single sign-out action.
 *
 * It clears the session cookies and, when the caller is inside an
 * AuthProvider, also drops the in-memory user so AuthGuard sees an
 * unauthenticated state on the very next render rather than after a
 * remount. AuthProvider wraps only the (dashboard) group, so the controls
 * on standalone pages get the cookie teardown and nothing to un-cache.
 *
 * Every logout control must go through here. The console has five, and
 * when each carried its own idea of what signing out meant, the header's
 * navigated without clearing anything and the sidebar's did nothing at
 * all (#212).
 */
export function useLogout(): () => void {
  const router = useRouter();
  const auth = useOptionalAuth();

  return React.useCallback(() => {
    // Revoke on the server first, while the bearer is still readable
    // (#215); AuthContext.logout and clearSession only drop local state.
    revokeSession();
    if (auth) {
      auth.logout();
    } else {
      clearSession();
    }
    router.replace("/auth/webauthn");
  }, [auth, router]);
}
