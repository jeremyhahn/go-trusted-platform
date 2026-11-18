"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useOptionalAuth } from "@/contexts/AuthContext";
import { clearSession, revokeSession, type RevokeOutcome } from "@/utils/session";

/**
 * useLocalLogout returns a sign-out that only drops this browser's copy of
 * the session: it clears the session cookies (and, inside an AuthProvider,
 * the in-memory user) and goes to the sign-in screen, without asking the
 * server for anything. The logout page offers it when the server could not
 * confirm a revocation (#646).
 */
export function useLocalLogout(): () => void {
  const router = useRouter();
  const auth = useOptionalAuth();

  return React.useCallback(() => {
    if (auth) {
      auth.logout();
    } else {
      clearSession();
    }
    router.replace("/auth/webauthn");
  }, [auth, router]);
}

/**
 * useLogout returns the console's single sign-out action.
 *
 * It revokes the bearer on the server first (#215), while the bearer is
 * still readable, and only a server answer counts as a server-side logout
 * (#646). When the server revoked the bearer, or already refuses it, or
 * there was no session, it clears the session cookies and, inside an
 * AuthProvider, the in-memory user, so AuthGuard sees an unauthenticated
 * state on the very next render, then goes to the sign-in screen. When
 * the revocation failed, it clears nothing, keeping the bearer so a retry
 * can still revoke it, and goes to the logout page's retry surface.
 *
 * Every logout control must go through here. The console has five, and
 * when each carried its own idea of what signing out meant, the header's
 * navigated without clearing anything and the sidebar's did nothing at
 * all (#212).
 */
export function useLogout(): () => Promise<RevokeOutcome> {
  const router = useRouter();
  const localLogout = useLocalLogout();

  return React.useCallback(async () => {
    const outcome = await revokeSession();
    if (outcome === "failed") {
      router.replace("/logout?revocation=failed");
    } else {
      localLogout();
    }
    return outcome;
  }, [localLogout, router]);
}
