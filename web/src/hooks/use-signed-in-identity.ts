"use client";

import { useOptionalAuth, type User } from "@/contexts/AuthContext";

/**
 * What the console shell shows for the signed-in account. It comes from the
 * session's JWT claims, never from a placeholder (#643): the token carries no
 * display name, so the email is the identity and the tenant the context.
 */
export interface SignedInIdentity {
  email: string;
  tenantId: string | null;
  initial: string;
}

/** Maps the authenticated user to the shell identity, or null when signed out. */
export function signedInIdentity(user: User | null): SignedInIdentity | null {
  if (!user || !user.email) {
    return null;
  }
  return {
    email: user.email,
    tenantId: user.tenantId,
    initial: user.email.charAt(0).toUpperCase(),
  };
}

/** The signed-in identity from the surrounding AuthProvider, if any. */
export function useSignedInIdentity(): SignedInIdentity | null {
  return signedInIdentity(useOptionalAuth()?.user ?? null);
}
