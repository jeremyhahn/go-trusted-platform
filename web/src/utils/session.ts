import { deleteCookie, setCookie } from "./cookie";
import type { Session } from "@/types/session";

/**
 * storeSession persists the credentials a completed login issued.
 *
 * The bearer is the platform-minted session token the protected routes'
 * auth seam validates. A renewal credential is persisted whenever one
 * arrives: none does while the platform mints the bearer, but the pair
 * returns together once the backbone's own bearer becomes the session, and
 * a credential rotated on every redemption must be replaced rather than
 * kept.
 *
 * Every login path funnels through here so no two of them can disagree
 * about what a session consists of — the same reason clearSession exists.
 */
export function storeSession(session: Session): void {
  const options = { secure: true, sameSite: "Strict" as const };
  setCookie("jwt", session.bearer, {
    ...options,
    expires: session.expiresAt ? new Date(session.expiresAt) : undefined,
  });
  if (session.refreshToken) {
    setCookie("refresh", session.refreshToken, {
      ...options,
      expires: session.refreshExpiresAt
        ? new Date(session.refreshExpiresAt)
        : undefined,
    });
    return;
  }
  // A login that issues no renewal credential must also REMOVE any the
  // browser is still holding. Leaving one behind is worse than never
  // storing it: a refresh credential outlives the bearer it came with and
  // can mint new ones, so a stale one belonging to the PREVIOUS principal
  // would survive a login as somebody else and renew their session once
  // refresh handling is wired. Storing a session replaces it whole.
  deleteCookie("refresh");
}

/**
 * clearSession removes every cookie that constitutes a signed-in session.
 *
 * This is the ONE place that knows which cookies those are. It had been
 * spelled out at five call sites, and they drifted: the console header's
 * Log out cleared nothing at all and the sidebar's had no handler, so
 * "Log out" moved the operator off the dashboard while leaving them
 * signed in (#212).
 *
 * The refresh credential is cleared with the bearer, and that matters more
 * than the bearer does: a refresh credential left behind can mint fresh
 * bearers long after the one it was issued with expired, so leaving it
 * would make "Log out" worse than it was before renewal existed.
 *
 * Clearing the browser's copy is not a server-side logout — the
 * credentials stay valid until they expire. Revoking them is #213.
 */
export function clearSession(): void {
  deleteCookie("jwt");
  deleteCookie("refresh");
  deleteCookie("uid");
}
