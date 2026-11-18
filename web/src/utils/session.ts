import { deleteCookie, getCookie, setCookie } from "./cookie";
import { getBaseUrl } from "./getBaseUrl";
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
 * Clearing the browser's copy is not a server-side logout on its own;
 * revokeSession is, and the sign-out action calls it first (#215).
 */
export function clearSession(): void {
  deleteCookie("jwt");
  deleteCookie("refresh");
  deleteCookie("uid");
}

/** What the server said to a sign-out; see revokeSession. */
export type RevokeOutcome = "revoked" | "rejected" | "failed" | "none";

/**
 * revokeSession signs the session out on the server (#215): the platform
 * adds the bearer to its deny-list, so a copy of the token stops working
 * the moment the operator signs out instead of when it expires.
 *
 * The bearer is read and sent as an explicit Authorization header before
 * the caller clears the cookies, so the request cannot race the cookie
 * teardown. `keepalive` lets it finish if the page navigates away.
 *
 * The promise resolves to what the server said (#646), so the caller can
 * tell a server-side logout from a local one:
 * - "revoked": a 2xx answer, the bearer is on the deny-list;
 * - "rejected": 401, the server already refuses this bearer, so there is
 *   nothing left to revoke;
 * - "failed": any other status (503 when the revocation store is down)
 *   or a request that never got an answer; the session may still be
 *   valid on the server, and the bearer should be kept for a retry;
 * - "none": no bearer cookie, so no request was sent.
 */
export async function revokeSession(): Promise<RevokeOutcome> {
  // Read the bearer before any await: a caller may clear the cookies
  // right after starting the revocation.
  const bearer = getCookie("jwt");
  if (!bearer) {
    return "none";
  }
  try {
    const response = await fetch(`${getBaseUrl()}/api/v1/logout`, {
      method: "POST",
      credentials: "same-origin",
      keepalive: true,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${bearer}`,
      },
    });
    if (response.ok) {
      return "revoked";
    }
    if (response.status === 401) {
      return "rejected";
    }
    return "failed";
  } catch {
    return "failed";
  }
}
