import { deleteCookie } from "./cookie";

/**
 * clearSession removes every cookie that constitutes a signed-in session.
 *
 * This is the ONE place that knows which cookies those are. It had been
 * spelled out at five call sites, and they drifted: the console header's
 * Log out cleared nothing at all and the sidebar's had no handler, so
 * "Log out" moved the operator off the dashboard while leaving them
 * signed in (#212).
 *
 * Clearing the browser's copy is not a server-side logout — the token
 * stays valid until it expires. Revoking it is #213.
 */
export function clearSession(): void {
  deleteCookie("jwt");
  deleteCookie("uid");
}
