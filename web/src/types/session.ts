/**
 * Session — the credential set a completed login hands the client.
 *
 * The ceremony runs on the unified backbone (go-qrdb's login resolver),
 * which verifies the factor and resolves the principal. The bearer stored
 * here is then minted by the PLATFORM from that identity, because the seam
 * every protected route runs validates platform-signed tokens and there is
 * no working inbound validator for the backbone's own bearer yet — see
 * login.SessionIssuer in pkg/webservice/v1/login/session.go.
 *
 * That is also why no refresh credential arrives today: the backbone's
 * renews the backbone's session, not the one in the jwt cookie. The field
 * stays optional because the pair returns together when the backbone
 * bearer becomes the session, and because a stale one may still be sitting
 * in a browser from an earlier build.
 *
 * Mirrors login.Session in pkg/webservice/v1/login/session.go.
 */
export interface Session {
  /** The OIDC access token to present on subsequent requests. */
  bearer: string;

  /** The bearer's expiry, RFC 3339. */
  expiresAt?: string;

  /**
   * Renews the session without re-running the factor ceremony. Not issued
   * while the platform mints the bearer (see above).
   */
  refreshToken?: string;

  /**
   * The session's absolute deadline, RFC 3339. Renewal does not move it;
   * past this instant the factor ceremony must run again.
   */
  refreshExpiresAt?: string;
}
