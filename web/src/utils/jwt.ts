import { getCookie } from "./cookie";

export interface JWTPayload {
  sub?: string;
  user_id?: string;
  email?: string;
  tenant_id?: string;
  is_tenant_owner?: boolean;
  roles?: string[];
  exp?: number;
  iat?: number;
}

/**
 * User object with camelCase properties for easier use in components.
 */
export interface User {
  id: string;
  email: string;
  tenantId: string | null;
  isTenantOwner: boolean;
  roles: string[];
}

/**
 * Decode a JWT token without verification (client-side only).
 * SECURITY NOTE: This does NOT verify the signature. Only use for extracting
 * claims on the client side. Server must always verify the token.
 *
 * @param token - JWT token string
 * @returns Decoded JWT payload or null if invalid
 */
export function decodeJWT(token: string): JWTPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return null;
    }

    // Convert base64url to base64 and add padding
    let payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    // Add padding if needed (base64url omits trailing = padding)
    const padLength = (4 - (payload.length % 4)) % 4;
    payload += "=".repeat(padLength);

    const decoded = atob(payload);
    return JSON.parse(decoded) as JWTPayload;
  } catch {
    return null;
  }
}

/**
 * Get JWT token from cookie.
 *
 * @returns JWT token string or null if not found
 */
export function getTokenFromCookie(): string | null {
  return getCookie("jwt");
}

/**
 * Get user information from JWT token stored in cookie.
 *
 * @returns User object with camelCase properties or null if token not found/invalid
 */
export function getUserFromToken(): User | null {
  const token = getTokenFromCookie();
  if (!token) {
    return null;
  }

  const payload = decodeJWT(token);
  if (!payload) {
    return null;
  }

  const userId = payload.sub || payload.user_id;
  const email = payload.email;
  const tenantId = payload.tenant_id ?? null;

  // Only require userId and email - tenantId is optional
  if (!userId || !email) {
    return null;
  }

  return {
    id: userId,
    email: email,
    tenantId: tenantId,
    isTenantOwner: payload.is_tenant_owner ?? false,
    roles: payload.roles ?? [],
  };
}
