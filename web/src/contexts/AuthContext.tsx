"use client";

import { createContext, useContext, useMemo, ReactNode } from "react";
import { decodeJWT, type JWTPayload } from "@/utils/jwt";
import { clearSession } from "@/utils/session";
import { setCookie } from "@/utils/cookie";
import {
  notifySessionChanged,
  useHydrated,
  useSessionToken,
} from "@/hooks/use-session-token";

export interface User {
  id: string;
  email: string;
  tenantId: string | null;
  isTenantOwner: boolean;
  roles: string[];
}

export interface AuthContextType {
  user: User | null;
  tenantId: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (token: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

function mapJWTToUser(payload: JWTPayload): User | null {
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

export function AuthProvider({ children }: { children: ReactNode }) {
  // The session cookie is the source of truth, read through an SSR-safe
  // external store: null while hydrating (so isLoading is true and nobody
  // redirects on a not-yet-read cookie), then the cookie value. login/logout
  // write the cookie and notify the store instead of copying into state.
  const hydrated = useHydrated();
  const token = useSessionToken();
  const user = useMemo<User | null>(() => {
    if (!token) return null;
    const payload = decodeJWT(token);
    return payload ? mapJWTToUser(payload) : null;
  }, [token]);
  const isLoading = !hydrated;

  const login = (token: string) => {
    setCookie("jwt", token, {
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      secure: true,
      sameSite: "Strict",
    });
    notifySessionChanged();
  };

  const logout = () => {
    clearSession();
    notifySessionChanged();
  };

  const value: AuthContextType = {
    user,
    tenantId: user?.tenantId ?? null,
    isAuthenticated: !!user,
    isLoading,
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/**
 * useOptionalAuth returns the auth context when the caller is inside an
 * AuthProvider and null otherwise. AuthProvider wraps only the (dashboard)
 * group, so the sign-out controls on standalone pages (/logout, /protected,
 * /admin/*) live outside it and must not throw just for asking.
 */
export function useOptionalAuth(): AuthContextType | null {
  return useContext(AuthContext) ?? null;
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
