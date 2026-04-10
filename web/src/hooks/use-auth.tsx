'use client';

/**
 * Authentication context and hook
 *
 * Features:
 * - User authentication state management
 * - Extracts user info from JWT cookie
 * - Logout functionality
 * - SSR-safe
 */

import React, { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react';
import { getUserFromToken, type User as JWTUser } from '@/utils/jwt';
import { deleteCookie } from '@/utils/cookie';

export interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
  tenantId: string | null;
  isTenantOwner: boolean;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface AuthContextValue {
  user: User | null;
  tenantId: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export interface AuthProviderProps {
  children: React.ReactNode;
}

/**
 * Convert JWT user to auth user format
 */
function jwtUserToAuthUser(jwtUser: JWTUser): User {
  return {
    id: jwtUser.id,
    email: jwtUser.email,
    name: jwtUser.email.split('@')[0], // Use email prefix as name
    roles: jwtUser.roles,
    tenantId: jwtUser.tenantId,
    isTenantOwner: jwtUser.isTenantOwner,
  };
}

/**
 * Auth Provider Component
 *
 * @example
 * ```tsx
 * // Wrap app with provider
 * <AuthProvider>
 *   <App />
 * </AuthProvider>
 * ```
 */
export function AuthProvider({ children }: AuthProviderProps): React.ReactElement {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const isMountedRef = useRef(true);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  /**
   * Load user from JWT token in cookie
   */
  const loadUser = useCallback(() => {
    try {
      const jwtUser = getUserFromToken();

      if (!isMountedRef.current) {
        return;
      }

      if (jwtUser) {
        setUser(jwtUserToAuthUser(jwtUser));
      } else {
        setUser(null);
      }
    } catch (err) {
      if (isMountedRef.current) {
        setUser(null);
      }
    } finally {
      if (isMountedRef.current) {
        setIsLoading(false);
      }
    }
  }, []);

  /**
   * Initialize auth state on mount
   */
  useEffect(() => {
    loadUser();
  }, [loadUser]);

  /**
   * Login - WebAuthn handles this, just refresh user state
   */
  const login = useCallback(async (_credentials: LoginCredentials): Promise<void> => {
    setIsLoading(true);
    // WebAuthn login sets the JWT cookie, just reload user
    loadUser();
    setIsLoading(false);
  }, [loadUser]);

  /**
   * Logout user - clear cookies and redirect
   */
  const logout = useCallback(async (): Promise<void> => {
    setIsLoading(true);

    // Clear auth cookies
    deleteCookie('jwt');
    deleteCookie('uid');

    setUser(null);
    setIsLoading(false);

    // Redirect to login
    window.location.href = '/auth/webauthn';
  }, []);

  /**
   * Refresh user from JWT token
   */
  const refresh = useCallback(async (): Promise<void> => {
    loadUser();
  }, [loadUser]);

  const value: AuthContextValue = {
    user,
    tenantId: user?.tenantId ?? null,
    isLoading,
    isAuthenticated: user !== null,
    login,
    logout,
    refresh,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/**
 * Hook to access auth context
 *
 * @example
 * ```tsx
 * function Profile() {
 *   const { user, isAuthenticated, logout } = useAuth();
 *
 *   if (!isAuthenticated) {
 *     return <div>Please login</div>;
 *   }
 *
 *   return (
 *     <div>
 *       <p>Welcome, {user.name}</p>
 *       <button onClick={logout}>Logout</button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);

  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }

  return context;
}
