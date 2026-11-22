import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AuthContextType } from "@/contexts/AuthContext";

import { useLogout } from "./use-logout";

const mocks = vi.hoisted(() => {
  const replace = vi.fn();
  return {
    replace,
    // One router object across renders, as next/navigation gives.
    router: { replace },
    clearSession: vi.fn(),
    auth: null as AuthContextType | null,
  };
});

vi.mock("next/navigation", () => ({
  useRouter: () => mocks.router,
}));

vi.mock("@/contexts/AuthContext", () => ({
  useOptionalAuth: () => mocks.auth,
}));

vi.mock("@/utils/session", () => ({
  clearSession: mocks.clearSession,
}));

function authWith(logout: () => void): AuthContextType {
  return {
    user: null,
    tenantId: null,
    isAuthenticated: true,
    isLoading: false,
    login: vi.fn(),
    logout,
  };
}

describe("useLogout", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.auth = null;
  });

  it("returns a function and does nothing until it is called", () => {
    const { result } = renderHook(() => useLogout());
    expect(typeof result.current).toBe("function");
    expect(mocks.clearSession).not.toHaveBeenCalled();
    expect(mocks.replace).not.toHaveBeenCalled();
  });

  it("inside an AuthProvider, logs out through the context and not clearSession", () => {
    const logout = vi.fn();
    mocks.auth = authWith(logout);
    const { result } = renderHook(() => useLogout());
    result.current();
    expect(logout).toHaveBeenCalledTimes(1);
    expect(mocks.clearSession).not.toHaveBeenCalled();
    expect(mocks.replace).toHaveBeenCalledWith("/auth/webauthn");
  });

  it("outside an AuthProvider, clears the session cookies", () => {
    const { result } = renderHook(() => useLogout());
    result.current();
    expect(mocks.clearSession).toHaveBeenCalledTimes(1);
    expect(mocks.replace).toHaveBeenCalledWith("/auth/webauthn");
  });

  it("clears the session before it navigates", () => {
    const order: string[] = [];
    mocks.clearSession.mockImplementation(() => order.push("clear"));
    mocks.replace.mockImplementation(() => order.push("replace"));
    const { result } = renderHook(() => useLogout());
    result.current();
    expect(order).toEqual(["clear", "replace"]);
  });

  it("does not navigate when the context logout throws", () => {
    mocks.auth = authWith(() => {
      throw new Error("logout failed");
    });
    const { result } = renderHook(() => useLogout());
    expect(() => result.current()).toThrow("logout failed");
    expect(mocks.replace).not.toHaveBeenCalled();
  });

  it("signs out again on a second call", () => {
    const { result } = renderHook(() => useLogout());
    result.current();
    result.current();
    expect(mocks.clearSession).toHaveBeenCalledTimes(2);
    expect(mocks.replace).toHaveBeenCalledTimes(2);
  });

  it("keeps the same callback while the context is unchanged", () => {
    const { result, rerender } = renderHook(() => useLogout());
    const first = result.current;
    rerender();
    expect(result.current).toBe(first);
  });

  it("returns a new callback when the context changes", () => {
    const { result, rerender } = renderHook(() => useLogout());
    const first = result.current;
    const logout = vi.fn();
    mocks.auth = authWith(logout);
    rerender();
    expect(result.current).not.toBe(first);
    result.current();
    expect(logout).toHaveBeenCalledTimes(1);
    expect(mocks.clearSession).not.toHaveBeenCalled();
  });
});
