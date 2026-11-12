import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AuthContextType, User } from "@/contexts/AuthContext";

import { signedInIdentity, useSignedInIdentity } from "./use-signed-in-identity";

const mocks = vi.hoisted(() => ({ auth: null as AuthContextType | null }));

vi.mock("@/contexts/AuthContext", () => ({
  useOptionalAuth: () => mocks.auth,
}));

function user(overrides: Partial<User> = {}): User {
  return {
    id: "u-1",
    email: "alice",
    tenantId: "tenant-1",
    isTenantOwner: false,
    roles: [],
    ...overrides,
  };
}

function authFor(u: User | null): AuthContextType {
  return {
    user: u,
    tenantId: u?.tenantId ?? null,
    isAuthenticated: u !== null,
    isLoading: false,
    login: vi.fn(),
    logout: vi.fn(),
  };
}

describe("signedInIdentity", () => {
  it("maps a user to email, tenant and upper-case initial", () => {
    expect(signedInIdentity(user())).toEqual({
      email: "alice",
      tenantId: "tenant-1",
      initial: "A",
    });
  });

  it("keeps a null tenant", () => {
    expect(signedInIdentity(user({ tenantId: null }))?.tenantId).toBeNull();
  });

  it("is null when signed out", () => {
    expect(signedInIdentity(null)).toBeNull();
  });

  it("is null for a user with an empty email", () => {
    expect(signedInIdentity(user({ email: "" }))).toBeNull();
  });

  it("is null for a malformed user without an email", () => {
    const malformed = { ...user(), email: undefined } as unknown as User;
    expect(signedInIdentity(malformed)).toBeNull();
  });

  it("uses the first character as-is when it has no upper case", () => {
    expect(signedInIdentity(user({ email: "1bob" }))?.initial).toBe("1");
  });

  it("upper-cases a non-ASCII initial", () => {
    expect(signedInIdentity(user({ email: "élise" }))?.initial).toBe("É");
  });

  it("does not trim the email", () => {
    expect(signedInIdentity(user({ email: " x" }))).toEqual(
      expect.objectContaining({ email: " x", initial: " " })
    );
  });
});

describe("useSignedInIdentity", () => {
  beforeEach(() => {
    mocks.auth = null;
  });

  it("is null outside an AuthProvider", () => {
    const { result } = renderHook(() => useSignedInIdentity());
    expect(result.current).toBeNull();
  });

  it("is null inside an AuthProvider with no user", () => {
    mocks.auth = authFor(null);
    const { result } = renderHook(() => useSignedInIdentity());
    expect(result.current).toBeNull();
  });

  it("returns the identity of the signed-in user", () => {
    mocks.auth = authFor(user({ email: "bob", tenantId: null }));
    const { result } = renderHook(() => useSignedInIdentity());
    expect(result.current).toEqual({ email: "bob", tenantId: null, initial: "B" });
  });

  it("follows the user when the context changes", () => {
    const { result, rerender } = renderHook(() => useSignedInIdentity());
    expect(result.current).toBeNull();
    mocks.auth = authFor(user());
    rerender();
    expect(result.current?.email).toBe("alice");
  });
});
