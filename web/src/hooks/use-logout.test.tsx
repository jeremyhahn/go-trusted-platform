import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getCookie } from "@/utils/cookie";
import { useLocalLogout, useLogout } from "./use-logout";

const replace = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace, push: vi.fn() }),
}));

function wipe(): void {
  for (const name of ["jwt", "refresh", "uid"]) {
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
  }
}

function signIn(): void {
  document.cookie = "jwt=the-bearer; path=/";
  document.cookie = "refresh=the-refresh; path=/";
}

// #646: only a server answer counts as a server-side logout. A revocation
// the server could not record keeps the bearer for a retry and lands on the
// logout page's retry surface instead of a silent sign-out.
describe("useLogout", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    wipe();
    replace.mockReset();
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    wipe();
  });

  it("keeps the bearer and routes to the retry surface when the server answers 503", async () => {
    signIn();
    fetchMock.mockResolvedValue(new Response(null, { status: 503 }));
    const { result } = renderHook(() => useLogout());

    let outcome: string | undefined;
    await act(async () => {
      outcome = await result.current();
    });

    expect(outcome).toBe("failed");
    expect(getCookie("jwt")).toBe("the-bearer");
    expect(replace).toHaveBeenCalledWith("/logout?revocation=failed");
  });

  it("clears the session and routes to sign-in when the server revokes it", async () => {
    signIn();
    fetchMock.mockResolvedValue(new Response(null, { status: 200 }));
    const { result } = renderHook(() => useLogout());

    await act(async () => {
      await result.current();
    });

    expect(getCookie("jwt")).toBeNull();
    expect(getCookie("refresh")).toBeNull();
    expect(replace).toHaveBeenCalledWith("/auth/webauthn");
  });
});

describe("useLocalLogout", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    wipe();
    replace.mockReset();
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    wipe();
  });

  it("clears the session cookies without asking the server", () => {
    signIn();
    const { result } = renderHook(() => useLocalLogout());

    act(() => result.current());

    expect(fetchMock).not.toHaveBeenCalled();
    expect(getCookie("jwt")).toBeNull();
    expect(getCookie("refresh")).toBeNull();
    expect(replace).toHaveBeenCalledWith("/auth/webauthn");
  });
});
