import { act, cleanup, renderHook } from "@testing-library/react";
import { renderToString } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";

import { notifySessionChanged, useHydrated, useSessionToken } from "./use-session-token";

function clearJwtCookie(): void {
  document.cookie = "jwt=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
}

function resetDom(): void {
  cleanup();
  clearJwtCookie();
}

function HydrationProbe() {
  return <span>{useHydrated() ? "hydrated" : "pending"}</span>;
}

function TokenProbe() {
  return <span>{useSessionToken() ?? "none"}</span>;
}

describe("useSessionToken", () => {
  afterEach(resetDom);

  it("returns the jwt cookie on the client", () => {
    document.cookie = "jwt=abc.def.ghi; path=/";
    const { result } = renderHook(() => useSessionToken());
    expect(result.current).toBe("abc.def.ghi");
  });

  it("returns null when there is no jwt cookie", () => {
    const { result } = renderHook(() => useSessionToken());
    expect(result.current).toBeNull();
  });

  it("re-renders subscribers when notifySessionChanged fires after the cookie changes", () => {
    const { result } = renderHook(() => useSessionToken());
    expect(result.current).toBeNull();

    document.cookie = "jwt=new.token.value; path=/";
    // Cookies emit no change event: without the notification the hook keeps
    // the value it last read.
    expect(result.current).toBeNull();

    act(() => notifySessionChanged());
    expect(result.current).toBe("new.token.value");

    clearJwtCookie();
    act(() => notifySessionChanged());
    expect(result.current).toBeNull();
  });

  it("is null in a server render even when the environment has a cookie", () => {
    document.cookie = "jwt=server.should.not.see; path=/";
    expect(renderToString(<TokenProbe />)).toContain("none");
  });
});

describe("useHydrated", () => {
  afterEach(cleanup);
  it("is false in a server render", () => {
    expect(renderToString(<HydrationProbe />)).toContain("pending");
  });

  it("is true once rendered on the client", () => {
    const { result } = renderHook(() => useHydrated());
    expect(result.current).toBe(true);
  });
});
