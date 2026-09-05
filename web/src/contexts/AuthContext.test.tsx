import { act, cleanup, render, screen } from "@testing-library/react";
import { renderToString } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";

import { AuthProvider, useAuth } from "./AuthContext";

/** Build an unsigned JWT whose payload decodeJWT will accept. */
function jwtFor(payload: Record<string, unknown>): string {
  const b64 = (o: Record<string, unknown>) =>
    Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "none", typ: "JWT" })}.${b64(payload)}.sig`;
}

const validPayload = {
  sub: "user-1",
  email: "user@example.com",
  tenant_id: "tenant-9",
  is_tenant_owner: true,
  roles: ["admin"],
  exp: Math.floor(Date.now() / 1000) + 3600,
};

function clearJwtCookie(): void {
  document.cookie = "jwt=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
}

// vitest runs without testing-library globals, so unmount explicitly.
function resetDom(): void {
  cleanup();
  clearJwtCookie();
}

function Probe() {
  const { isLoading, isAuthenticated, user, tenantId } = useAuth();
  return (
    <div>
      <span data-testid="loading">{String(isLoading)}</span>
      <span data-testid="authed">{String(isAuthenticated)}</span>
      <span data-testid="email">{user?.email ?? "-"}</span>
      <span data-testid="tenant">{tenantId ?? "-"}</span>
    </div>
  );
}

function LoginButton({ token }: { token: string }) {
  const { login, logout } = useAuth();
  return (
    <>
      <button onClick={() => login(token)}>login</button>
      <button onClick={() => logout()}>logout</button>
    </>
  );
}

describe("AuthProvider", () => {
  afterEach(resetDom);

  it("is loading with no user during a server render, even if a cookie exists", () => {
    document.cookie = `jwt=${jwtFor(validPayload)}; path=/`;
    const html = renderToString(
      <AuthProvider>
        <Probe />
      </AuthProvider>
    );
    expect(html).toContain('data-testid="loading">true<');
    expect(html).toContain('data-testid="authed">false<');
  });

  it("derives the user from the jwt cookie once rendered on the client", () => {
    document.cookie = `jwt=${jwtFor(validPayload)}; path=/`;
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>
    );
    expect(screen.getByTestId("loading").textContent).toBe("false");
    expect(screen.getByTestId("authed").textContent).toBe("true");
    expect(screen.getByTestId("email").textContent).toBe("user@example.com");
    expect(screen.getByTestId("tenant").textContent).toBe("tenant-9");
  });

  it("is not loading and not authenticated on the client without a cookie", () => {
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>
    );
    expect(screen.getByTestId("loading").textContent).toBe("false");
    expect(screen.getByTestId("authed").textContent).toBe("false");
    expect(screen.getByTestId("email").textContent).toBe("-");
  });

  it("login and logout update every consumer through the session store", () => {
    render(
      <AuthProvider>
        <Probe />
        <LoginButton token={jwtFor(validPayload)} />
      </AuthProvider>
    );
    expect(screen.getByTestId("authed").textContent).toBe("false");

    act(() => screen.getByText("login").click());
    expect(screen.getByTestId("authed").textContent).toBe("true");
    expect(screen.getByTestId("email").textContent).toBe("user@example.com");

    act(() => screen.getByText("logout").click());
    expect(screen.getByTestId("authed").textContent).toBe("false");
    expect(screen.getByTestId("email").textContent).toBe("-");
  });

  it("treats a malformed token as no user", () => {
    document.cookie = "jwt=not.a.jwt; path=/";
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>
    );
    expect(screen.getByTestId("loading").textContent).toBe("false");
    expect(screen.getByTestId("authed").textContent).toBe("false");
  });
});
