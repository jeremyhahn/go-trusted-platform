import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import * as authContext from "@/contexts/AuthContext";
import * as hooks from "./index";

// #216: the barrel once exported a second auth implementation with its own
// React context, so a consumer importing from one path never saw a provider
// mounted from the other. These tests pin the barrel to the one context.

function ContextProbe() {
  const { isAuthenticated } = authContext.useAuth();
  return <span data-testid="authed">{String(isAuthenticated)}</span>;
}

function BarrelProbe() {
  const { isAuthenticated } = hooks.useAuth();
  return <span data-testid="authed">{String(isAuthenticated)}</span>;
}

describe("hooks barrel auth exports", () => {
  afterEach(cleanup);

  it("re-exports the AuthContext implementation, not a copy", () => {
    expect(hooks.useAuth).toBe(authContext.useAuth);
    expect(hooks.useOptionalAuth).toBe(authContext.useOptionalAuth);
    expect(hooks.AuthProvider).toBe(authContext.AuthProvider);
  });

  it("a provider mounted through the barrel serves a context consumer", () => {
    render(
      <hooks.AuthProvider>
        <ContextProbe />
      </hooks.AuthProvider>
    );
    expect(screen.getByTestId("authed").textContent).toBe("false");
  });

  it("a barrel consumer outside any provider fails loudly", () => {
    expect(() => render(<BarrelProbe />)).toThrow(
      "useAuth must be used within an AuthProvider"
    );
  });
});
