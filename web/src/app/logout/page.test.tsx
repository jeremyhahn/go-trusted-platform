import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import LogoutPage from "./page";

const logout = vi.fn(() => Promise.resolve("revoked"));
const localLogout = vi.fn();
let search = "";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(search),
}));

vi.mock("@/hooks/use-logout", () => ({
  useLogout: () => logout,
  useLocalLogout: () => localLogout,
}));

// #646: a sign-out the server did not confirm is shown with a retry, not
// hidden behind a silent redirect.
describe("LogoutPage", () => {
  beforeEach(() => {
    logout.mockClear();
    localLogout.mockClear();
  });

  afterEach(cleanup);

  it("signs out on mount when there is no failed revocation", async () => {
    search = "";
    render(<LogoutPage />);

    await vi.waitFor(() => expect(logout).toHaveBeenCalledTimes(1));
  });

  it("offers a retry and a browser-only sign-out after a failed revocation", async () => {
    search = "revocation=failed";
    render(<LogoutPage />);

    expect(
      await screen.findByText(/The server did not confirm your sign-out/),
    ).toBeTruthy();
    expect(logout).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Retry sign-out" }));
    expect(logout).toHaveBeenCalledTimes(1);

    fireEvent.click(
      screen.getByRole("button", { name: "Sign out of this browser only" }),
    );
    expect(localLogout).toHaveBeenCalledTimes(1);
  });
});
