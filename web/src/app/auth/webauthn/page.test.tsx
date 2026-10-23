import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import WebAuthnUI from "./page";

// #643: registration begin reads the account address from "email" and the
// server refuses an address IAM would reject. These tests pin the form to
// that contract at the fetch boundary.

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => new URLSearchParams("status=not_registered"),
}));

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("WebAuthnUI registration form", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("asks for an email and sends it as the email field", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(400, { error: 'invalid email address: "jhahn"' })
    );
    render(<WebAuthnUI />);

    const input = await screen.findByLabelText("Email");
    expect(input.getAttribute("type")).toBe("email");
    expect(input.getAttribute("placeholder")).toBe("Enter your email");

    fireEvent.change(input, { target: { value: "jhahn@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Register" }));

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toMatch(/\/api\/v1\/webauthn\/registration\/begin$/);
    expect(JSON.parse(String(init?.body))).toEqual({ email: "jhahn@example.com" });
  });

  it("refuses to submit without an email", async () => {
    render(<WebAuthnUI />);

    fireEvent.click(await screen.findByRole("button", { name: "Register" }));

    expect(await screen.findByText("Please enter your email address.")).toBeTruthy();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
