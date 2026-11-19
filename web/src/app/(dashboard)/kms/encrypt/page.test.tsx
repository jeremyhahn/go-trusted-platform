import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import EncryptPage from "./page";

describe("EncryptPage", () => {
  afterEach(() => {
    cleanup();
  });

  it("renders the page heading and description", () => {
    render(<EncryptPage />);
    const heading = screen.getByRole("heading", { level: 1 });
    expect(heading.textContent).toBe("Encryption Operations");
    expect(
      screen.getByText("Encrypt and decrypt data using KMS cryptographic keys"),
    ).toBeTruthy();
  });

  it("marks the feature as under development", () => {
    render(<EncryptPage />);
    expect(screen.getByText("This feature is under development")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Coming Soon" })).toBeTruthy();
  });

  it("lists the four planned operations", () => {
    render(<EncryptPage />);
    for (const title of [
      "Encrypt Data",
      "Decrypt Data",
      "Generate Data Key",
      "Wrap/Unwrap Key",
    ]) {
      expect(screen.getByText(title)).toBeTruthy();
    }
  });

  it("disables every operation button so nothing can be run yet", () => {
    render(<EncryptPage />);
    const buttons = screen.getAllByRole("button");
    expect(buttons.map((b) => b.textContent?.trim())).toEqual([
      "Encrypt",
      "Decrypt",
      "Generate",
      "Wrap Key",
    ]);
    for (const b of buttons) {
      expect((b as HTMLButtonElement).disabled).toBe(true);
    }
  });

  it("renders no form inputs that could accept plaintext", () => {
    const { container } = render(<EncryptPage />);
    expect(container.querySelectorAll("input, textarea, select")).toHaveLength(0);
  });
});
