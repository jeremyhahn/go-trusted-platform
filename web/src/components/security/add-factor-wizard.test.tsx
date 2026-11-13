import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AuthFactor } from "@/types/auth-factors";
import { AddFactorWizard } from "./add-factor-wizard";

// #1820: unit tests for the add-factor wizard. The factors API is mocked;
// FIDO2 is reported unavailable (jsdom has no WebAuthn).

const api = vi.hoisted(() => ({
  add: vi.fn(),
  rotate: vi.fn(),
  fido2: vi.fn(() => false),
}));

vi.mock("@/utils/auth-factors-api", () => ({
  authFactorsApi: { add: api.add, rotate: api.rotate },
  isFIDO2Available: api.fido2,
}));

const PEM = "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n";

const added: AuthFactor = {
  id: "f-1",
  user_id: "user-7",
  type: "mtls",
  label: "Work laptop",
  metadata: {},
  registered_at: "2026-11-01T00:00:00Z",
  last_used_at: null,
  revoked_at: null,
  created_by: "self",
};

function renderWizard(
  props: Partial<React.ComponentProps<typeof AddFactorWizard>> = {}
) {
  const onOpenChange = vi.fn();
  const onAdded = vi.fn();
  render(
    <AddFactorWizard
      open
      onOpenChange={onOpenChange}
      userId="user-7"
      onAdded={onAdded}
      {...props}
    />
  );
  return { onOpenChange, onAdded };
}

function next() {
  return screen.getByRole("button", { name: /^(Next|Add factor)$/ });
}

async function uploadPEM() {
  fireEvent.click(screen.getByLabelText("Upload existing cert"));
  const file = new File([PEM], "cert.pem", { type: "application/x-pem-file" });
  fireEvent.change(screen.getByLabelText("Select PEM file"), {
    target: { files: [file] },
  });
  await screen.findByText(/BEGIN CERTIFICATE/);
}

describe("AddFactorWizard", () => {
  beforeEach(() => {
    api.add.mockReset();
    api.rotate.mockReset();
    api.fido2.mockReturnValue(false);
  });

  afterEach(() => {
    cleanup();
  });

  it("starts on the type step with Next disabled until a type is picked", () => {
    renderWizard();
    expect(screen.getByText("Add authentication factor")).toBeTruthy();
    expect(screen.getByLabelText("Step 1 of 4")).toBeTruthy();
    expect(next()).toHaveProperty("disabled", true);
    expect(screen.queryByRole("button", { name: "Back" })).toBeNull();

    fireEvent.click(screen.getByLabelText("mTLS Certificate"));
    expect(next()).toHaveProperty("disabled", false);
  });

  it("disables PIV always and FIDO2 when WebAuthn is unavailable", () => {
    renderWizard();
    expect(screen.getByLabelText("PIV Smartcard")).toHaveProperty("disabled", true);
    expect(screen.getByLabelText("FIDO2 / Passkey")).toHaveProperty("disabled", true);
    expect(screen.getByText("WebAuthn not available on this device.")).toBeTruthy();
  });

  it("enables FIDO2 when WebAuthn is available", () => {
    api.fido2.mockReturnValue(true);
    renderWizard();
    expect(screen.getByLabelText("FIDO2 / Passkey")).toHaveProperty("disabled", false);
    fireEvent.click(screen.getByLabelText("FIDO2 / Passkey"));
    expect(next()).toHaveProperty("disabled", false);
  });

  it("adds an uploaded mTLS cert and reports the new factor", async () => {
    api.add.mockResolvedValue({ ok: true, data: { factor: added } });
    const { onAdded, onOpenChange } = renderWizard();

    fireEvent.click(screen.getByLabelText("mTLS Certificate"));
    fireEvent.click(next());
    expect(screen.getByLabelText("Step 2 of 4")).toBeTruthy();
    expect(next()).toHaveProperty("disabled", true);

    await uploadPEM();
    fireEvent.click(next());

    expect(screen.getByLabelText("Step 3 of 4")).toBeTruthy();
    const label = screen.getByLabelText("Label");
    expect(label.getAttribute("placeholder")).toBe("Work laptop cert");
    expect(next()).toHaveProperty("disabled", true);
    fireEvent.change(label, { target: { value: "   " } });
    expect(next()).toHaveProperty("disabled", true);
    fireEvent.change(label, { target: { value: "Work laptop" } });
    expect(next().textContent).toContain("Add factor");
    fireEvent.click(next());

    expect(await screen.findByText("Factor added successfully")).toBeTruthy();
    expect(screen.getByText("Factor added")).toBeTruthy();
    expect(screen.getByText("Self-issued (mTLS)")).toBeTruthy();
    expect(api.add).toHaveBeenCalledWith("user-7", {
      type: "mtls",
      label: "Work laptop",
      cert_pem: PEM,
      webauthn_response: undefined,
    });
    expect(api.rotate).not.toHaveBeenCalled();
    expect(onAdded).toHaveBeenCalledWith(added);

    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("goes back a step and clears the cert when the mTLS source changes", async () => {
    renderWizard();
    fireEvent.click(screen.getByLabelText("mTLS Certificate"));
    fireEvent.click(next());
    await uploadPEM();
    expect(next()).toHaveProperty("disabled", false);

    fireEvent.click(screen.getByLabelText("Generate new cert"));
    expect(screen.queryByText(/BEGIN CERTIFICATE/)).toBeNull();
    expect(next()).toHaveProperty("disabled", true);

    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByLabelText("Step 1 of 4")).toBeTruthy();
    expect(screen.getByLabelText("mTLS Certificate")).toHaveProperty("checked", true);
  });

  it("shows the API error and stays on the label step", async () => {
    api.add.mockResolvedValue({ ok: false, error: "label already in use", status: 409 });
    const { onAdded } = renderWizard();

    fireEvent.click(screen.getByLabelText("mTLS Certificate"));
    fireEvent.click(next());
    await uploadPEM();
    fireEvent.click(next());
    fireEvent.change(screen.getByLabelText("Label"), { target: { value: "dup" } });
    fireEvent.click(next());

    expect(await screen.findByText("label already in use")).toBeTruthy();
    expect(screen.getByLabelText("Step 3 of 4")).toBeTruthy();
    expect(onAdded).not.toHaveBeenCalled();
  });

  it("rotates an existing factor from the cert step without a Back button", async () => {
    api.rotate.mockResolvedValue({ ok: true, data: { factor: added } });
    const { onAdded } = renderWizard({
      rotateFactorId: "f-1",
      rotateFactorType: "mtls",
    });

    expect(screen.getByText("Rotate authentication factor")).toBeTruthy();
    expect(screen.getByLabelText("Step 2 of 4")).toBeTruthy();
    await uploadPEM();
    expect(screen.queryByRole("button", { name: "Back" })).toBeNull();
    fireEvent.click(next());
    fireEvent.change(screen.getByLabelText("Label"), { target: { value: "Rotated" } });
    fireEvent.click(next());

    expect(await screen.findByText("Factor added successfully")).toBeTruthy();
    expect(api.rotate).toHaveBeenCalledWith("user-7", {
      factor_id: "f-1",
      cert_pem: PEM,
      webauthn_response: undefined,
    });
    expect(api.add).not.toHaveBeenCalled();
    expect(onAdded).toHaveBeenCalledWith(added);
  });

  it("renders nothing while closed", () => {
    renderWizard({ open: false });
    expect(screen.queryByText("Add authentication factor")).toBeNull();
  });
});
