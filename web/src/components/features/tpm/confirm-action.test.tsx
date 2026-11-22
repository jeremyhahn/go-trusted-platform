import React from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ConfirmAction } from "./confirm-action";

/**
 * ConfirmAction guards destructive TPM actions: the action runs only on
 * Confirm, never on opening the dialog or on dismissing it.
 */

const TITLE = "Clear the TPM?";

function renderAction(onConfirm: () => void, disabled?: boolean) {
  return render(
    <ConfirmAction
      label="Clear TPM"
      title={TITLE}
      description="Erases all keys"
      onConfirm={onConfirm}
      disabled={disabled}
    />
  );
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name }));
  });
}

describe("ConfirmAction", () => {
  let onConfirm: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    onConfirm = vi.fn();
  });

  afterEach(() => {
    cleanup();
  });

  it("opening the dialog does not run the action", async () => {
    renderAction(onConfirm);
    await click("Clear TPM");

    expect(screen.queryByText(TITLE)).not.toBeNull();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("Cancel closes without running the action", async () => {
    renderAction(onConfirm);
    await click("Clear TPM");
    await click("Cancel");

    expect(screen.queryByText(TITLE)).toBeNull();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("Escape closes without running the action", async () => {
    renderAction(onConfirm);
    await click("Clear TPM");
    await act(async () => {
      fireEvent.keyDown(document.activeElement ?? document.body, { key: "Escape" });
    });

    expect(screen.queryByText(TITLE)).toBeNull();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("a disabled trigger does not open the dialog", async () => {
    renderAction(onConfirm, true);
    await click("Clear TPM");

    expect(screen.queryByText(TITLE)).toBeNull();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("Confirm runs the action exactly once and closes", async () => {
    renderAction(onConfirm);
    await click("Clear TPM");
    await click("Confirm");

    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(TITLE)).toBeNull();
  });
});
