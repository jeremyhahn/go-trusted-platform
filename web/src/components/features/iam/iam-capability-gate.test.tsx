import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

// #2054: the IAM policy and app write controls carry the capability gate:
// each names its op and, when the server does not offer it, is disabled
// with the server's reason as its title.

const { off } = vi.hoisted(() => ({ off: new Set<string>() }));

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: "not-configured: iam" } : { enabled: true },
  }),
}));

import { PolicyValidateCard } from "./policy-validate-card";
import { PolicyTestCard } from "./policy-test-card";
import { PolicyEditCard } from "./policy-edit-card";
import { AppRenameForm } from "./app-rename-form";

const VALIDATE_OP = "POST /api/v1/iam/tenants/{tenant}/policies/validate";
const TEST_OP = "POST /api/v1/iam/tenants/{tenant}/policies/test";
const UPDATE_POLICY_OP = "PUT /api/v1/iam/tenants/{tenant}/policies/{id}";
const UPDATE_APP_OP = "PUT /api/v1/iam/tenants/{tenant}/apps/{id}";

afterEach(() => {
  cleanup();
  off.clear();
});

function expectGated(button: HTMLElement, op: string) {
  expect(button.getAttribute("data-capability-op")).toBe(op);
}

function expectOff(button: HTMLElement) {
  expect((button as HTMLButtonElement).disabled).toBe(true);
  expect(button.getAttribute("title")).toBe("not-configured: iam");
  expect(button.getAttribute("data-capability-enabled")).toBe("false");
}

describe("PolicyValidateCard capability gate", () => {
  it("names the validate op on its button", () => {
    render(<PolicyValidateCard specYaml="spec: {}" validate={vi.fn()} />);
    const button = screen.getByRole("button", { name: "Validate" });
    expectGated(button, VALIDATE_OP);
    expect((button as HTMLButtonElement).disabled).toBe(false);
  });

  it("disables Validate with the reason when the op is off", () => {
    off.add(VALIDATE_OP);
    const validate = vi.fn();
    render(<PolicyValidateCard specYaml="spec: {}" validate={validate} />);
    const button = screen.getByRole("button", { name: "Validate" });
    expectGated(button, VALIDATE_OP);
    expectOff(button);
    fireEvent.click(button);
    expect(validate).not.toHaveBeenCalled();
  });
});

describe("PolicyTestCard capability gate", () => {
  function fill() {
    fireEvent.change(screen.getByLabelText("Subject"), { target: { value: "user-1" } });
    fireEvent.change(screen.getByLabelText("Action"), { target: { value: "read" } });
    fireEvent.change(screen.getByLabelText("Resource"), { target: { value: "kv://a" } });
  }

  it("names the test op on its submit button", () => {
    render(<PolicyTestCard test={vi.fn()} />);
    fill();
    const button = screen.getByRole("button", { name: "Run test" });
    expectGated(button, TEST_OP);
    expect((button as HTMLButtonElement).disabled).toBe(false);
  });

  it("disables Run test with the reason when the op is off", () => {
    off.add(TEST_OP);
    const test = vi.fn();
    render(<PolicyTestCard test={test} />);
    fill();
    const button = screen.getByRole("button", { name: "Run test" });
    expectGated(button, TEST_OP);
    expectOff(button);
    fireEvent.click(button);
    expect(test).not.toHaveBeenCalled();
  });
});

describe("PolicyEditCard capability gate", () => {
  function renderCard(save = vi.fn()) {
    render(
      <PolicyEditCard
        initialDescription="d"
        initialPriority={1}
        initialSpecYaml="spec: {}"
        save={save}
        onSaved={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    return save;
  }

  it("names the update-policy op on Save", () => {
    renderCard();
    const button = screen.getByRole("button", { name: "Save" });
    expectGated(button, UPDATE_POLICY_OP);
    expect((button as HTMLButtonElement).disabled).toBe(false);
  });

  it("disables Save with the reason when the op is off", () => {
    off.add(UPDATE_POLICY_OP);
    const save = renderCard();
    const button = screen.getByRole("button", { name: "Save" });
    expectGated(button, UPDATE_POLICY_OP);
    expectOff(button);
    fireEvent.click(button);
    expect(save).not.toHaveBeenCalled();
  });
});

describe("AppRenameForm capability gate", () => {
  it("names the update-app op on Save", () => {
    render(<AppRenameForm name="billing" saving={false} onSave={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Application name"), { target: { value: "billing-2" } });
    const button = screen.getByRole("button", { name: "Save" });
    expectGated(button, UPDATE_APP_OP);
    expect((button as HTMLButtonElement).disabled).toBe(false);
  });

  it("disables Save with the reason when the op is off", () => {
    off.add(UPDATE_APP_OP);
    const onSave = vi.fn();
    render(<AppRenameForm name="billing" saving={false} onSave={onSave} />);
    fireEvent.change(screen.getByLabelText("Application name"), { target: { value: "billing-2" } });
    const button = screen.getByRole("button", { name: "Save" });
    expectGated(button, UPDATE_APP_OP);
    expectOff(button);
    fireEvent.click(button);
    expect(onSave).not.toHaveBeenCalled();
  });
});
