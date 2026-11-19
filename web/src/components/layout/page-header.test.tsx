import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { PageHeader } from "./page-header";

describe("PageHeader", () => {
  afterEach(() => {
    cleanup();
  });

  it("renders the title as the page heading", () => {
    render(<PageHeader title="Certificates" />);
    const heading = screen.getByRole("heading", { level: 1 });
    expect(heading.textContent).toBe("Certificates");
  });

  it("renders the description when given", () => {
    render(<PageHeader title="Keys" description="Manage TPM keys" />);
    expect(screen.getByText("Manage TPM keys").tagName).toBe("P");
  });

  it("omits the description paragraph when it is missing or empty", () => {
    const { container, rerender } = render(<PageHeader title="Keys" />);
    expect(container.querySelector("p")).toBeNull();
    rerender(<PageHeader title="Keys" description="" />);
    expect(container.querySelector("p")).toBeNull();
  });

  it("renders an empty heading for an empty title", () => {
    render(<PageHeader title="" />);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("");
  });

  it("renders actions in the actions area", () => {
    render(<PageHeader title="Users" actions={<button type="button">Add user</button>} />);
    expect(screen.getByRole("button", { name: "Add user" })).toBeTruthy();
  });

  it("renders children when no actions are given", () => {
    render(
      <PageHeader title="Users">
        <button type="button">Invite</button>
      </PageHeader>,
    );
    expect(screen.getByRole("button", { name: "Invite" })).toBeTruthy();
  });

  it("prefers actions over children when both are given", () => {
    render(
      <PageHeader title="Users" actions={<button type="button">Add user</button>}>
        <button type="button">Invite</button>
      </PageHeader>,
    );
    expect(screen.getByRole("button", { name: "Add user" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Invite" })).toBeNull();
  });

  it("renders no actions area without actions or children", () => {
    const { container } = render(<PageHeader title="Users" />);
    const root = container.firstElementChild as HTMLElement;
    expect(root.children).toHaveLength(1);
  });

  it("renders no actions area for falsy actions and children", () => {
    const { container } = render(
      <PageHeader title="Users" actions={null}>
        {false}
      </PageHeader>,
    );
    const root = container.firstElementChild as HTMLElement;
    expect(root.children).toHaveLength(1);
  });

  it("merges a custom class name with its own classes", () => {
    const { container } = render(<PageHeader title="Users" className="custom-header" />);
    const root = container.firstElementChild as HTMLElement;
    expect(root.classList.contains("custom-header")).toBe(true);
    expect(root.classList.contains("flex")).toBe(true);
  });

  it("passes other HTML attributes through to the root element", () => {
    const { container } = render(
      <PageHeader title="Users" id="users-header" data-testid="page-header" aria-live="polite" />,
    );
    const root = screen.getByTestId("page-header");
    expect(root).toBe(container.firstElementChild);
    expect(root.id).toBe("users-header");
    expect(root.getAttribute("aria-live")).toBe("polite");
  });
});
