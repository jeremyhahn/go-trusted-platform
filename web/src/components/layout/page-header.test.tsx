import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { PageHeader } from "./page-header";

// #1819: unit tests for the page title block: heading, optional
// description, actions (preferred over children) and passthrough props.

function root(container: HTMLElement): HTMLElement {
  return container.firstElementChild as HTMLElement;
}

describe("PageHeader", () => {
  afterEach(() => {
    cleanup();
  });

  it("renders the title as the page heading", () => {
    render(<PageHeader title="Certificates" />);

    const heading = screen.getByRole("heading", { level: 1 });
    expect(heading.textContent).toBe("Certificates");
  });

  it("renders only the heading when nothing else is given", () => {
    const { container } = render(<PageHeader title="Devices" />);

    const el = root(container);
    expect(el.children.length).toBe(1);
    expect(el.querySelector("p")).toBeNull();
  });

  it("renders an empty heading for an empty title", () => {
    render(<PageHeader title="" />);

    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("");
  });

  it("renders the description under the title", () => {
    render(<PageHeader title="Keys" description="Keys held by the KMS" />);

    expect(screen.getByText("Keys held by the KMS").tagName).toBe("P");
  });

  it("omits an empty description", () => {
    const { container } = render(<PageHeader title="Keys" description="" />);

    expect(container.querySelector("p")).toBeNull();
  });

  it("renders the actions", () => {
    render(<PageHeader title="Users" actions={<button>Add user</button>} />);

    expect(screen.getByRole("button", { name: "Add user" })).toBeTruthy();
  });

  it("renders children when no actions are given", () => {
    render(
      <PageHeader title="Users">
        <button>Invite</button>
      </PageHeader>
    );

    expect(screen.getByRole("button", { name: "Invite" })).toBeTruthy();
  });

  it("prefers actions over children", () => {
    render(
      <PageHeader title="Users" actions={<button>Add user</button>}>
        <button>Invite</button>
      </PageHeader>
    );

    expect(screen.getByRole("button", { name: "Add user" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Invite" })).toBeNull();
  });

  it("renders no action area for null actions and no children", () => {
    const { container } = render(<PageHeader title="Users" actions={null} />);

    expect(root(container).children.length).toBe(1);
  });

  it("merges a caller class name with the layout classes", () => {
    const { container } = render(
      <PageHeader title="Users" className="custom-header" />
    );

    const el = root(container);
    expect(el.classList.contains("custom-header")).toBe(true);
    expect(el.classList.contains("flex")).toBe(true);
    expect(el.classList.contains("justify-between")).toBe(true);
  });

  it("lets a caller margin replace the default margin", () => {
    const { container } = render(<PageHeader title="Users" className="mb-2" />);

    const el = root(container);
    expect(el.classList.contains("mb-2")).toBe(true);
    expect(el.classList.contains("mb-6")).toBe(false);
  });

  it("passes other attributes through to the root element", () => {
    const { container } = render(
      <PageHeader title="Users" id="users-header" data-testid="page-header" />
    );

    const el = screen.getByTestId("page-header");
    expect(el).toBe(root(container));
    expect(el.id).toBe("users-header");
  });

  it("does not set the title as a tooltip attribute on the root", () => {
    const { container } = render(<PageHeader title="Users" />);

    expect(root(container).hasAttribute("title")).toBe(false);
  });
});
