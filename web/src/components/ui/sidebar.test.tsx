import { act } from "@testing-library/react";
import { hydrateRoot, type Root } from "react-dom/client";
import { renderToString } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SidebarProvider, SidebarTrigger, useSidebar } from "./sidebar";

function Probe() {
  const { state } = useSidebar();
  return (
    <>
      <span data-testid="state">{state}</span>
      <SidebarTrigger />
    </>
  );
}

function tree(defaultOpen: boolean) {
  return (
    <SidebarProvider defaultOpen={defaultOpen}>
      <Probe />
    </SidebarProvider>
  );
}

let root: Root | null = null;
let container: HTMLDivElement | null = null;
let consoleError: ReturnType<typeof vi.spyOn>;

function hydrate(defaultOpen: boolean) {
  const html = renderToString(tree(defaultOpen));
  container = document.createElement("div");
  container.innerHTML = html;
  document.body.appendChild(container);
  const serverState = container.querySelector('[data-testid="state"]')
    ?.textContent;
  act(() => {
    root = hydrateRoot(container as HTMLDivElement, tree(defaultOpen));
  });
  return serverState;
}

function probeState() {
  return container?.querySelector('[data-testid="state"]')?.textContent;
}

function clickTrigger() {
  const button = Array.from(
    container?.querySelectorAll("button") ?? []
  ).find((b) => b.textContent?.includes("Toggle Sidebar"));
  expect(button).toBeDefined();
  act(() => {
    button?.click();
  });
}

describe("SidebarProvider cookie restore", () => {
  beforeEach(() => {
    document.cookie = "sidebar:state=; path=/; max-age=0";
    window.innerWidth = 1024;
    consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    act(() => {
      root?.unmount();
    });
    root = null;
    container?.remove();
    container = null;
    consoleError.mockRestore();
    document.cookie = "sidebar:state=; path=/; max-age=0";
  });

  it("restores a collapsed cookie over defaultOpen true without a hydration mismatch", () => {
    document.cookie = "sidebar:state=false; path=/";
    const serverState = hydrate(true);
    expect(serverState).toBe("expanded");
    expect(probeState()).toBe("collapsed");
    expect(consoleError).not.toHaveBeenCalled();
  });

  it("restores an expanded cookie over defaultOpen false", () => {
    document.cookie = "sidebar:state=true; path=/";
    const serverState = hydrate(false);
    expect(serverState).toBe("collapsed");
    expect(probeState()).toBe("expanded");
    expect(consoleError).not.toHaveBeenCalled();
  });

  it("keeps defaultOpen when no cookie is set", () => {
    hydrate(true);
    expect(probeState()).toBe("expanded");
    expect(consoleError).not.toHaveBeenCalled();
  });

  it("a toggle after restore persists and keeps the new state", () => {
    document.cookie = "sidebar:state=false; path=/";
    hydrate(true);
    expect(probeState()).toBe("collapsed");

    clickTrigger();
    expect(probeState()).toBe("expanded");
    expect(document.cookie).toContain("sidebar:state=true");

    clickTrigger();
    expect(probeState()).toBe("collapsed");
    expect(document.cookie).toContain("sidebar:state=false");
    expect(consoleError).not.toHaveBeenCalled();
  });
});
