import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { dismissToast, toast, useToast } from "./use-toast";

// The toast list is module state shared by every hook; each test leaves it
// empty by dismissing what it created.
const created: string[] = [];

function track(id: string): string {
  created.push(id);
  return id;
}

describe("useToast", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    act(() => {
      created.splice(0).forEach((id) => dismissToast(id));
    });
    cleanup();
    vi.useRealTimers();
  });

  it("starts with no toasts", () => {
    const { result } = renderHook(() => useToast());
    expect(result.current.toasts).toEqual([]);
  });

  it("adds a toast with a generated id and the default 5 s duration", () => {
    const { result } = renderHook(() => useToast());
    let id = "";
    act(() => {
      id = track(result.current.toast({ title: "Saved", description: "ok", variant: "success" }));
    });
    expect(id).toMatch(/^toast-\d+-[a-z0-9]+$/);
    expect(result.current.toasts).toEqual([
      { id, title: "Saved", description: "ok", variant: "success", duration: 5000 },
    ]);
  });

  it("gives every toast a distinct id", () => {
    const { result } = renderHook(() => useToast());
    let a = "";
    let b = "";
    act(() => {
      a = track(result.current.toast({ title: "a" }));
      b = track(result.current.toast({ title: "b" }));
    });
    expect(a).not.toBe(b);
    expect(result.current.toasts.map((t) => t.title)).toEqual(["a", "b"]);
  });

  it("auto-dismisses after the default duration", () => {
    const { result } = renderHook(() => useToast());
    act(() => {
      track(result.current.toast({ title: "brief" }));
    });
    act(() => vi.advanceTimersByTime(4999));
    expect(result.current.toasts).toHaveLength(1);
    act(() => vi.advanceTimersByTime(1));
    expect(result.current.toasts).toEqual([]);
  });

  it("honours a custom duration", () => {
    const { result } = renderHook(() => useToast());
    act(() => {
      track(result.current.toast({ title: "quick", duration: 100 }));
    });
    expect(result.current.toasts[0].duration).toBe(100);
    act(() => vi.advanceTimersByTime(100));
    expect(result.current.toasts).toEqual([]);
  });

  it.each([0, -1])("never auto-dismisses a toast with duration %i", (duration) => {
    const { result } = renderHook(() => useToast());
    act(() => {
      track(result.current.toast({ title: "sticky", duration }));
    });
    act(() => vi.advanceTimersByTime(60_000));
    expect(result.current.toasts).toHaveLength(1);
    expect(result.current.toasts[0].duration).toBe(duration);
  });

  it("accepts a toast with no fields", () => {
    const { result } = renderHook(() => useToast());
    act(() => {
      track(result.current.toast({}));
    });
    expect(result.current.toasts).toHaveLength(1);
    expect(result.current.toasts[0].title).toBeUndefined();
  });

  it("dismisses one toast by id and leaves the others", () => {
    const { result } = renderHook(() => useToast());
    let a = "";
    act(() => {
      a = track(result.current.toast({ title: "a", duration: 0 }));
      track(result.current.toast({ title: "b", duration: 0 }));
    });
    act(() => result.current.dismiss(a));
    expect(result.current.toasts.map((t) => t.title)).toEqual(["b"]);
  });

  it("ignores a dismiss of an unknown id", () => {
    const { result } = renderHook(() => useToast());
    act(() => {
      track(result.current.toast({ title: "kept", duration: 0 }));
    });
    act(() => result.current.dismiss("no-such-toast"));
    act(() => result.current.dismiss(""));
    expect(result.current.toasts).toHaveLength(1);
  });

  it("shares toasts between hook instances", () => {
    const first = renderHook(() => useToast());
    const second = renderHook(() => useToast());
    act(() => {
      track(first.result.current.toast({ title: "shared", duration: 0 }));
    });
    expect(second.result.current.toasts.map((t) => t.title)).toEqual(["shared"]);
  });

  it("picks up toasts that exist before it mounts", () => {
    act(() => {
      track(toast({ title: "earlier", duration: 0 }));
    });
    const { result } = renderHook(() => useToast());
    expect(result.current.toasts.map((t) => t.title)).toEqual(["earlier"]);
  });

  it("stops listening once unmounted", () => {
    const first = renderHook(() => useToast());
    const second = renderHook(() => useToast());
    first.unmount();
    act(() => {
      track(second.result.current.toast({ title: "after", duration: 0 }));
    });
    expect(first.result.current.toasts).toEqual([]);
    expect(second.result.current.toasts).toHaveLength(1);
  });

  it("keeps toast and dismiss stable across renders", () => {
    const { result, rerender } = renderHook(() => useToast());
    const { toast: t, dismiss: d } = result.current;
    rerender();
    expect(result.current.toast).toBe(t);
    expect(result.current.dismiss).toBe(d);
  });
});

describe("toast (standalone)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    act(() => {
      created.splice(0).forEach((id) => dismissToast(id));
    });
    cleanup();
    vi.useRealTimers();
  });

  it("reaches a mounted hook and applies the default duration", () => {
    const { result } = renderHook(() => useToast());
    let id = "";
    act(() => {
      id = track(toast({ title: "outside", variant: "destructive" }));
    });
    expect(result.current.toasts).toEqual([
      { id, title: "outside", variant: "destructive", duration: 5000 },
    ]);
    act(() => vi.advanceTimersByTime(5000));
    expect(result.current.toasts).toEqual([]);
  });

  it("does not auto-dismiss at duration 0", () => {
    const { result } = renderHook(() => useToast());
    act(() => {
      track(toast({ title: "sticky", duration: 0 }));
    });
    act(() => vi.advanceTimersByTime(60_000));
    expect(result.current.toasts).toHaveLength(1);
  });

  it("returns the same id that dismissToast removes", () => {
    const { result } = renderHook(() => useToast());
    let id = "";
    act(() => {
      id = track(toast({ title: "gone", duration: 0 }));
    });
    act(() => dismissToast(id));
    expect(result.current.toasts).toEqual([]);
  });

  it("dismissToast ignores an unknown id", () => {
    const { result } = renderHook(() => useToast());
    act(() => {
      track(toast({ title: "kept", duration: 0 }));
    });
    act(() => dismissToast("toast-0-unknown"));
    expect(result.current.toasts).toHaveLength(1);
  });
});
