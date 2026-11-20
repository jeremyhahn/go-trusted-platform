import { describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";

const tpmClient = { marker: "tpm" };
vi.mock("trusted-platform-sdk", () => ({ useTPM: () => tpmClient }));

import { operationError, useTPMKeyOperations } from "./use-tpm-key-operations";

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("operationError", () => {
  it("reads an Error, an error string and an error object, else the fallback", () => {
    expect(operationError(new Error("boom"), "fb")).toBe("boom");
    expect(operationError({ error: "refused" }, "fb")).toBe("refused");
    expect(operationError({ error: { message: "denied" } }, "fb")).toBe("denied");
    expect(operationError({ success: false }, "fb")).toBe("fb");
  });
});

describe("useTPMKeyOperations", () => {
  it("passes the SDK TPM client to the call and keeps the data it answers", async () => {
    const { result } = renderHook(() => useTPMKeyOperations());
    const call = vi.fn().mockResolvedValue({ success: true, data: { algorithms: ["RSA"] } });

    let returned: unknown;
    await act(async () => {
      returned = await result.current.run("capabilities", call);
    });

    expect(call).toHaveBeenCalledWith(tpmClient);
    expect(returned).toEqual({ algorithms: ["RSA"] });
    expect(result.current.results.capabilities).toEqual({ algorithms: ["RSA"] });
    expect(result.current.errors.capabilities).toBeUndefined();
    expect(result.current.pending).toBeNull();
  });

  it("records an in-band refusal as the operation's error and returns null", async () => {
    const { result } = renderHook(() => useTPMKeyOperations());
    let returned: unknown = "unset";
    await act(async () => {
      returned = await result.current.run("deleteAK", async () => ({
        success: false,
        error: { message: "refusing to evict the platform IAK" },
      }));
    });
    expect(returned).toBeNull();
    expect(result.current.errors.deleteAK).toBe("refusing to evict the platform IAK");
    expect(result.current.results.deleteAK).toBeUndefined();
  });

  it("records a thrown error, or the fallback, as the operation's error", async () => {
    const { result } = renderHook(() => useTPMKeyOperations());
    await act(async () => {
      await result.current.run("provision", async () => {
        throw new Error("network down");
      });
    });
    expect(result.current.errors.provision).toBe("network down");

    await act(async () => {
      await result.current.run("clear", async () => ({ success: false }));
    });
    expect(result.current.errors.clear).toBe("clear failed");
  });

  it("drops an operation's earlier result when a later run of it fails", async () => {
    const { result } = renderHook(() => useTPMKeyOperations());
    await act(async () => {
      await result.current.run("verifyQuote", async () => ({ success: true, data: { verified: true } }));
    });
    expect(result.current.results.verifyQuote).toEqual({ verified: true });

    await act(async () => {
      await result.current.run("verifyQuote", async () => ({ success: false, error: "quote signature invalid" }));
    });
    expect(result.current.errors.verifyQuote).toBe("quote signature invalid");
    // The stale "verified" answer must not stand beside the new failure.
    expect(result.current.results.verifyQuote).toBeUndefined();
  });

  it("clears an operation's earlier error when a later run of it succeeds", async () => {
    const { result } = renderHook(() => useTPMKeyOperations());
    await act(async () => {
      await result.current.run("getAK", async () => ({ success: false, error: "no AK" }));
    });
    expect(result.current.errors.getAK).toBe("no AK");
    await act(async () => {
      await result.current.run("getAK", async () => ({ success: true, data: { handle: 1 } }));
    });
    expect(result.current.errors.getAK).toBeUndefined();
    expect(result.current.results.getAK).toEqual({ handle: 1 });
  });

  it("keeps pending on an operation still in flight when another one finishes", async () => {
    const { result } = renderHook(() => useTPMKeyOperations());
    const slow = deferred<{ success: boolean; data: unknown }>();
    const fast = deferred<{ success: boolean; data: unknown }>();

    let slowRun: Promise<unknown> = Promise.resolve();
    let fastRun: Promise<unknown> = Promise.resolve();
    act(() => {
      slowRun = result.current.run("provision", () => slow.promise);
    });
    act(() => {
      fastRun = result.current.run("platform", () => fast.promise);
    });
    expect(result.current.pending).toBe("platform");

    await act(async () => {
      fast.resolve({ success: true, data: {} });
      await fastRun;
    });
    expect(result.current.pending).toBe("provision");

    await act(async () => {
      slow.resolve({ success: true, data: {} });
      await slowRun;
    });
    expect(result.current.pending).toBeNull();
  });
});
