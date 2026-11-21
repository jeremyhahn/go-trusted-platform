import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";

import {
  ok,
  refused,
  stubControlPlane,
  withControlPlane,
} from "@/test/control-plane-fetch";

import { useAttestationCollect } from "./use-attestation-collect";

function wrapper({ children }: { children: ReactNode }) {
  return withControlPlane(children);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("useAttestationCollect", () => {
  it("collectHost sends one POST to the host collect route", async () => {
    const sent = stubControlPlane({
      "POST /api/v1/attestation/host": ok({ status: "ATTESTATION_STATUS_SUCCESS" }),
    });
    const { result } = renderHook(() => useAttestationCollect(), { wrapper });

    const res = await result.current.collectHost({
      config: { pcrIndices: [7] },
      nonce: "bg==",
    });

    expect(res.success).toBe(true);
    expect(sent).toHaveLength(1);
    expect(sent[0].method).toBe("POST");
    expect(sent[0].path).toBe("/api/v1/attestation/host");
    expect(sent[0].body).toEqual({ config: { pcrIndices: [7] }, nonce: "bg==" });
  });

  it("collectVM sends one POST to the vm collect route", async () => {
    const sent = stubControlPlane({
      "POST /api/v1/attestation/vm/vm-1": ok({ vm_id: "vm-1", verified: true }),
    });
    const { result } = renderHook(() => useAttestationCollect(), { wrapper });

    const res = await result.current.collectVM({
      vmId: "vm-1",
      config: { pcrIndices: [7] },
      nonce: "bg==",
    });

    expect(res.success).toBe(true);
    expect(sent).toHaveLength(1);
    expect(sent[0].method).toBe("POST");
    expect(sent[0].path).toBe("/api/v1/attestation/vm/vm-1");
    expect(sent[0].body).toEqual({
      vmId: "vm-1",
      config: { pcrIndices: [7] },
      nonce: "bg==",
    });
  });

  it("collectContainer sends one POST to the container collect route", async () => {
    const sent = stubControlPlane({
      "POST /api/v1/attestation/container/c-1": ok({ container_id: "c-1", verified: true }),
    });
    const { result } = renderHook(() => useAttestationCollect(), { wrapper });

    const res = await result.current.collectContainer({ containerId: "c-1" });

    expect(res.success).toBe(true);
    expect(sent).toHaveLength(1);
    expect(sent[0].method).toBe("POST");
    expect(sent[0].path).toBe("/api/v1/attestation/container/c-1");
    expect(sent[0].body).toEqual({ containerId: "c-1" });
  });

  it("returns the refusal when the host route answers 403", async () => {
    stubControlPlane({
      "POST /api/v1/attestation/host": refused(403, "caller not admitted"),
    });
    const { result } = renderHook(() => useAttestationCollect(), { wrapper });

    const res = await result.current.collectHost({
      config: { pcrIndices: [7] },
      nonce: "bg==",
    });

    expect(res.success).toBe(false);
    expect(res.error?.status).toBe(403);
  });
});
