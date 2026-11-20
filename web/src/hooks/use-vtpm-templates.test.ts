import { describe, expect, it } from "vitest";

// #2023 Codex r2: VTPMService.importBundle resolves with a camelCase
// VTPMBundle, so the hook must convert it to the snake_case wire shape the
// bundle views read; a bare cast left created_at, tpm_state and the manifest
// flags undefined.

import { bundleToWire, type VTPMBundle } from "./use-vtpm-templates";

const bundle = {
  id: "bundle-1",
  mode: "full",
  manifest: {
    version: "1",
    id: "bundle-1",
    mode: "full",
    hostname: "host-a",
    createdAt: "2026-11-20T00:00:00Z",
    ekAlgorithm: "ecc-p256",
    ekHandle: 0x81010001,
    secureBootEnabled: true,
    labels: { env: "dev" },
    clonedFrom: "bundle-0",
  },
  tpmState: {
    stateDir: "/var/lib/vtpm/bundle-1/tpm",
    permallFile: "/var/lib/vtpm/bundle-1/tpm/tpm2-00.permall",
    volatileFile: "/var/lib/vtpm/bundle-1/tpm/tpm2-00.volatilestate",
  },
  ovmfState: { nvramFile: "/var/lib/vtpm/bundle-1/OVMF_VARS.fd" },
  createdAt: "2026-11-20T00:00:00Z",
  clonedFrom: "bundle-0",
} as unknown as VTPMBundle;

describe("bundleToWire", () => {
  it("maps an imported bundle onto the wire fields", () => {
    const w = bundleToWire(bundle);

    expect(w.id).toBe("bundle-1");
    expect(w.created_at).toBe("2026-11-20T00:00:00Z");
    expect(w.cloned_from).toBe("bundle-0");
    expect(w.tpm_state?.state_dir).toBe("/var/lib/vtpm/bundle-1/tpm");
    expect(w.tpm_state?.permall_file).toBe("/var/lib/vtpm/bundle-1/tpm/tpm2-00.permall");
    expect(w.ovmf_state?.nvram_file).toBe("/var/lib/vtpm/bundle-1/OVMF_VARS.fd");
    expect(w.manifest?.secure_boot_enabled).toBe(true);
    expect(w.manifest?.ek_algorithm).toBe("ecc-p256");
    expect(w.manifest?.ek_handle).toBe(0x81010001);
    expect(w.manifest?.created_at).toBe("2026-11-20T00:00:00Z");
    expect(w.manifest?.cloned_from).toBe("bundle-0");
    expect(w.manifest?.labels).toEqual({ env: "dev" });
  });

  // #2023 Codex r2: importBundle resolves with SDK BundleMode names; the
  // list, get and clone results carry the wire names, so imports must too.
  it("converts SDK bundle modes to their wire names", () => {
    const sdkBundle = {
      ...(bundle as unknown as Record<string, unknown>),
      mode: "PRE_ASSIGNED",
      manifest: { ...(bundle.manifest as unknown as Record<string, unknown>), mode: "PRE_ASSIGNED" },
    } as unknown as VTPMBundle;
    const w = bundleToWire(sdkBundle);

    expect(w.mode).toBe("pre-assigned");
    expect(w.manifest?.mode).toBe("pre-assigned");
  });

  it("maps the TEMPLATE mode to template", () => {
    const sdkBundle = { ...(bundle as unknown as Record<string, unknown>), mode: "TEMPLATE" } as unknown as VTPMBundle;
    expect(bundleToWire(sdkBundle).mode).toBe("template");
  });
});
