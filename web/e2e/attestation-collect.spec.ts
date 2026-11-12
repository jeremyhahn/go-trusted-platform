import { test } from "@playwright/test";

// #1732 (epic #1665, slice 1): attestation collect, manifest verify and
// manifest delete, every REST operation reachable from the dashboard.
test.describe("Attestation collect and manifests", () => {
  test.fixme("VerifyManifest: POST /manifests/verify shows the verdict", async () => {});
  test.fixme("DeleteManifest: DELETE /manifests/{id} after confirm", async () => {});
  test.fixme("CollectHostAttestation: POST /host shows the result", async () => {});
  test.fixme("CollectVMAttestation: POST /vm/{id} shows the result", async () => {});
  test.fixme("CollectContainerAttestation: POST /container/{id} shows the result", async () => {});
});
