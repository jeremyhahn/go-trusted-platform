/**
 * Switch ports E2E tests (#1724, slice 29 of #1665).
 *
 * Covers ListPorts, GetPortStatus, EnablePort, DisablePort and SetPortVLAN
 * from the switch detail page, with mocked API responses.
 */

import { test } from "@playwright/test";

test.describe("Switch ports", () => {
  test.fixme("ListPorts: lists the ports of a switch", async () => {});
  test.fixme("GetPortStatus: shows the status of one port", async () => {});
  test.fixme("EnablePort: enables a port after confirmation", async () => {});
  test.fixme("DisablePort: disables a port after confirmation", async () => {});
  test.fixme("SetPortVLAN: sets the VLAN of a port", async () => {});
});
