import { test } from "@playwright/test";

// Issue #1737 (slice 12 of epic #1665): device templates, profile
// assignment and config lookup.
test.describe("Device templates", () => {
  test.fixme("CreateTemplate creates a template from the dialog", async () => {});
  test.fixme("GetTemplate shows a template's details", async () => {});
  test.fixme("UpdateTemplate saves an edited template", async () => {});
  test.fixme("DeleteTemplate removes a template after confirmation", async () => {});
  test.fixme("CreateProfileFromTemplate creates a profile from a template", async () => {});
  test.fixme("FindConfigForDevice looks up the config for a device", async () => {});
  test.fixme("AssignProfileToDevice assigns a profile to a device", async () => {});
  test.fixme("UnassignProfileFromDevice unassigns a profile after confirmation", async () => {});
});
