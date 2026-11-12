import { test } from "@playwright/test";

// KMS operations page (#1734, slice 20 of #1665): one test per REST operation.
test.describe("KMS operations", () => {
  test.fixme("imports a key", async () => {});
  test.fixme("updates key status behind a confirm dialog", async () => {});
  test.fixme("lists key versions", async () => {});
  test.fixme("batch encrypts", async () => {});
  test.fixme("batch decrypts", async () => {});
  test.fixme("hashes data", async () => {});
  test.fixme("computes an HMAC", async () => {});
  test.fixme("verifies an HMAC", async () => {});
  test.fixme("generates random bytes", async () => {});
  test.fixme("generates a data key", async () => {});
  test.fixme("generates a wrapped data key", async () => {});
  test.fixme("shows backend status", async () => {});
});
