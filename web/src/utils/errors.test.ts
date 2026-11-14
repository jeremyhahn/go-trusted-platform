import { describe, expect, it } from "vitest";

import { errorMessage } from "./errors";

describe("errorMessage", () => {
  it("returns the message of an Error", () => {
    expect(errorMessage(new Error("boom"), "fallback")).toBe("boom");
  });

  it("returns the message of an Error subclass", () => {
    expect(errorMessage(new TypeError("bad type"), "fallback")).toBe("bad type");
  });

  it("returns the fallback for an Error with an empty message", () => {
    expect(errorMessage(new Error(""), "fallback")).toBe("fallback");
  });

  it("returns a non-empty string as is", () => {
    expect(errorMessage("plain", "fallback")).toBe("plain");
  });

  it("returns the fallback for an empty string", () => {
    expect(errorMessage("", "fallback")).toBe("fallback");
  });

  it.each([
    ["undefined", undefined],
    ["null", null],
    ["a number", 42],
    ["a boolean", false],
    ["a plain object with a message", { message: "not an Error" }],
    ["an array", ["x"]],
  ])("returns the fallback for %s", (_name, value) => {
    expect(errorMessage(value, "fallback")).toBe("fallback");
  });

  it("returns an empty fallback when that is what it is given", () => {
    expect(errorMessage(undefined, "")).toBe("");
  });
});
