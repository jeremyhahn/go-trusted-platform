import { describe, expect, it } from "vitest";

import { resolveDynamicId } from "./dynamic-route";

const PLACEHOLDER = "__placeholder__";

describe("resolveDynamicId", () => {
  it("returns the id from params", () => {
    expect(resolveDynamicId({ id: "abc" }, "/devices/other", "devices")).toBe("abc");
  });

  it("returns the first element of an array param", () => {
    expect(resolveDynamicId({ id: ["first", "second"] }, null, "devices")).toBe(
      "first",
    );
  });

  it("uses a custom param name", () => {
    expect(
      resolveDynamicId({ id: "wrong", zoneId: "z1" }, null, "zones", "zoneId"),
    ).toBe("z1");
  });

  it("falls back to the pathname when params hold the placeholder", () => {
    expect(
      resolveDynamicId({ id: PLACEHOLDER }, "/devices/dev-1/edit", "devices"),
    ).toBe("dev-1");
  });

  it("falls back to the pathname when the array param holds the placeholder", () => {
    expect(
      resolveDynamicId({ id: [PLACEHOLDER] }, "/devices/dev-1", "devices"),
    ).toBe("dev-1");
  });

  it.each([
    ["missing", {}],
    ["undefined", { id: undefined }],
    ["empty", { id: "" }],
    ["an empty array", { id: [] }],
  ])("falls back to the pathname when the param is %s", (_name, params) => {
    expect(resolveDynamicId(params, "/devices/dev-1", "devices")).toBe("dev-1");
  });

  it.each([
    ["null", null],
    ["undefined", undefined],
  ])("falls back to the pathname when params are %s", (_name, params) => {
    expect(resolveDynamicId(params, "/devices/dev-1", "devices")).toBe("dev-1");
  });

  it("URL-decodes the pathname segment", () => {
    expect(resolveDynamicId(null, "/zones/a%20b%2Fc", "zones")).toBe("a b/c");
  });

  it("ignores empty path segments", () => {
    expect(resolveDynamicId(null, "//devices//dev-1/", "devices")).toBe("dev-1");
  });

  it("uses the first occurrence of the parent segment", () => {
    expect(resolveDynamicId(null, "/devices/one/devices/two", "devices")).toBe(
      "one",
    );
  });

  it("returns an empty string when the pathname segment is the placeholder", () => {
    expect(
      resolveDynamicId(null, `/devices/${PLACEHOLDER}`, "devices"),
    ).toBe("");
  });

  it("returns an empty string when the parent segment is last", () => {
    expect(resolveDynamicId(null, "/devices", "devices")).toBe("");
  });

  it("returns an empty string when the parent segment is absent", () => {
    expect(resolveDynamicId(null, "/zones/z1", "devices")).toBe("");
  });

  it.each([
    ["null", null],
    ["undefined", undefined],
    ["empty", ""],
  ])("returns an empty string when the pathname is %s", (_name, pathname) => {
    expect(resolveDynamicId(null, pathname, "devices")).toBe("");
  });

  it("does not match the parent segment as a substring", () => {
    expect(resolveDynamicId(null, "/my-devices/dev-1", "devices")).toBe("");
  });

  it("throws on a malformed percent-encoding in the pathname", () => {
    expect(() => resolveDynamicId(null, "/devices/%E0%A4%A", "devices")).toThrow(
      URIError,
    );
  });
});
