import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import TPMNVRAMPage from "./page";

// #1824: the page lists the NV indices from GET /api/v1/tpm/info through the
// real useApi hook and runs read, define, write and undefine through the TPM
// service; only the service and the toast are stubbed.

const tpm = {
  getInfo: vi.fn(),
  readNVRAM: vi.fn(),
  defineNVRAM: vi.fn(),
  writeNVRAM: vi.fn(),
  undefineNVRAM: vi.fn(),
};
const toast = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useTPM: () => tpm,
  useToast: () => ({ toast }),
}));

const ordinary = { handle: 0x1500001, type: "ordinary", size: 4, authRead: true, authWrite: true };
const counter = { handle: 0x1c00002, type: "counter", size: 2048, authRead: false, authWrite: false };

function info(nvIndexes: object[] = [ordinary, counter]) {
  return {
    data: {
      nvIndexes,
      capabilities: [
        { name: "nvIndexesDefined", value: "2" },
        { name: "nvIndexesMax", value: "64" },
        { name: "nvBufferMax", value: "1024" },
      ],
    },
  };
}

/** The text of the stat card whose title is given. */
function card(title: string): string {
  return screen.getByText(title).parentElement?.parentElement?.textContent ?? "";
}

async function loaded() {
  render(<TPMNVRAMPage />);
  await screen.findByText("0x01500001");
}

function rowButton(title: "Read" | "Write" | "Undefine", row = 0) {
  const button = screen.getAllByTitle(title)[row];
  if (!button) throw new Error(`no ${title} button`);
  return button;
}

function dialogButton(name: RegExp): HTMLButtonElement {
  return screen.getByRole("button", { name }) as HTMLButtonElement;
}

function utf8Base64(s: string): string {
  return Buffer.from(s, "utf8").toString("base64");
}

// Radix Dialog's focus scope probes `:modal`, which jsdom answers slowly
// (see components/layout/account-identity.test.tsx).
const nativeMatches = Element.prototype.matches;

describe("TPMNVRAMPage", () => {
  const writeText = vi.fn();
  const confirm = vi.fn();

  beforeAll(() => {
    Element.prototype.matches = function (this: Element, selector: string) {
      return selector === ":modal" ? false : nativeMatches.call(this, selector);
    };
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    vi.stubGlobal("confirm", confirm);
  });

  afterAll(() => {
    Element.prototype.matches = nativeMatches;
    vi.unstubAllGlobals();
  });

  beforeEach(() => {
    for (const fn of Object.values(tpm)) fn.mockReset();
    toast.mockReset();
    writeText.mockReset();
    confirm.mockReset();
    tpm.getInfo.mockResolvedValue(info());
  });

  afterEach(() => {
    cleanup();
  });

  it("lists the NV indices with their type, size and auth, and the stats", async () => {
    await loaded();

    expect(screen.getByText("0x01C00002")).toBeTruthy();
    expect(screen.getByText("0x01500001").closest("tr")?.textContent).toContain("ordinary");
    expect(screen.getByText("0x01C00002").closest("tr")?.textContent).toContain("counter");
    expect(screen.getByText("4 B")).toBeTruthy();
    expect(screen.getByText("R")).toBeTruthy();
    expect(screen.getByText("W")).toBeTruthy();
    expect(screen.getByText("policy")).toBeTruthy();
    expect(card("Indexes Defined")).toContain("2 / 64");
    expect(card("NV Buffer Max")).toContain("1.0 KB");
    expect(card("Total Size")).toContain("2.0 KB");
  });

  it("formats megabytes and shows the empty state without indices", async () => {
    tpm.getInfo.mockResolvedValue({
      data: { capabilities: [{ name: "nvBufferMax", value: String(3 * 1024 * 1024) }] },
    });
    render(<TPMNVRAMPage />);

    expect(await screen.findByText("No NV indices defined.")).toBeTruthy();
    expect(card("Indexes Defined")).toContain("0 / 0");
    expect(card("NV Buffer Max")).toContain("3.0 MB");
    expect(card("Total Size")).toContain("0 B");
  });

  it("shows the server error, toasts it and renders no table", async () => {
    tpm.getInfo.mockResolvedValue({ error: { message: "tpm service is not available" } });
    render(<TPMNVRAMPage />);

    expect(await screen.findByText("tpm service is not available")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Error loading TPM info",
        description: "tpm service is not available",
        variant: "destructive",
      })
    );
    expect(screen.queryByText("Defined NV Indices")).toBeNull();
  });

  it("reads an index with its password and shows hex and ASCII", async () => {
    tpm.readNVRAM.mockResolvedValue({ data: { data: btoa("hi\u0000!") } });
    await loaded();

    fireEvent.click(rowButton("Read"));
    expect(await screen.findByText("Read NV Index 0x01500001")).toBeTruthy();
    fireEvent.change(screen.getByPlaceholderText("leave blank if not required"), { target: { value: "pw" } });
    fireEvent.click(dialogButton(/^Read$/));

    expect(await screen.findByText("6869 0021")).toBeTruthy();
    expect(screen.getByText("hi.!")).toBeTruthy();
    expect(tpm.readNVRAM).toHaveBeenCalledWith({ index: 0x1500001, size: 4, password: "pw" });

    fireEvent.click(dialogButton(/Copy/));
    expect(writeText).toHaveBeenCalledWith("6869 0021");
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Copied", variant: "success" }));
  });

  it("breaks the hex dump every 16 bytes", async () => {
    tpm.readNVRAM.mockResolvedValue({ data: { data: btoa("A".repeat(17)) } });
    await loaded();

    fireEvent.click(rowButton("Read"));
    fireEvent.click(await screen.findByRole("button", { name: /^Read$/ }));

    const hex = await screen.findByText(/^4141/);
    expect(hex.textContent).toBe(`${Array(8).fill("4141").join(" ")}\n41`);
  });

  it("reads without a password and shows an empty payload", async () => {
    tpm.readNVRAM.mockResolvedValue({ data: {} });
    await loaded();

    fireEvent.click(rowButton("Read", 1));
    fireEvent.click(await screen.findByRole("button", { name: /^Read$/ }));

    expect(await screen.findByText("(empty)")).toBeTruthy();
    expect(screen.getByText("(no printable bytes)")).toBeTruthy();
    expect(tpm.readNVRAM).toHaveBeenCalledWith({ index: 0x1c00002, size: 2048 });
  });

  it("shows a payload that is not base64 as it is", async () => {
    tpm.readNVRAM.mockResolvedValue({ data: { data: "not base64!" } });
    await loaded();

    fireEvent.click(rowButton("Read"));
    fireEvent.click(await screen.findByRole("button", { name: /^Read$/ }));

    expect(await screen.findByText("not base64!")).toBeTruthy();
    expect(screen.getByText("(no printable bytes)")).toBeTruthy();
  });

  it("shows a rejected read in the dialog", async () => {
    tpm.readNVRAM.mockRejectedValue(new Error("TPM_RC_NV_AUTHORIZATION"));
    await loaded();

    fireEvent.click(rowButton("Read"));
    fireEvent.click(await screen.findByRole("button", { name: /^Read$/ }));

    expect(await screen.findByText("TPM_RC_NV_AUTHORIZATION")).toBeTruthy();
    expect(screen.queryByText("(empty)")).toBeNull();
  });

  it("shows a read error from the server instead of an empty payload", async () => {
    tpm.readNVRAM.mockResolvedValue({ error: { message: "TPM_RC_NV_LOCKED" } });
    await loaded();

    fireEvent.click(rowButton("Read"));
    fireEvent.click(await screen.findByRole("button", { name: /^Read$/ }));

    expect(await screen.findByText("TPM_RC_NV_LOCKED")).toBeTruthy();
    expect(screen.queryByText("(empty)")).toBeNull();
  });

  it("defines an index with the chosen attributes and passwords, then reloads", async () => {
    tpm.defineNVRAM.mockResolvedValue({ data: {} });
    await loaded();

    fireEvent.click(screen.getByRole("button", { name: /Define Index/ }));
    expect(await screen.findByDisplayValue("0x1500001")).toBeTruthy();
    fireEvent.click(screen.getByText("AUTHWRITE"));
    fireEvent.click(screen.getByText("NO_DA"));
    fireEvent.change(screen.getByPlaceholderText("UserAuth value for the new index"), { target: { value: "pw" } });
    fireEvent.change(screen.getByPlaceholderText("leave blank for unlocked TPMs"), { target: { value: "owner" } });
    fireEvent.click(dialogButton(/^Define$/));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "NV index defined", description: "0x01500001", variant: "success" })
      )
    );
    expect(tpm.defineNVRAM).toHaveBeenCalledWith({
      index: 0x1500001,
      size: 32,
      attributes: ["AUTHREAD", "NO_DA"],
      password: "pw",
      parentPassword: "owner",
    });
    await waitFor(() => expect(tpm.getInfo).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByText("Define New NV Index")).toBeNull());
  });

  it("takes a decimal handle and reads a non-numeric size as 0", async () => {
    tpm.defineNVRAM.mockResolvedValue({ data: {} });
    await loaded();

    fireEvent.click(screen.getByRole("button", { name: /Define Index/ }));
    fireEvent.change(await screen.findByDisplayValue("0x1500001"), { target: { value: " 21233665 " } });
    fireEvent.change(screen.getByDisplayValue("32"), { target: { value: "" } });
    fireEvent.click(dialogButton(/^Define$/));

    await waitFor(() => expect(tpm.defineNVRAM).toHaveBeenCalledTimes(1));
    expect(tpm.defineNVRAM).toHaveBeenCalledWith({ index: 0x1440001, size: 0, attributes: ["AUTHREAD", "AUTHWRITE"] });
  });

  it.each(["", "   ", "zz", "0xzz"])("refuses the invalid handle %j", async (handle) => {
    await loaded();

    fireEvent.click(screen.getByRole("button", { name: /Define Index/ }));
    fireEvent.change(await screen.findByDisplayValue("0x1500001"), { target: { value: handle } });
    fireEvent.click(dialogButton(/^Define$/));

    expect(await screen.findByText("invalid handle (use 0x… or decimal)")).toBeTruthy();
    expect(tpm.defineNVRAM).not.toHaveBeenCalled();
  });

  it("keeps the define dialog open on a rejected define", async () => {
    tpm.defineNVRAM.mockRejectedValue(new Error("TPM_RC_NV_DEFINED"));
    await loaded();

    fireEvent.click(screen.getByRole("button", { name: /Define Index/ }));
    fireEvent.click(await screen.findByRole("button", { name: /^Define$/ }));

    expect(await screen.findByText("TPM_RC_NV_DEFINED")).toBeTruthy();
    expect(screen.getByText("Define New NV Index")).toBeTruthy();
    expect(toast).not.toHaveBeenCalled();
  });

  it("shows a define error from the server instead of a success", async () => {
    tpm.defineNVRAM.mockResolvedValue({ error: { message: "TPM_RC_NV_SPACE" } });
    await loaded();

    fireEvent.click(screen.getByRole("button", { name: /Define Index/ }));
    fireEvent.click(await screen.findByRole("button", { name: /^Define$/ }));

    expect(await screen.findByText("TPM_RC_NV_SPACE")).toBeTruthy();
    expect(toast).not.toHaveBeenCalledWith(expect.objectContaining({ title: "NV index defined" }));
  });

  it("writes the text truncated to the index size", async () => {
    tpm.writeNVRAM.mockResolvedValue({ data: {} });
    await loaded();

    fireEvent.click(rowButton("Write"));
    expect(await screen.findByText("Write NV Index 0x01500001")).toBeTruthy();
    expect(dialogButton(/^Write$/).disabled).toBe(true);
    fireEvent.change(screen.getByPlaceholderText("payload bytes…"), { target: { value: "abcdef" } });
    expect(screen.getByText("6 / 4 bytes")).toBeTruthy();
    fireEvent.click(dialogButton(/^Write$/));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "NV index written", description: "4 bytes → 0x01500001", variant: "success" })
      )
    );
    expect(tpm.writeNVRAM).toHaveBeenCalledWith({ index: 0x1500001, data: btoa("abcd") });
  });

  it("refuses UTF-8 text larger than the index instead of splitting a character", async () => {
    tpm.writeNVRAM.mockResolvedValue({ data: {} });
    await loaded();

    fireEvent.click(rowButton("Write"));
    fireEvent.change(await screen.findByPlaceholderText("payload bytes…"), { target: { value: "ab€" } });
    expect(screen.getByText("5 / 4 bytes")).toBeTruthy();
    fireEvent.click(dialogButton(/^Write$/));

    expect(await screen.findByText("Text is 5 bytes; this index holds 4")).toBeTruthy();
    expect(tpm.writeNVRAM).not.toHaveBeenCalled();
    expect(toast).not.toHaveBeenCalledWith(expect.objectContaining({ title: "NV index written" }));
  });

  it("writes UTF-8 text that exactly fills the index", async () => {
    tpm.getInfo.mockResolvedValue(info([{ ...ordinary, size: 5 }, counter]));
    tpm.writeNVRAM.mockResolvedValue({ data: {} });
    await loaded();

    fireEvent.click(rowButton("Write"));
    fireEvent.change(await screen.findByPlaceholderText("payload bytes…"), { target: { value: "ab€" } });
    expect(screen.getByText("5 / 5 bytes")).toBeTruthy();
    fireEvent.click(dialogButton(/^Write$/));

    await waitFor(() => expect(tpm.writeNVRAM).toHaveBeenCalledTimes(1));
    expect(tpm.writeNVRAM).toHaveBeenCalledWith({
      index: 0x1500001,
      data: Buffer.from([0x61, 0x62, 0xe2, 0x82, 0xac]).toString("base64"),
    });
  });

  it("writes UTF-8 text as its bytes and counts them", async () => {
    tpm.writeNVRAM.mockResolvedValue({ data: {} });
    await loaded();

    fireEvent.click(rowButton("Write", 1));
    fireEvent.change(await screen.findByPlaceholderText("payload bytes…"), { target: { value: "5 €" } });
    expect(screen.getByText("5 / 2048 bytes")).toBeTruthy();
    const password = document.querySelector('[role="dialog"] input[type="password"]');
    if (!password) throw new Error("no password input");
    fireEvent.change(password, { target: { value: "pw" } });
    fireEvent.click(dialogButton(/^Write$/));

    await waitFor(() => expect(tpm.writeNVRAM).toHaveBeenCalledTimes(1));
    expect(tpm.writeNVRAM).toHaveBeenCalledWith({ index: 0x1c00002, data: utf8Base64("5 €"), password: "pw" });
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "5 bytes → 0x01C00002" }));
  });

  it("shows a rejected write in the dialog", async () => {
    tpm.writeNVRAM.mockRejectedValue(new Error("TPM_RC_NV_RANGE"));
    await loaded();

    fireEvent.click(rowButton("Write"));
    fireEvent.change(await screen.findByPlaceholderText("payload bytes…"), { target: { value: "ab" } });
    fireEvent.click(dialogButton(/^Write$/));

    expect(await screen.findByText("TPM_RC_NV_RANGE")).toBeTruthy();
    expect(toast).not.toHaveBeenCalled();
  });

  it("shows a write error from the server instead of a success", async () => {
    tpm.writeNVRAM.mockResolvedValue({ error: { message: "TPM_RC_NV_LOCKED" } });
    await loaded();

    fireEvent.click(rowButton("Write"));
    fireEvent.change(await screen.findByPlaceholderText("payload bytes…"), { target: { value: "ab" } });
    fireEvent.click(dialogButton(/^Write$/));

    expect(await screen.findByText("TPM_RC_NV_LOCKED")).toBeTruthy();
    expect(toast).not.toHaveBeenCalledWith(expect.objectContaining({ title: "NV index written" }));
  });

  it("undefines nothing when the operator cancels", async () => {
    confirm.mockReturnValue(false);
    await loaded();

    fireEvent.click(rowButton("Undefine"));

    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("0x01500001"));
    expect(tpm.undefineNVRAM).not.toHaveBeenCalled();
  });

  it("undefines a confirmed index and reloads", async () => {
    confirm.mockReturnValue(true);
    tpm.undefineNVRAM.mockResolvedValue({ data: {} });
    await loaded();

    fireEvent.click(rowButton("Undefine", 1));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "NV index undefined", description: "0x01C00002", variant: "success" })
      )
    );
    expect(tpm.undefineNVRAM).toHaveBeenCalledWith({ index: 0x1c00002 });
    await waitFor(() => expect(tpm.getInfo).toHaveBeenCalledTimes(2));
  });

  it("toasts a rejected undefine", async () => {
    confirm.mockReturnValue(true);
    tpm.undefineNVRAM.mockRejectedValue(new Error("TPM_RC_NV_AUTHORIZATION"));
    await loaded();

    fireEvent.click(rowButton("Undefine"));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Undefine failed", description: "TPM_RC_NV_AUTHORIZATION", variant: "destructive" })
      )
    );
    expect((rowButton("Undefine") as HTMLButtonElement).disabled).toBe(false);
  });

  it("toasts an undefine error from the server instead of a success", async () => {
    confirm.mockReturnValue(true);
    tpm.undefineNVRAM.mockResolvedValue({ error: { message: "TPM_RC_NV_LOCKED" } });
    await loaded();

    fireEvent.click(rowButton("Undefine"));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Undefine failed", description: "TPM_RC_NV_LOCKED", variant: "destructive" })
      )
    );
    expect(toast).not.toHaveBeenCalledWith(expect.objectContaining({ title: "NV index undefined" }));
  });

  it("fetches the indices again on Refresh", async () => {
    await loaded();

    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));

    await waitFor(() => expect(tpm.getInfo).toHaveBeenCalledTimes(2));
  });
});
