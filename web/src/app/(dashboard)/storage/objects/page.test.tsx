import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ObjectStoragePage from "./page";

// #1826: the object storage page lists the QuicBaaS buckets, selects the
// first, lists its objects and drives bucket create and delete and object
// upload, download and delete. The client is a stable fake so the real useApi
// and useMutation hooks run against it.

const buckets = [
  { name: "alpha", region: "eu-1", objectCount: 2, totalSizeBytes: 3072, config: { versioning: "enabled", encryptionEnabled: true }, createdAt: "2026-11-01T00:00:00Z" },
  { name: "beta", objectCount: 0, totalSizeBytes: 0, createdAt: "2026-11-01T00:00:00Z" },
];

const objects = [
  { bucket: "alpha", key: "docs/readme.txt", size: 1024, contentType: "text/plain", storageClass: "standard", lastModified: "2026-11-01T00:00:00Z" },
  { bucket: "alpha", key: "cold.bin", size: 2048, storageClass: "deep_archive", lastModified: "2026-11-01T00:00:00Z" },
  { bucket: "alpha", key: "odd.dat", size: 0, contentType: "application/x-odd", storageClass: "glacier_x", lastModified: "2026-11-01T00:00:00Z" },
];

const admin = { listBuckets: vi.fn(), createBucket: vi.fn(), deleteBucket: vi.fn() };
const store = { listObjects: vi.fn(), putObject: vi.fn(), getObject: vi.fn(), deleteObject: vi.fn() };
const client = { quicBaaSObjectStorageAdmin: admin, quicBaaSObjectStorage: store };
const toast = vi.fn();
const toastResult = { toast };

// The SDK answers with an ApiResponse: data on success, error on refusal.
const ok = (data: unknown) => ({ data });
const refused = (message: string) => ({ error: { code: "REFUSED", message } });

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  usePlatformClient: () => client,
  useToast: () => toastResult,
}));

// The Radix menu's portal does not settle in jsdom, so row menus render inline.
vi.mock("@/components/ui/dropdown-menu", async (importOriginal) => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Item = ({ children, onClick }: { children?: React.ReactNode; onClick?: () => void }) => (
    <button type="button" role="menuitem" onClick={onClick}>
      {children}
    </button>
  );
  return {
    ...(await importOriginal<typeof import("@/components/ui/dropdown-menu")>()),
    DropdownMenu: Pass,
    DropdownMenuTrigger: Pass,
    DropdownMenuContent: Pass,
    DropdownMenuItem: Item,
  };
});

function rowFor(key: string): HTMLElement {
  const row = screen.getByText(key).closest("tr");
  if (!row) throw new Error(`no table row for ${key}`);
  return row;
}

function selectRows(...keys: string[]) {
  for (const key of keys) fireEvent.click(within(rowFor(key)).getByRole("checkbox", { name: "Select row" }));
}

function chipFor(bucket: string): HTMLElement {
  const chip = screen.getByText(bucket, { selector: "span.font-medium" }).parentElement;
  if (!chip) throw new Error(`no bucket chip for ${bucket}`);
  return chip;
}

function stat(title: string): string {
  const card = screen.getByText(title).parentElement?.parentElement;
  return card?.querySelector(".text-2xl")?.textContent?.trim() ?? "";
}

async function renderPage() {
  render(<ObjectStoragePage />);
  await screen.findByText("docs/readme.txt");
}

async function openUpload(file: File) {
  fireEvent.click(screen.getByRole("button", { name: /Upload Object/ }));
  const input = await screen.findByLabelText("File");
  fireEvent.change(input, { target: { files: [file] } });
}

describe("ObjectStoragePage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    admin.listBuckets.mockResolvedValue(ok({ buckets }));
    admin.createBucket.mockResolvedValue(ok({}));
    admin.deleteBucket.mockResolvedValue(ok({}));
    store.listObjects.mockImplementation(({ bucket }: { bucket: string }) =>
      Promise.resolve(ok({ objects: bucket === "alpha" ? objects : [] })),
    );
    store.putObject.mockResolvedValue(ok({}));
    store.deleteObject.mockResolvedValue(ok({}));
    store.getObject.mockResolvedValue(ok({ content: btoa("hello") }));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("selects the first bucket and lists its objects", async () => {
    await renderPage();
    expect(admin.listBuckets).toHaveBeenCalledWith({});
    expect(store.listObjects).toHaveBeenCalledWith({ bucket: "alpha", prefix: undefined, maxKeys: 100 });
    expect(screen.getByText('Browse objects in "alpha"')).toBeTruthy();
  });

  it("marks the versioned, encrypted bucket and counts its objects", async () => {
    await renderPage();
    const alpha = within(chipFor("alpha"));
    expect(alpha.getByText("2 objects")).toBeTruthy();
    expect(alpha.getByText("V")).toBeTruthy();
    expect(alpha.getByText("E")).toBeTruthy();
    const beta = within(chipFor("beta"));
    expect(beta.getByText("0 objects")).toBeTruthy();
    expect(beta.queryByText("V")).toBeNull();
    expect(beta.queryByText("E")).toBeNull();
  });

  it("labels the storage classes, keeps an unknown one as it is and defaults the content type", async () => {
    await renderPage();
    expect(within(rowFor("docs/readme.txt")).getByText("Standard")).toBeTruthy();
    expect(within(rowFor("docs/readme.txt")).getByText("1 KB")).toBeTruthy();
    expect(within(rowFor("cold.bin")).getByText("Deep Archive")).toBeTruthy();
    expect(within(rowFor("cold.bin")).getByText("application/octet-stream")).toBeTruthy();
    expect(within(rowFor("odd.dat")).getByText("glacier_x")).toBeTruthy();
    expect(within(rowFor("odd.dat")).getByText("0 B")).toBeTruthy();
  });

  it("counts buckets, objects and their total size", async () => {
    await renderPage();
    expect(stat("Total Buckets")).toBe("2");
    expect(stat("Total Objects")).toBe("3");
    expect(stat("Total Size")).toBe("3 KB");
    expect(screen.getByText('In "alpha"')).toBeTruthy();
  });

  it("lists another bucket's objects when it is picked", async () => {
    await renderPage();
    fireEvent.click(chipFor("beta"));
    await waitFor(() =>
      expect(store.listObjects).toHaveBeenLastCalledWith({ bucket: "beta", prefix: undefined, maxKeys: 100 }),
    );
    expect(await screen.findByText("No objects found in this bucket")).toBeTruthy();
    expect(stat("Total Size")).toBe("0 B");
  });

  it("lists again under the prefix the operator types, and clears it", async () => {
    await renderPage();
    fireEvent.change(screen.getByPlaceholderText("Filter by prefix..."), { target: { value: "docs/" } });
    await waitFor(() =>
      expect(store.listObjects).toHaveBeenLastCalledWith({ bucket: "alpha", prefix: "docs/", maxKeys: 100 }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Clear prefix" }));
    await waitFor(() =>
      expect(store.listObjects).toHaveBeenLastCalledWith({ bucket: "alpha", prefix: undefined, maxKeys: 100 }),
    );
  });

  it("lists no objects and offers a first bucket when there are no buckets", async () => {
    admin.listBuckets.mockResolvedValue(ok({}));
    render(<ObjectStoragePage />);
    expect(await screen.findByText("Create your first bucket")).toBeTruthy();
    expect(screen.getAllByText("Select a bucket to view objects").length).toBeGreaterThan(0);
    expect(store.listObjects).not.toHaveBeenCalled();
    expect((screen.getByRole("button", { name: /Upload Object/ }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows the error and a toast when the buckets are refused", async () => {
    admin.listBuckets.mockResolvedValue(refused("storage offline"));
    render(<ObjectStoragePage />);
    expect(await screen.findByText("storage offline")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error loading buckets", variant: "destructive" }));
  });

  it("shows the error and a toast when the objects are refused", async () => {
    store.listObjects.mockResolvedValue(refused("bucket sealed"));
    render(<ObjectStoragePage />);
    expect(await screen.findByText("bucket sealed")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error loading objects" }));
  });

  it("refuses to create a bucket without a name", async () => {
    await renderPage();
    fireEvent.click(screen.getByRole("button", { name: /Create Bucket/ }));
    fireEvent.change(await screen.findByLabelText("Bucket Name"), { target: { value: " " } });
    fireEvent.click(screen.getAllByRole("button", { name: "Create Bucket" }).at(-1)!);
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "Bucket name is required" })),
    );
    expect(admin.createBucket).not.toHaveBeenCalled();
  });

  it("creates a bucket with its region, versioning and encryption and selects it", async () => {
    await renderPage();
    fireEvent.click(screen.getByRole("button", { name: /Create Bucket/ }));
    fireEvent.change(await screen.findByLabelText("Bucket Name"), { target: { value: "gamma" } });
    fireEvent.change(screen.getByLabelText("Region (optional)"), { target: { value: "eu-2" } });
    fireEvent.click(screen.getByLabelText("Enable versioning"));
    fireEvent.click(screen.getByLabelText("Enable encryption"));
    fireEvent.click(screen.getAllByRole("button", { name: "Create Bucket" }).at(-1)!);
    await waitFor(() =>
      expect(admin.createBucket).toHaveBeenCalledWith({
        name: "gamma",
        region: "eu-2",
        config: { versioning: "enabled", encryptionEnabled: false, defaultStorageClass: "standard" },
      }),
    );
    await waitFor(() =>
      expect(store.listObjects).toHaveBeenLastCalledWith({ bucket: "gamma", prefix: undefined, maxKeys: 100 }),
    );
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Bucket created" }));
  });

  it("keeps the bucket dialog open when the create is refused", async () => {
    admin.createBucket.mockResolvedValue(refused("name taken"));
    await renderPage();
    fireEvent.click(screen.getByRole("button", { name: /Create Bucket/ }));
    fireEvent.change(await screen.findByLabelText("Bucket Name"), { target: { value: "alpha" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Create Bucket" }).at(-1)!);
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error creating bucket", description: "name taken" })),
    );
    expect(admin.createBucket).toHaveBeenCalledWith(expect.objectContaining({ region: undefined }));
    expect(screen.getByLabelText("Bucket Name")).toBeTruthy();
  });

  it("deletes a bucket only after confirmation, and reports a refusal", async () => {
    vi.stubGlobal("confirm", vi.fn().mockReturnValueOnce(false).mockReturnValue(true));
    await renderPage();
    const del = () => within(chipFor("beta")).getByRole("button");
    fireEvent.click(del());
    expect(admin.deleteBucket).not.toHaveBeenCalled();
    fireEvent.click(del());
    await waitFor(() => expect(admin.deleteBucket).toHaveBeenCalledWith({ name: "beta" }));
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Bucket deleted" })));
    admin.deleteBucket.mockResolvedValue(refused("not empty"));
    await waitFor(() => expect(admin.listBuckets).toHaveBeenCalledTimes(2));
    fireEvent.click(del());
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error deleting bucket", description: "not empty" })),
    );
  });

  it("uploads a file under its own name into the selected bucket", async () => {
    await renderPage();
    await openUpload(new File(["hello"], "hello.txt", { type: "text/plain" }));
    expect((screen.getByLabelText("Object Key") as HTMLInputElement).value).toBe("hello.txt");
    fireEvent.click(screen.getByRole("button", { name: /^Upload$/ }));
    await waitFor(() =>
      expect(store.putObject).toHaveBeenCalledWith({
        bucket: "alpha",
        key: "hello.txt",
        content: btoa("hello"),
        contentType: "text/plain",
        storageClass: "standard",
      }),
    );
    await waitFor(() => expect(screen.queryByLabelText("Object Key")).toBeNull());
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Object uploaded" }));
  });

  it("uploads under the key the operator types, as octet-stream when the file has no type", async () => {
    await renderPage();
    fireEvent.click(screen.getByRole("button", { name: /Upload Object/ }));
    fireEvent.change(await screen.findByLabelText("Object Key"), { target: { value: "raw/blob" } });
    fireEvent.change(screen.getByLabelText("File"), { target: { files: [new File(["ab"], "blob")] } });
    fireEvent.click(screen.getByRole("button", { name: /^Upload$/ }));
    await waitFor(() =>
      expect(store.putObject).toHaveBeenCalledWith(
        expect.objectContaining({ key: "raw/blob", content: btoa("ab"), contentType: "application/octet-stream" }),
      ),
    );
  });

  it("uploads an empty file as empty content", async () => {
    await renderPage();
    await openUpload(new File([], "empty.txt", { type: "text/plain" }));
    fireEvent.click(screen.getByRole("button", { name: /^Upload$/ }));
    await waitFor(() => expect(store.putObject).toHaveBeenCalledWith(expect.objectContaining({ key: "empty.txt", content: "" })));
  });

  it("refuses an upload without a file or without a key", async () => {
    await renderPage();
    fireEvent.click(screen.getByRole("button", { name: /Upload Object/ }));
    await screen.findByLabelText("Object Key");
    expect((screen.getByRole("button", { name: /^Upload$/ }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("File"), { target: { files: [new File(["x"], "x.txt")] } });
    fireEvent.change(screen.getByLabelText("Object Key"), { target: { value: "  " } });
    fireEvent.click(screen.getByRole("button", { name: /^Upload$/ }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "Object key is required" })),
    );
    expect(store.putObject).not.toHaveBeenCalled();
  });

  it("keeps the upload dialog open when the upload is refused", async () => {
    store.putObject.mockResolvedValue(refused("quota exceeded"));
    await renderPage();
    await openUpload(new File(["x"], "x.txt"));
    fireEvent.click(screen.getByRole("button", { name: /^Upload$/ }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error uploading object", description: "quota exceeded" })),
    );
    expect(screen.getByLabelText("Object Key")).toBeTruthy();
  });

  it("downloads an object under the last segment of its key", async () => {
    const createObjectURL = vi.fn(() => "blob:object");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      expect(this.download).toBe("readme.txt");
    });
    await renderPage();
    fireEvent.click(within(rowFor("docs/readme.txt")).getByRole("menuitem", { name: /Download/ }));
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Download started" })));
    expect(store.getObject).toHaveBeenCalledWith({ bucket: "alpha", key: "docs/readme.txt" });
    expect(click).toHaveBeenCalledTimes(1);
    const blob = (createObjectURL.mock.calls[0] as unknown as [Blob])[0];
    expect(blob.type).toBe("text/plain");
    expect(blob.size).toBe(5);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:object");
    click.mockRestore();
  });

  it("reports a refused download and content that is not base64", async () => {
    store.getObject.mockResolvedValueOnce(refused("gone")).mockResolvedValueOnce(ok({ content: "%%%" }));
    await renderPage();
    fireEvent.click(within(rowFor("cold.bin")).getByRole("menuitem", { name: /Download/ }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error downloading object", description: "gone" })),
    );
    fireEvent.click(within(rowFor("cold.bin")).getByRole("menuitem", { name: /Download/ }));
    await waitFor(() => expect(toast).toHaveBeenCalledTimes(2));
    expect(toast).toHaveBeenLastCalledWith(expect.objectContaining({ title: "Error downloading object", variant: "destructive" }));
  });

  it("deletes an object only after confirmation, and reports a refusal", async () => {
    vi.stubGlobal("confirm", vi.fn().mockReturnValueOnce(false).mockReturnValue(true));
    await renderPage();
    const del = () => within(rowFor("odd.dat")).getByRole("menuitem", { name: /Delete/ });
    fireEvent.click(del());
    expect(store.deleteObject).not.toHaveBeenCalled();
    fireEvent.click(del());
    await waitFor(() => expect(store.deleteObject).toHaveBeenCalledWith({ bucket: "alpha", key: "odd.dat" }));
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Object deleted" })));
    store.deleteObject.mockResolvedValue(refused("held"));
    await waitFor(() => expect(store.listObjects).toHaveBeenCalledTimes(2));
    fireEvent.click(del());
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error deleting object", description: "held" })),
    );
  });

  it("deletes nothing when the bulk delete is not confirmed", async () => {
    const confirm = vi.fn(() => false);
    vi.stubGlobal("confirm", confirm);
    await renderPage();
    selectRows("cold.bin", "odd.dat");
    fireEvent.click(screen.getByRole("button", { name: "Delete selected (2)" }));
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("Delete 2 selected objects?"));
    expect(store.deleteObject).not.toHaveBeenCalled();
  });

  it("goes on with the next selected object after a refused bulk delete", async () => {
    const unhandled = vi.fn();
    process.on("unhandledRejection", unhandled);
    try {
      vi.stubGlobal("confirm", vi.fn(() => true));
      store.deleteObject.mockResolvedValueOnce(refused("held")).mockResolvedValueOnce(ok({}));
      await renderPage();
      selectRows("cold.bin", "odd.dat");
      fireEvent.click(screen.getByRole("button", { name: "Delete selected (2)" }));
      await waitFor(() => expect(store.deleteObject).toHaveBeenCalledTimes(2));
      expect(store.deleteObject.mock.calls).toEqual([
        [{ bucket: "alpha", key: "cold.bin" }],
        [{ bucket: "alpha", key: "odd.dat" }],
      ]);
      await waitFor(() =>
        expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error deleting object", description: "held" })),
      );
      await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Object deleted" })));
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(unhandled).not.toHaveBeenCalled();
    } finally {
      process.off("unhandledRejection", unhandled);
    }
  });
});
