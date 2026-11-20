import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ImagesPage from "./page";

// #1827: unit tests for the compute images page. It reads the registry list
// (bare or wrapped in a payload envelope), filters it, formats sizes and
// deletes an image after a confirm.

const toast = vi.fn();

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast }),
}));

const fetchMock = vi.fn();
const confirmMock = vi.fn();

function json(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  };
}

const images = [
  {
    repository: "library/nginx",
    tag: "1.27",
    digest: "sha256:0123456789abcdef0123",
    size: 1536,
    layers: 3,
    created_at: "2026-11-01T00:00:00Z",
  },
  { repository: "tools/busybox", tag: "", size: 512, layers: 1 },
  { repository: "big/model", tag: "v2", digest: "sha256:ffff", size: 5 * 1024 * 1024 * 1024, layers: 9 },
  { repository: "odd/size", tag: "neg", size: -1, layers: 0 },
];

function rows(): string[] {
  return screen
    .getAllByRole("row")
    .slice(1)
    .map((r) =>
      Array.from(r.querySelectorAll("td"))
        .slice(0, 5)
        .map((td) => td.textContent)
        .join("|")
    );
}

describe("ImagesPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("confirm", confirmMock);
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
    vi.unstubAllGlobals();
  });

  it("lists the images with tag, short digest, layers and binary sizes", async () => {
    fetchMock.mockResolvedValue(json({ images, total: 4 }));
    render(<ImagesPage />);

    expect(await screen.findByText("4 images in the registry")).toBeTruthy();
    expect(rows()).toEqual([
      // The digest column shows its first 16 characters.
      "library/nginx|1.27|sha256:012345678|3|1.5 KiB",
      "tools/busybox|—|—|1|512 B",
      "big/model|v2|sha256:ffff|9|5.0 GiB",
      "odd/size|neg|—|0|—",
    ]);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/compute/images",
      expect.objectContaining({ credentials: "include" })
    );
  });

  it("reads a list wrapped in a payload envelope and says 1 image", async () => {
    fetchMock.mockResolvedValue(json({ payload: { images: [images[0]], total: 1 } }));
    render(<ImagesPage />);

    expect(await screen.findByText("1 image in the registry")).toBeTruthy();
    expect(rows()).toHaveLength(1);
  });

  it("shows the empty registry when the body has no images", async () => {
    fetchMock.mockResolvedValue(json({}));
    render(<ImagesPage />);

    expect(await screen.findByText("No images have been pushed to the registry yet.")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("shows the HTTP status and body when the list fails", async () => {
    fetchMock.mockResolvedValue(json("registry offline", 502));
    render(<ImagesPage />);

    expect(await screen.findByText("Failed to load images: HTTP 502: registry offline")).toBeTruthy();
  });

  it("shows a thrown non-Error value as the load error", async () => {
    fetchMock.mockRejectedValue("socket closed");
    render(<ImagesPage />);

    expect(await screen.findByText("Failed to load images: socket closed")).toBeTruthy();
  });

  it("filters by repository, tag and digest, case-insensitively", async () => {
    fetchMock.mockResolvedValue(json({ images }));
    render(<ImagesPage />);
    await screen.findByText("4 images in the registry");

    const input = screen.getByPlaceholderText(/Filter by repository/);
    fireEvent.change(input, { target: { value: "NGINX" } });
    expect(rows().map((r) => r.split("|")[0])).toEqual(["library/nginx"]);

    fireEvent.change(input, { target: { value: "v2" } });
    expect(rows().map((r) => r.split("|")[0])).toEqual(["big/model"]);

    fireEvent.change(input, { target: { value: "sha256:ffff" } });
    expect(rows().map((r) => r.split("|")[0])).toEqual(["big/model"]);

    fireEvent.change(input, { target: { value: "nothing-matches" } });
    expect(screen.getByText("No images match the current filter.")).toBeTruthy();
  });

  it("deletes a tagged image after confirm and reloads the list", async () => {
    fetchMock.mockResolvedValue(json({ images }));
    confirmMock.mockReturnValue(true);
    render(<ImagesPage />);
    await screen.findByText("4 images in the registry");

    fireEvent.click(screen.getAllByTitle("Delete image")[0]);
    await vi.waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Image deleted", description: "library/nginx:1.27" })
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/compute/images/library%2Fnginx%3A1.27",
      expect.objectContaining({ method: "DELETE" })
    );
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
  });

  it("deletes an untagged image by repository alone", async () => {
    fetchMock.mockResolvedValue(json({ images }));
    confirmMock.mockReturnValue(true);
    render(<ImagesPage />);
    await screen.findByText("4 images in the registry");

    fireEvent.click(screen.getAllByTitle("Delete image")[1]);
    await vi.waitFor(() => expect(toast).toHaveBeenCalled());
    expect(confirmMock).toHaveBeenCalledWith("Delete tools/busybox? This cannot be undone.");
    expect(fetchMock.mock.calls[1][0]).toBe("/api/v1/compute/images/tools%2Fbusybox");
  });

  it("does nothing when the delete is not confirmed", async () => {
    fetchMock.mockResolvedValue(json({ images }));
    confirmMock.mockReturnValue(false);
    render(<ImagesPage />);
    await screen.findByText("4 images in the registry");

    fireEvent.click(screen.getAllByTitle("Delete image")[0]);
    expect(confirmMock).toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(toast).not.toHaveBeenCalled();
  });

  it("toasts a failed delete and keeps the list", async () => {
    fetchMock.mockResolvedValueOnce(json({ images })).mockResolvedValueOnce(json("locked", 409));
    confirmMock.mockReturnValue(true);
    render(<ImagesPage />);
    await screen.findByText("4 images in the registry");

    fireEvent.click(screen.getAllByTitle("Delete image")[0]);
    await vi.waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Delete failed",
        description: "HTTP 409: locked",
        variant: "destructive",
      })
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(rows()).toHaveLength(4);
  });

  it("reloads from the Refresh button", async () => {
    fetchMock.mockResolvedValue(json({ images: [] }));
    render(<ImagesPage />);
    await screen.findByText("No images have been pushed to the registry yet.");

    fireEvent.click(screen.getByText("Refresh"));
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  });
});
