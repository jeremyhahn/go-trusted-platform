import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import EventLogsPage from "./page";

// useApi is driven by hand so each test sets the exact loading, error and
// data state the page renders; the fetcher and the onError option the page
// hands to useApi are captured and exercised on their own.
type ApiOptions = { onError?: (err: Error) => void };

const service = { listManifests: vi.fn() };
const toast = vi.fn();
const refetch = vi.fn();
const api: {
  state: { data: unknown; isLoading: boolean; error: Error | null };
  fetcher: (() => unknown) | null;
  options: ApiOptions | undefined;
} = {
  state: { data: null, isLoading: false, error: null },
  fetcher: null,
  options: undefined,
};

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useAttestation: () => service,
  useToast: () => ({ toast }),
  useApi: (fetcher: () => unknown, _deps: unknown[], options?: ApiOptions) => {
    api.fetcher = fetcher;
    api.options = options;
    return { ...api.state, refetch };
  },
}));

const digest = "c2hhMjU2LWRpZ2VzdC1vZi1wY3ItemVyby12YWx1ZQ==";

const manifests = {
  manifests: [
    {
      id: "m-1",
      hostId: "host-a",
      timestamp: "2026-08-31T10:00:00Z",
      host: {
        pcrs: [
          { index: 0, value: digest, algorithm: "SHA256" },
          { index: 23, value: "AAAA", algorithm: "SHA1" },
        ],
      },
      vms: [
        {
          vmId: "vm-1",
          timestamp: "2026-08-31T10:05:00Z",
          pcrs: [{ index: 7, value: "BBBBBBBB", algorithm: "SHA384" }],
        },
        { vmId: "vm-empty", timestamp: "2026-08-31T10:05:00Z" },
      ],
    },
    // No host section and no VMs: contributes no entry.
    { id: "m-2", hostId: "host-b", timestamp: "2026-08-31T10:00:00Z" },
  ],
};

function statValue(title: string): string | null | undefined {
  const card = screen.getByText(title).parentElement?.parentElement;
  return card?.querySelector(".text-2xl")?.textContent;
}

describe("EventLogsPage", () => {
  beforeEach(() => {
    api.state = { data: null, isLoading: false, error: null };
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it("fetches the event logs from listManifests with no filter", () => {
    render(<EventLogsPage />);
    service.listManifests.mockReturnValue("pending");

    expect(api.fetcher?.()).toBe("pending");
    expect(service.listManifests).toHaveBeenCalledWith({});
  });

  it("toasts a destructive error when loading fails", () => {
    render(<EventLogsPage />);
    api.options?.onError?.(new Error("upstream down"));

    expect(toast).toHaveBeenCalledWith({
      title: "Error loading event logs",
      description: "upstream down",
      variant: "destructive",
    });
  });

  it("shows the loading state while the manifests load", () => {
    api.state = { data: null, isLoading: true, error: null };
    render(<EventLogsPage />);

    expect(screen.getByText("Loading event logs...")).toBeTruthy();
    expect(screen.queryByText("TPM Event Logs")).toBeNull();
  });

  it("shows the error with a retry that refetches", () => {
    api.state = { data: null, isLoading: false, error: new Error("forbidden") };
    render(<EventLogsPage />);

    expect(screen.getByText("Error Loading Event Logs")).toBeTruthy();
    expect(screen.getByText("forbidden")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("prefers the error over the loading state", () => {
    api.state = { data: null, isLoading: true, error: new Error("both") };
    render(<EventLogsPage />);

    expect(screen.getByText("Error Loading Event Logs")).toBeTruthy();
    expect(screen.queryByText("Loading event logs...")).toBeNull();
  });

  it("shows zero counts, the empty state and a disabled export with no data", () => {
    render(<EventLogsPage />);

    expect(statValue("Total Events")).toBe("0");
    expect(statValue("Devices")).toBe("0");
    expect(statValue("PCRs Used")).toBe("0");
    expect(statValue("Event Types")).toBe("0");
    expect(screen.getByText("No event logs found")).toBeTruthy();
    expect(screen.getByRole("button", { name: /Export/ })).toHaveProperty("disabled", true);
  });

  it("treats a response without a manifests list as empty", () => {
    api.state = { data: {}, isLoading: false, error: null };
    render(<EventLogsPage />);

    expect(statValue("Total Events")).toBe("0");
    expect(screen.getByText("No event logs found")).toBeTruthy();
  });

  it("lists host and VM PCR values and counts them", () => {
    api.state = { data: manifests, isLoading: false, error: null };
    render(<EventLogsPage />);

    expect(statValue("Total Events")).toBe("3");
    expect(statValue("Devices")).toBe("2");
    expect(statValue("PCRs Used")).toBe("3");
    expect(statValue("Event Types")).toBe("2");

    expect(screen.getAllByText("host-a")).toHaveLength(2);
    expect(screen.getByText("VM: vm-1")).toBeTruthy();
    expect(screen.queryByText(/vm-empty/)).toBeNull();
    expect(screen.queryByText("host-b")).toBeNull();
    expect(screen.getByText("Host PCR 0 value")).toBeTruthy();
    expect(screen.getByText("VM vm-1 PCR 7 value")).toBeTruthy();
    expect(screen.getAllByText("PCR_VALUE")).toHaveLength(2);
    expect(screen.getByText("VM_PCR_VALUE")).toBeTruthy();
    expect(screen.getByText(`${digest.substring(0, 16)}...`)).toBeTruthy();
    expect(screen.queryByText("No event logs found")).toBeNull();
  });

  it("colours known PCR indices and falls back to grey for others", () => {
    api.state = { data: manifests, isLoading: false, error: null };
    render(<EventLogsPage />);

    const table = screen.getByRole("table");
    expect(within(table).getByText("PCR[0]", { exact: false }).className).toContain("bg-blue-500/10");
    expect(within(table).getByText("PCR[7]", { exact: false }).className).toContain("bg-cyan-500/10");
    expect(within(table).getByText("PCR[23]", { exact: false }).className).toContain("bg-gray-500/10");
  });

  it("refetches on Refresh", () => {
    api.state = { data: manifests, isLoading: false, error: null };
    render(<EventLogsPage />);

    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("exports the listed entries as a dated JSON download", async () => {
    api.state = { data: manifests, isLoading: false, error: null };
    const blobs: Blob[] = [];
    const createObjectURL = vi.fn((blob: Blob) => {
      blobs.push(blob);
      return "blob:event-logs";
    });
    const revokeObjectURL = vi.fn();
    Object.assign(URL, { createObjectURL, revokeObjectURL });
    let download = "";
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(function (this: HTMLAnchorElement) {
        download = this.download;
      });
    render(<EventLogsPage />);

    const exportButton = screen.getByRole("button", { name: /Export/ });
    expect(exportButton).toHaveProperty("disabled", false);
    fireEvent.click(exportButton);

    expect(click).toHaveBeenCalledTimes(1);
    expect(download).toMatch(/^event-logs-\d{4}-\d{2}-\d{2}\.json$/);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:event-logs");
    expect(document.querySelector("a[download]")).toBeNull();
    expect(blobs[0].type).toBe("application/json");
    const text = await new Promise<string>((resolve) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result));
      reader.readAsText(blobs[0]);
    });
    const exported = JSON.parse(text);
    expect(exported).toHaveLength(3);
    expect(exported[0]).toMatchObject({
      id: "m-1-host-pcr-0",
      deviceId: "host-a",
      pcrIndex: 0,
      eventType: "PCR_VALUE",
      digestAlgorithm: "SHA256",
      dataSize: Buffer.from(digest, "base64").length,
    });
    expect(exported[2]).toMatchObject({
      id: "m-1-vm-1-pcr-7",
      deviceId: "vm-1",
      deviceName: "VM: vm-1",
      timestamp: "2026-08-31T10:05:00Z",
      dataSize: 6,
    });
  });
});
