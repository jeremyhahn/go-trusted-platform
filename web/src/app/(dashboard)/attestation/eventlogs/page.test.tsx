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

// The toolbar's Radix popover filter is replaced by plain buttons with the same
// toggle semantics (an open Radix popover costs seconds per test under jsdom).
// The page's own filter configuration and filterFns still decide the rows.
type FilterProps = {
  column?: { getFilterValue: () => unknown; setFilterValue: (v: unknown) => void };
  title?: string;
  options: { label: string; value: string }[];
};

vi.mock("@/components/ui/data-table-faceted-filter", () => ({
  DataTableFacetedFilter: ({ column, title, options }: FilterProps) => (
    <div data-filter={title}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => {
            const current = (column?.getFilterValue() as string[] | undefined) ?? [];
            const next = current.includes(o.value) ? current.filter((v) => v !== o.value) : [...current, o.value];
            column?.setFilterValue(next.length ? next : undefined);
          }}
        >
          {o.label}
        </button>
      ))}
    </div>
  ),
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

  describe("filters", () => {
    const hostPcr0 = "Host PCR 0 value";
    const hostPcr23 = "Host PCR 23 value";
    const vmPcr7 = "VM vm-1 PCR 7 value";

    function visible(): string[] {
      return [hostPcr0, hostPcr23, vmPcr7].filter((d) => screen.queryByText(d) !== null);
    }

    function options(title: string): HTMLElement[] {
      const filter = document.querySelector(`[data-filter="${title}"]`);
      if (!filter) throw new Error(`no ${title} filter`);
      return Array.from(filter.querySelectorAll<HTMLElement>("button"));
    }

    function choose(title: string, label: string) {
      const item = options(title).find((el) => el.textContent === label);
      if (!item) throw new Error(`no ${title} option ${label}`);
      fireEvent.click(item);
    }

    beforeEach(() => {
      api.state = { data: manifests, isLoading: false, error: null };
    });

    it("keeps only the rows whose device matches the search", () => {
      render(<EventLogsPage />);
      expect(visible()).toEqual([hostPcr0, hostPcr23, vmPcr7]);

      fireEvent.change(screen.getByPlaceholderText("Search by device name..."), { target: { value: "vm-1" } });
      expect(visible()).toEqual([vmPcr7]);

      fireEvent.change(screen.getByPlaceholderText("Search by device name..."), { target: { value: "host-a" } });
      expect(visible()).toEqual([hostPcr0, hostPcr23]);
    });

    it("offers only the PCR indices present and matches a numeric PCR to its string option", () => {
      render(<EventLogsPage />);
      expect(options("PCR Index").map((o) => o.textContent)).toEqual(["PCR[0]", "PCR[7]", "PCR[23]"]);
      expect(options("Algorithm").map((o) => o.textContent)).toEqual(["SHA-256", "SHA-384", "SHA-512", "SHA-1"]);

      choose("PCR Index", "PCR[7]");
      expect(visible()).toEqual([vmPcr7]);

      // A second index widens the match; unticking the first narrows it again.
      choose("PCR Index", "PCR[0]");
      expect(visible()).toEqual([hostPcr0, vmPcr7]);
      choose("PCR Index", "PCR[7]");
      expect(visible()).toEqual([hostPcr0]);
    });

    it("combines the search, PCR and algorithm filters", () => {
      render(<EventLogsPage />);
      choose("Algorithm", "SHA-256");
      choose("Algorithm", "SHA-384");
      expect(visible()).toEqual([hostPcr0, vmPcr7]);

      choose("PCR Index", "PCR[23]");
      expect(visible()).toEqual([]);
      expect(screen.getByText("No event logs found")).toBeTruthy();
    });

    it("keeps only the rows with the selected algorithm", () => {
      render(<EventLogsPage />);
      choose("Algorithm", "SHA-1");
      expect(visible()).toEqual([hostPcr23]);
    });

    it("hides every row for an algorithm no entry uses", () => {
      render(<EventLogsPage />);
      choose("Algorithm", "SHA-512");
      expect(visible()).toEqual([]);
    });

    it("restores every row on Reset", () => {
      render(<EventLogsPage />);
      expect(screen.queryByText("Reset")).toBeNull();
      choose("PCR Index", "PCR[0]");
      fireEvent.change(screen.getByPlaceholderText("Search by device name..."), { target: { value: "host" } });
      expect(visible()).toEqual([hostPcr0]);

      fireEvent.click(screen.getByText("Reset"));
      expect(visible()).toEqual([hostPcr0, hostPcr23, vmPcr7]);
      expect((screen.getByPlaceholderText("Search by device name...") as HTMLInputElement).value).toBe("");
      expect(screen.queryByText("Reset")).toBeNull();
    });
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
