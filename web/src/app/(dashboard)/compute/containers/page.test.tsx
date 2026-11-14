import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { SERVICE_NOT_CONFIGURED } from "trusted-platform-sdk";
import { afterEach, describe, expect, it, vi } from "vitest";

import ContainersPage from "./page";

// #1827: unit tests for the containers dashboard page. The page reads the
// SDK's containers into the console's Container type, counts them by status,
// filters them, and shows an informational state when compute is not wired
// on this node.

const service = {
  listContainers: vi.fn(),
};
const toast = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useCompute: () => service,
  useToast: () => ({ toast }),
}));

type Row = {
  id: string;
  name: string;
  image: string;
  status: string;
  createdAt: string;
  ports: { container: number; host?: number; protocol: string }[];
};

vi.mock("@/components/features/compute/container-table", () => ({
  ContainerTable: ({ containers, onRefresh }: { containers: Row[]; onRefresh: () => void }) => (
    <div>
      <ul data-testid="container-rows">
        {containers.map((c) => (
          <li key={c.id}>
            {`${c.id}|${c.name}|${c.image}|${c.status}|${c.createdAt}|${c.ports
              .map((p) => `${p.container}:${p.host}/${p.protocol}`)
              .join(",")}`}
          </li>
        ))}
      </ul>
      <button onClick={onRefresh}>table-refresh</button>
    </div>
  ),
}));

vi.mock("@/components/features/compute/container-form", () => ({
  ContainerForm: ({ open, onSuccess }: { open: boolean; onSuccess: () => void }) => (
    <div data-testid="container-form" data-open={String(open)}>
      <button onClick={onSuccess}>form-success</button>
    </div>
  ),
}));

vi.mock("@/components/features/platform", () => ({
  ServiceUnavailableState: ({ service: name, description }: { service: string; description: string }) => (
    <div data-testid="service-unavailable">{`${name}: ${description}`}</div>
  ),
}));

// A native select stands in for the Radix one, which jsdom cannot open.
vi.mock("@/components/ui/select", () => ({
  Select: ({ value, onValueChange, children }: { value: string; onValueChange: (v: string) => void; children: ReactNode }) => (
    <select aria-label="status-filter" value={value} onChange={(e) => onValueChange(e.target.value)}>
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  SelectItem: ({ value, children }: { value: string; children: ReactNode }) => <option value={value}>{children}</option>,
}));

function ok(containers: unknown[]) {
  return { data: { containers }, success: true };
}

const sample = [
  {
    id: "c-1",
    state: "CONTAINER_STATE_RUNNING",
    createdAt: "2026-11-01T00:00:00Z",
    config: {
      name: "web",
      image: "nginx:1",
      ports: [
        { containerPort: 80, hostPort: 8080, protocol: "UDP" },
        { containerPort: 443, hostPort: 8443 },
      ],
    },
  },
  { id: "c-2", state: "CONTAINER_STATE_STOPPED", createdAt: "2026-11-02T00:00:00Z", config: { name: "db", image: "pg:16" } },
  { id: "c-3", state: "CONTAINER_STATE_ERROR", createdAt: "2026-11-03T00:00:00Z" },
  { id: "c-4", createdAt: "2026-11-04T00:00:00Z", config: { image: "busybox" } },
];

function stat(label: string): string | null {
  // The filter's options carry the same labels; the counter is a div.
  const card = screen.getAllByText(label).find((el) => el.tagName === "DIV");
  return card?.nextElementSibling?.textContent ?? null;
}

async function rows(): Promise<string[]> {
  const list = await screen.findByTestId("container-rows");
  return Array.from(list.querySelectorAll("li")).map((li) => li.textContent ?? "");
}

describe("ContainersPage", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("maps SDK containers into rows, defaulting name, image, status and protocol", async () => {
    service.listContainers.mockResolvedValue(ok(sample));
    render(<ContainersPage />);

    expect(await rows()).toEqual([
      "c-1|web|nginx:1|running|2026-11-01T00:00:00Z|80:8080/udp,443:8443/tcp",
      "c-2|db|pg:16|stopped|2026-11-02T00:00:00Z|",
      "c-3|c-3||error|2026-11-03T00:00:00Z|",
      "c-4|c-4|busybox|creating|2026-11-04T00:00:00Z|",
    ]);
    expect(stat("Total")).toBe("4");
    expect(stat("Running")).toBe("1");
    expect(stat("Stopped")).toBe("1");
    expect(stat("Error")).toBe("1");
    expect(toast).not.toHaveBeenCalled();
  });

  it("stamps a container without a creation time with the current time", async () => {
    service.listContainers.mockResolvedValue(ok([{ id: "c-9", state: "CONTAINER_STATE_RUNNING" }]));
    render(<ContainersPage />);

    const [row] = await rows();
    const createdAt = row.split("|")[4];
    expect(Number.isNaN(Date.parse(createdAt))).toBe(false);
  });

  it("filters the rows by status and back to all", async () => {
    service.listContainers.mockResolvedValue(ok(sample));
    render(<ContainersPage />);
    await rows();

    const filter = screen.getByLabelText("status-filter");
    fireEvent.change(filter, { target: { value: "stopped" } });
    expect((await rows()).map((r) => r.split("|")[0])).toEqual(["c-2"]);

    fireEvent.change(filter, { target: { value: "creating" } });
    expect((await rows()).map((r) => r.split("|")[0])).toEqual(["c-4"]);

    fireEvent.change(filter, { target: { value: "all" } });
    expect(await rows()).toHaveLength(4);
    // The counters do not follow the filter.
    expect(stat("Total")).toBe("4");
  });

  it("shows zero counters and no rows for an empty or missing list", async () => {
    service.listContainers.mockResolvedValue({ data: {}, success: true });
    render(<ContainersPage />);

    expect(await rows()).toEqual([]);
    expect(stat("Total")).toBe("0");
    expect(stat("Running")).toBe("0");
  });

  it("toasts a fetch error and still renders the empty page", async () => {
    service.listContainers.mockResolvedValue({
      error: { status: 500, message: "boom" },
      success: false,
    });
    render(<ContainersPage />);

    await vi.waitFor(() => expect(toast).toHaveBeenCalled());
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ variant: "destructive", description: expect.stringContaining("boom") })
    );
    expect(await rows()).toEqual([]);
    expect(screen.queryByTestId("service-unavailable")).toBeNull();
  });

  it("shows the compute-not-configured state on a 503 without a toast", async () => {
    service.listContainers.mockResolvedValue({
      error: { status: 503, message: "compute is not configured", details: { reason: SERVICE_NOT_CONFIGURED } },
      success: false,
    });
    render(<ContainersPage />);

    const state = await screen.findByTestId("service-unavailable");
    expect(state.textContent).toContain("Compute:");
    expect(screen.queryByText("Create Container")).toBeNull();
    expect(screen.queryByTestId("container-rows")).toBeNull();
    expect(toast).not.toHaveBeenCalled();
  });

  it("treats a 503 without the not-configured reason as a real error", async () => {
    service.listContainers.mockResolvedValue({
      error: { status: 503, message: "upstream down" },
      success: false,
    });
    render(<ContainersPage />);

    await vi.waitFor(() => expect(toast).toHaveBeenCalled());
    expect(screen.queryByTestId("service-unavailable")).toBeNull();
    expect(screen.getByText("Create Container")).toBeTruthy();
  });

  it("toasts when the client throws instead of returning an error", async () => {
    service.listContainers.mockRejectedValue(new Error("network"));
    render(<ContainersPage />);

    await vi.waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "Failed to fetch containers: network" }))
    );
  });

  it("refetches from the refresh button, the table and the form", async () => {
    service.listContainers.mockResolvedValue(ok(sample));
    render(<ContainersPage />);
    await rows();
    expect(service.listContainers).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByText("table-refresh"));
    await vi.waitFor(() => expect(service.listContainers).toHaveBeenCalledTimes(2));

    fireEvent.click(screen.getByText("form-success"));
    await vi.waitFor(() => expect(service.listContainers).toHaveBeenCalledTimes(3));
  });

  it("opens the create form from the Create Container button", async () => {
    service.listContainers.mockResolvedValue(ok([]));
    render(<ContainersPage />);
    await rows();

    expect(screen.getByTestId("container-form").getAttribute("data-open")).toBe("false");
    fireEvent.click(screen.getByText("Create Container"));
    expect(screen.getByTestId("container-form").getAttribute("data-open")).toBe("true");
  });
});
