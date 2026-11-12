import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import VectorDatabasePage from "./page";

// #1826: the vector page lists the vector namespaces as collections with
// their metric, index and counts, creates and deletes collections and runs a
// similarity search. The vector client is a stable fake so the real useApi
// and useMutation hooks run against it.

const vector = {
  listNamespaces: vi.fn(),
  createNamespace: vi.fn(),
  deleteNamespace: vi.fn(),
  search: vi.fn(),
};
const toast = vi.fn();
const toastResult = { toast };

// The SDK answers with an ApiResponse: data on success, error on refusal.
const ok = (data: unknown) => ({ data });
const refused = (message: string) => ({ error: { code: "REFUSED", message } });

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useQuicBaaSVector: () => vector,
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

// The Radix select needs pointer capture jsdom lacks, so it renders as a
// native select over the same items; the page's values and handlers are kept.
vi.mock("@/components/ui/select", () => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Select = ({ value, onValueChange, children }: { value?: string; onValueChange?: (v: string) => void; children?: React.ReactNode }) => (
    <select value={value} onChange={(e) => onValueChange?.(e.target.value)}>
      <option value="">none</option>
      {children}
    </select>
  );
  const Item = ({ value, children }: { value: string; children?: React.ReactNode }) => <option value={value}>{children}</option>;
  return { Select, SelectTrigger: () => null, SelectValue: () => null, SelectContent: Pass, SelectItem: Item };
});

const namespaces = [
  { name: "docs", dimension: 384, metric: "COSINE", vectorCount: 1500, createdAt: 1_700_000_000 },
  { name: "images", dimension: 512, metric: "EUCLIDEAN", vectorCount: 0, createdAt: 1_700_000_000 },
  { name: "audio", dimension: 768, metric: "MANHATTAN", vectorCount: 20, createdAt: 1_700_000_000 },
  { name: "odd", dimension: 128, metric: "WEIRD", vectorCount: 0, createdAt: 1_700_000_000 },
];

function rowFor(name: string): HTMLElement {
  const row = screen.getByText(name).closest("tr");
  if (!row) throw new Error(`no table row for ${name}`);
  return row;
}

function stat(title: string): string {
  // "Collections" also titles the table card; the statistics cards come first.
  const card = screen.getAllByText(title)[0].parentElement?.parentElement;
  return card?.querySelector(".text-2xl")?.textContent?.trim() ?? "";
}

async function openCreate() {
  fireEvent.click(screen.getByRole("button", { name: /^Create Collection$/ }));
  return (await screen.findByLabelText("Collection Name")) as HTMLInputElement;
}

async function searchFromRow(name: string) {
  fireEvent.click(within(rowFor(name)).getByRole("menuitem", { name: /Search Vectors/ }));
  return (await screen.findByLabelText("Query Vector (JSON array)")) as HTMLTextAreaElement;
}

function submitButton(label: string): HTMLElement {
  const dialog = screen.getByRole("dialog");
  return within(dialog).getByRole("button", { name: label });
}

describe("VectorDatabasePage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vector.listNamespaces.mockResolvedValue(ok({ namespaces }));
    vector.createNamespace.mockResolvedValue(ok({ name: "new" }));
    vector.deleteNamespace.mockResolvedValue(ok({}));
    vector.search.mockResolvedValue(
      ok({ results: [{ id: "v-1", score: 0.98765 }, { id: "v-2", score: 0.5 }] }),
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("lists the namespaces as collections with metric, default index, count and date", async () => {
    render(<VectorDatabasePage />);
    const docs = within(await screen.findByText("docs").then(() => rowFor("docs")));
    expect(vector.listNamespaces).toHaveBeenCalledWith({ limit: 100 });
    expect(docs.getByText("384")).toBeTruthy();
    expect(docs.getByText("Cosine")).toBeTruthy();
    expect(docs.getByText("HNSW")).toBeTruthy();
    expect(docs.getByText((1500).toLocaleString())).toBeTruthy();
    expect(docs.getByText("-")).toBeTruthy();
    expect(docs.getByText(new Date(1_700_000_000 * 1000).toLocaleDateString())).toBeTruthy();
    expect(within(rowFor("images")).getByText("Euclidean")).toBeTruthy();
    expect(within(rowFor("audio")).getByText("Manhattan")).toBeTruthy();
    expect(within(rowFor("odd")).getByText("WEIRD")).toBeTruthy();
  });

  it("counts collections, vectors, average dimensions and collections with data", async () => {
    render(<VectorDatabasePage />);
    await screen.findByText("docs");
    expect(stat("Collections")).toBe("4");
    expect(stat("Total Vectors")).toBe((1520).toLocaleString());
    expect(stat("Avg Dimensions")).toBe("448");
    expect(stat("Search Ready")).toBe("2");
  });

  it("shows zero statistics and the empty state without namespaces", async () => {
    vector.listNamespaces.mockResolvedValue(ok({}));
    render(<VectorDatabasePage />);
    expect(await screen.findByText("No collections found")).toBeTruthy();
    expect(stat("Collections")).toBe("0");
    expect(stat("Avg Dimensions")).toBe("0");
    fireEvent.click(screen.getByRole("button", { name: /Create your first collection/ }));
    expect(await screen.findByLabelText("Collection Name")).toBeTruthy();
  });

  it("shows and reports a refused list", async () => {
    vector.listNamespaces.mockResolvedValue(refused("vector store down"));
    render(<VectorDatabasePage />);
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error loading collections", description: "vector store down" }),
      ),
    );
    expect(screen.getByText("vector store down")).toBeTruthy();
  });

  it("refuses to create a collection without a name", async () => {
    render(<VectorDatabasePage />);
    const name = await openCreate();
    fireEvent.change(name, { target: { value: "   " } });
    fireEvent.click(submitButton("Create Collection"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "Collection name is required" })),
    );
    expect(vector.createNamespace).not.toHaveBeenCalled();
  });

  it("creates a 384 dimension cosine HNSW collection by default and reloads", async () => {
    render(<VectorDatabasePage />);
    await screen.findByText("docs");
    fireEvent.change(await openCreate(), { target: { value: "embeddings" } });
    fireEvent.click(submitButton("Create Collection"));
    await waitFor(() =>
      expect(vector.createNamespace).toHaveBeenCalledWith({
        name: "embeddings",
        dimension: 384,
        metric: "COSINE",
        indexConfig: { type: "hnsw" },
      }),
    );
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Collection created", description: 'Collection "embeddings" created successfully' }),
      ),
    );
    await waitFor(() => expect(vector.listNamespaces).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("maps the chosen dimensions, metric and index type", async () => {
    render(<VectorDatabasePage />);
    fireEvent.change(await openCreate(), { target: { value: "big" } });
    fireEvent.change(screen.getByDisplayValue("384 (MiniLM)"), { target: { value: "1536" } });
    fireEvent.change(screen.getByDisplayValue("Cosine"), { target: { value: "dot_product" } });
    fireEvent.change(screen.getByDisplayValue("HNSW (Approximate)"), { target: { value: "ivf" } });
    fireEvent.click(submitButton("Create Collection"));
    await waitFor(() =>
      expect(vector.createNamespace).toHaveBeenCalledWith({
        name: "big",
        dimension: 1536,
        metric: "DOT_PRODUCT",
        indexConfig: { type: "ivf" },
      }),
    );
  });

  it("maps euclidean and keeps the dialog open on a refused create", async () => {
    vector.createNamespace.mockResolvedValue(refused("name taken"));
    render(<VectorDatabasePage />);
    fireEvent.change(await openCreate(), { target: { value: "docs" } });
    fireEvent.change(screen.getByDisplayValue("Cosine"), { target: { value: "euclidean" } });
    fireEvent.click(submitButton("Create Collection"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error creating collection", description: "name taken" }),
      ),
    );
    expect(vector.createNamespace).toHaveBeenCalledWith(expect.objectContaining({ metric: "EUCLIDEAN" }));
    expect(screen.getByRole("dialog")).toBeTruthy();
  });

  it("deletes a collection with force only after confirmation", async () => {
    vi.stubGlobal("confirm", vi.fn().mockReturnValueOnce(false).mockReturnValue(true));
    render(<VectorDatabasePage />);
    await screen.findByText("docs");
    fireEvent.click(within(rowFor("images")).getByRole("menuitem", { name: /Delete/ }));
    expect(vector.deleteNamespace).not.toHaveBeenCalled();
    fireEvent.click(within(rowFor("images")).getByRole("menuitem", { name: /Delete/ }));
    await waitFor(() => expect(vector.deleteNamespace).toHaveBeenCalledWith({ name: "images", force: true }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Collection deleted", description: 'Collection "images" deleted successfully' }),
      ),
    );
    await waitFor(() => expect(vector.listNamespaces).toHaveBeenCalledTimes(2));
  });

  it("reports a refused delete", async () => {
    vi.stubGlobal("confirm", vi.fn(() => true));
    vector.deleteNamespace.mockResolvedValue(refused("in use"));
    render(<VectorDatabasePage />);
    await screen.findByText("docs");
    fireEvent.click(within(rowFor("docs")).getByRole("menuitem", { name: /Delete/ }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error deleting collection", description: "in use" })),
    );
    expect(vector.listNamespaces).toHaveBeenCalledTimes(1);
  });

  it("refuses a search without a collection", async () => {
    render(<VectorDatabasePage />);
    await screen.findByText("docs");
    fireEvent.click(screen.getByRole("button", { name: /^Search Vectors$/ }));
    fireEvent.change(await screen.findByLabelText("Query Vector (JSON array)"), { target: { value: "[1]" } });
    fireEvent.click(submitButton("Search"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "Please select a collection" })),
    );
    expect(vector.search).not.toHaveBeenCalled();
  });

  it("refuses a query vector that is not a JSON array of numbers", async () => {
    render(<VectorDatabasePage />);
    await screen.findByText("docs");
    const input = await searchFromRow("docs");
    for (const bad of ["", "not json", "{\"a\":1}", "[1, \"two\"]"]) {
      toast.mockClear();
      fireEvent.change(input, { target: { value: bad } });
      fireEvent.click(submitButton("Search"));
      await waitFor(() =>
        expect(toast).toHaveBeenCalledWith(
          expect.objectContaining({ description: "Vector must be a valid JSON array of numbers" }),
        ),
      );
    }
    expect(vector.search).not.toHaveBeenCalled();
  });

  it("searches the row's collection with top 10 and shows the scored results", async () => {
    render(<VectorDatabasePage />);
    await screen.findByText("docs");
    fireEvent.change(await searchFromRow("audio"), { target: { value: "[0.1, 0.2]" } });
    fireEvent.click(submitButton("Search"));
    await waitFor(() =>
      expect(vector.search).toHaveBeenCalledWith({
        namespace: "audio",
        vector: [0.1, 0.2],
        topK: 10,
        includeMetadata: true,
      }),
    );
    expect(await screen.findByText("Results (2)")).toBeTruthy();
    expect(screen.getByText("v-1")).toBeTruthy();
    expect(screen.getByText("Score: 0.9877")).toBeTruthy();
    expect(screen.getByText("Score: 0.5000")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Search completed", description: "Found 2 results" }));
  });

  it("uses the chosen collection and top K, and falls back to 10 for an invalid top K", async () => {
    render(<VectorDatabasePage />);
    await screen.findByText("docs");
    fireEvent.click(screen.getByRole("button", { name: /^Search Vectors$/ }));
    fireEvent.change(await screen.findByLabelText("Query Vector (JSON array)"), { target: { value: "[]" } });
    fireEvent.change(screen.getByDisplayValue("none"), { target: { value: "images" } });
    fireEvent.change(screen.getByLabelText("Top K Results"), { target: { value: "3" } });
    fireEvent.click(submitButton("Search"));
    await waitFor(() =>
      expect(vector.search).toHaveBeenCalledWith(expect.objectContaining({ namespace: "images", vector: [], topK: 3 })),
    );
    fireEvent.change(screen.getByLabelText("Top K Results"), { target: { value: "0" } });
    expect((screen.getByLabelText("Top K Results") as HTMLInputElement).value).toBe("10");
  });

  it("offers each named collection with its dimension in the search picker", async () => {
    vector.listNamespaces.mockResolvedValue(ok({ namespaces: [...namespaces, { ...namespaces[1], name: "" }] }));
    render(<VectorDatabasePage />);
    await screen.findByText("docs");
    fireEvent.click(screen.getByRole("button", { name: /^Search Vectors$/ }));
    const picker = (await screen.findByDisplayValue("none")) as HTMLSelectElement;
    expect(Array.from(picker.options).map((o) => o.textContent)).toEqual([
      "none",
      "docs (384d)",
      "images (512d)",
      "audio (768d)",
      "odd (128d)",
    ]);
  });

  it("reports no results and a refused search", async () => {
    vector.search.mockResolvedValueOnce(ok({})).mockResolvedValueOnce(refused("dimension mismatch"));
    render(<VectorDatabasePage />);
    await screen.findByText("docs");
    fireEvent.change(await searchFromRow("docs"), { target: { value: "[1]" } });
    fireEvent.click(submitButton("Search"));
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "Found 0 results" })));
    expect(screen.queryByText(/^Results/)).toBeNull();
    fireEvent.click(submitButton("Search"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Search failed", description: "dimension mismatch" })),
    );
  });

  it("clears the results and query vector when the search dialog closes", async () => {
    render(<VectorDatabasePage />);
    await screen.findByText("docs");
    fireEvent.change(await searchFromRow("docs"), { target: { value: "[1]" } });
    fireEvent.click(submitButton("Search"));
    expect(await screen.findByText("Results (2)")).toBeTruthy();
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const input = await searchFromRow("docs");
    expect(input.value).toBe("");
    expect(screen.queryByText("Results (2)")).toBeNull();
  });
});
