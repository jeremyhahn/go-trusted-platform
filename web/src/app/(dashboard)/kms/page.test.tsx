import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";

import type { GenerateKeyInput, Key } from "@/types/security";

type ApiOptions = { onError?: (err: Error) => void };
type MutationOptions = {
  onSuccess?: (result: unknown) => void;
  onError?: (err: Error) => void;
};
type TableProps = {
  keys: Key[];
  loading: boolean;
  onView: (k: Key) => void;
  onRotate: (k: Key) => Promise<void>;
  onExport: (k: Key) => Promise<void>;
  onDelete: (k: Key) => Promise<void>;
};
type FormProps = { onSubmit: (d: GenerateKeyInput) => Promise<void>; loading: boolean };

const h = vi.hoisted(() => ({
  push: vi.fn(),
  toast: vi.fn(),
  refetch: vi.fn(),
  kms: {
    listKeys: vi.fn(),
    generateKey: vi.fn(),
    rotateKey: vi.fn(),
    deleteKey: vi.fn(),
    exportKey: vi.fn(),
  },
  api: {
    data: undefined as unknown,
    isLoading: false,
    error: null as Error | null,
    fetcher: undefined as undefined | (() => unknown),
    options: undefined as undefined | { onError?: (err: Error) => void },
  },
  table: undefined as unknown,
  form: undefined as unknown,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: h.push }),
}));

vi.mock("@/hooks", () => ({
  useKMS: () => h.kms,
  useToast: () => ({ toast: h.toast }),
  useApi: (fetcher: () => unknown, _deps: unknown[], options: ApiOptions) => {
    h.api.fetcher = fetcher;
    h.api.options = options;
    return {
      data: h.api.data,
      isLoading: h.api.isLoading,
      error: h.api.error,
      refetch: h.refetch,
    };
  },
  useMutation: <T, R>(fn: (v: T) => Promise<R>, options: MutationOptions) => {
    const mutateAsync = async (v: T) => {
      try {
        const r = await fn(v);
        options.onSuccess?.(r);
        return r;
      } catch (e) {
        options.onError?.(e as Error);
        throw e;
      }
    };
    return {
      mutate: (v: T) => {
        mutateAsync(v).catch(() => undefined);
      },
      mutateAsync,
      isLoading: false,
    };
  },
}));

vi.mock("@/components/features/kms/key-table", () => ({
  KeyTable: (props: TableProps) => {
    h.table = props;
    return (
      <ul data-testid="key-table" data-loading={String(props.loading)}>
        {props.keys.map((k) => (
          <li key={k.id}>{k.id}</li>
        ))}
      </ul>
    );
  },
}));

vi.mock("@/components/features/kms/key-form", () => ({
  KeyForm: (props: FormProps) => {
    h.form = props;
    return <div data-testid="key-form" />;
  },
}));

import KMSKeysPage from "./page";

const table = () => h.table as TableProps;
const form = () => h.form as FormProps;

const key = (over: Partial<Key> = {}): Key =>
  ({
    id: "k1",
    name: "Alpha",
    algorithm: "AES-256",
    type: "symmetric",
    status: "active",
    createdAt: "2026-01-02T03:04:05Z",
    rotationCount: 0,
    ...over,
  }) as Key;

describe("KMSKeysPage", () => {
  let confirmSpy: MockInstance<(message?: string) => boolean>;

  beforeEach(() => {
    h.api.data = undefined;
    h.api.isLoading = false;
    h.api.error = null;
    h.table = undefined;
    h.form = undefined;
    confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
    vi.useRealTimers();
  });

  describe("rendering", () => {
    it("renders the heading and an empty table when no data has loaded", () => {
      render(<KMSKeysPage />);
      expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Cryptographic Keys");
      expect(table().keys).toEqual([]);
      expect(screen.queryByText("Error")).toBeNull();
    });

    it("treats a response without a keys field as an empty list", () => {
      h.api.data = {};
      render(<KMSKeysPage />);
      expect(table().keys).toEqual([]);
    });

    it("fetches the key list through the KMS client", () => {
      h.kms.listKeys.mockResolvedValue({ keys: [] });
      render(<KMSKeysPage />);
      h.api.fetcher?.();
      expect(h.kms.listKeys).toHaveBeenCalledTimes(1);
    });

    it("disables Refresh and flags the table while loading", () => {
      h.api.isLoading = true;
      render(<KMSKeysPage />);
      const refresh = screen.getByRole("button", { name: /Refresh/ }) as HTMLButtonElement;
      expect(refresh.disabled).toBe(true);
      expect(table().loading).toBe(true);
    });

    it("refetches when Refresh is clicked", () => {
      render(<KMSKeysPage />);
      fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));
      expect(h.refetch).toHaveBeenCalledTimes(1);
    });

    it("shows the load error message", () => {
      h.api.error = new Error("kms unavailable");
      render(<KMSKeysPage />);
      expect(screen.getByText("Error")).toBeTruthy();
      expect(screen.getByText("kms unavailable")).toBeTruthy();
    });

    it("toasts a destructive message when loading fails", () => {
      render(<KMSKeysPage />);
      h.api.options?.onError?.(new Error("boom"));
      expect(h.toast).toHaveBeenCalledWith({
        title: "Error loading keys",
        description: "boom",
        variant: "destructive",
      });
    });
  });

  describe("key mapping", () => {
    it("maps a camelCase key", () => {
      h.api.data = {
        keys: [
          {
            keyId: "k1",
            name: "Alpha",
            algorithm: "AES_256",
            status: "ENABLED",
            createdAt: "2026-01-02T03:04:05Z",
            version: 3,
          },
        ],
      };
      render(<KMSKeysPage />);
      expect(table().keys).toEqual([
        {
          id: "k1",
          name: "Alpha",
          algorithm: "AES-256",
          type: "symmetric",
          status: "active",
          createdAt: "2026-01-02T03:04:05Z",
          rotationCount: 2,
        },
      ]);
    });

    it("maps a snake_case key with an epoch-second timestamp and no name", () => {
      h.api.data = {
        keys: [{ key_id: "k2", algorithm: "RSA_4096", status: "disabled", created_at: 1700000000 }],
      };
      render(<KMSKeysPage />);
      expect(table().keys).toEqual([
        {
          id: "k2",
          name: "k2",
          algorithm: "RSA-4096",
          type: "asymmetric",
          status: "disabled",
          createdAt: new Date(1700000000 * 1000).toISOString(),
          rotationCount: 0,
        },
      ]);
    });

    it("prefers keyId over key_id and createdAt over created_at", () => {
      h.api.data = {
        keys: [
          {
            keyId: "camel",
            key_id: "snake",
            algorithm: "ECDSA_P256",
            createdAt: "2026-03-03T00:00:00Z",
            created_at: "1999-01-01T00:00:00Z",
          },
        ],
      };
      render(<KMSKeysPage />);
      expect(table().keys[0].id).toBe("camel");
      expect(table().keys[0].createdAt).toBe("2026-03-03T00:00:00Z");
    });

    it.each([
      ["RSA_2048", "RSA-2048", "asymmetric"],
      ["ECDSA_P256", "ECDSA-P256", "asymmetric"],
      ["ECDSA_P384", "ECDSA-P384", "asymmetric"],
      ["AES_128", "AES-256", "symmetric"],
      ["HMAC_SHA256", "AES-256", "symmetric"],
      ["CHACHA20_POLY1305", "AES-256", "symmetric"],
      ["NOT_AN_ALGORITHM", "AES-256", "asymmetric"],
      ["", "AES-256", "asymmetric"],
    ])("maps algorithm %j to %s (%s)", (wire, algorithm, type) => {
      h.api.data = { keys: [{ keyId: "k", algorithm: wire }] };
      render(<KMSKeysPage />);
      expect(table().keys[0].algorithm).toBe(algorithm);
      expect(table().keys[0].type).toBe(type);
    });

    it.each([["enabled"], ["Enabled"], ["ENABLED"]])("treats status %j as active", (status) => {
      h.api.data = { keys: [{ keyId: "k", algorithm: "AES_256", status }] };
      render(<KMSKeysPage />);
      expect(table().keys[0].status).toBe("active");
    });

    it.each([["DISABLED"], ["PENDING_DELETION"], [""], [undefined]])(
      "treats status %j as disabled",
      (status) => {
        h.api.data = { keys: [{ keyId: "k", algorithm: "AES_256", status }] };
        render(<KMSKeysPage />);
        expect(table().keys[0].status).toBe("disabled");
      },
    );

    it("falls back to the current time for a missing, zero or Go zero-time timestamp", () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(new Date("2026-11-12T10:00:00Z"));
      h.api.data = {
        keys: [
          { keyId: "missing", algorithm: "AES_256" },
          { keyId: "zero", algorithm: "AES_256", created_at: 0 },
          { keyId: "empty", algorithm: "AES_256", createdAt: "" },
          { keyId: "gozero", algorithm: "AES_256", createdAt: "0001-01-01T00:00:00Z" },
        ],
      };
      render(<KMSKeysPage />);
      for (const k of table().keys) {
        expect(k.createdAt).toBe("2026-11-12T10:00:00.000Z");
      }
    });

    it("gives a key with no id an empty id and name", () => {
      h.api.data = { keys: [{ algorithm: "AES_256", version: 1 }] };
      render(<KMSKeysPage />);
      expect(table().keys[0].id).toBe("");
      expect(table().keys[0].name).toBe("");
      expect(table().keys[0].rotationCount).toBe(0);
    });
  });

  describe("view", () => {
    it("navigates to the key detail page with the id URL-encoded", () => {
      render(<KMSKeysPage />);
      table().onView(key({ id: "a/b c" }));
      expect(h.push).toHaveBeenCalledWith("/kms/a%2Fb%20c");
    });
  });

  describe("rotate", () => {
    it("does nothing when the user cancels", async () => {
      confirmSpy.mockReturnValue(false);
      render(<KMSKeysPage />);
      await table().onRotate(key());
      expect(confirmSpy).toHaveBeenCalledWith('Rotate key "Alpha"? This will create a new version.');
      expect(h.kms.rotateKey).not.toHaveBeenCalled();
    });

    it("rotates, retaining the old version, then toasts and reloads", async () => {
      h.kms.rotateKey.mockResolvedValue({});
      render(<KMSKeysPage />);
      await table().onRotate(key());
      await waitFor(() => expect(h.refetch).toHaveBeenCalledTimes(1));
      expect(h.kms.rotateKey).toHaveBeenCalledWith({ keyId: "k1", retainOldVersion: true });
      expect(h.toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Key rotated", variant: "success" }));
    });

    it("toasts the error and does not reload when rotation fails", async () => {
      h.kms.rotateKey.mockRejectedValue(new Error("rotate denied"));
      render(<KMSKeysPage />);
      await table().onRotate(key());
      await waitFor(() =>
        expect(h.toast).toHaveBeenCalledWith({
          title: "Error rotating key",
          description: "rotate denied",
          variant: "destructive",
        }),
      );
      expect(h.refetch).not.toHaveBeenCalled();
    });
  });

  describe("delete", () => {
    it("does nothing when the user cancels", async () => {
      confirmSpy.mockReturnValue(false);
      render(<KMSKeysPage />);
      await table().onDelete(key());
      expect(confirmSpy).toHaveBeenCalledWith('Delete key "Alpha"? This action cannot be undone.');
      expect(h.kms.deleteKey).not.toHaveBeenCalled();
    });

    it("deletes, then toasts and reloads", async () => {
      h.kms.deleteKey.mockResolvedValue({});
      render(<KMSKeysPage />);
      await table().onDelete(key());
      await waitFor(() => expect(h.refetch).toHaveBeenCalledTimes(1));
      expect(h.kms.deleteKey).toHaveBeenCalledWith({ keyId: "k1" });
      expect(h.toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Key deleted", variant: "success" }));
    });

    it("toasts the error when deletion fails", async () => {
      h.kms.deleteKey.mockRejectedValue(new Error("in use"));
      render(<KMSKeysPage />);
      await table().onDelete(key());
      await waitFor(() =>
        expect(h.toast).toHaveBeenCalledWith({
          title: "Error deleting key",
          description: "in use",
          variant: "destructive",
        }),
      );
      expect(h.refetch).not.toHaveBeenCalled();
    });
  });

  describe("export", () => {
    let createObjectURL: ReturnType<typeof vi.fn>;
    let revokeObjectURL: ReturnType<typeof vi.fn>;
    let click: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
      createObjectURL = vi.fn(() => "blob:export");
      revokeObjectURL = vi.fn();
      Object.assign(window.URL, { createObjectURL, revokeObjectURL });
      click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    });

    it("does nothing when the user cancels", async () => {
      confirmSpy.mockReturnValue(false);
      render(<KMSKeysPage />);
      await table().onExport(key());
      expect(confirmSpy).toHaveBeenCalledWith('Export key "Alpha"? This will expose the key material.');
      expect(h.kms.exportKey).not.toHaveBeenCalled();
    });

    it("downloads the wrapped material as JSON and cleans up", async () => {
      h.kms.exportKey.mockResolvedValue({
        keyId: "k1",
        format: "JWK",
        wrappedMaterial: "d3JhcHBlZA==",
        version: 2,
        extra: "not exported",
      });
      render(<KMSKeysPage />);
      await table().onExport(key());
      await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
      expect(h.kms.exportKey).toHaveBeenCalledWith({ keyId: "k1" });
      const blob = createObjectURL.mock.calls[0][0] as Blob;
      expect(blob.type).toBe("application/json");
      const text = await new Promise<string>((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.readAsText(blob);
      });
      expect(JSON.parse(text)).toEqual({
        keyId: "k1",
        format: "JWK",
        wrappedMaterial: "d3JhcHBlZA==",
        version: 2,
      });
      const anchor = click.mock.contexts[0] as HTMLAnchorElement;
      expect(anchor.download).toBe("key_export.json");
      expect(revokeObjectURL).toHaveBeenCalledWith("blob:export");
      expect(document.querySelector("a[download]")).toBeNull();
    });

    it.each([[{}], [{ keyId: "k1", wrappedMaterial: "" }], [null], [undefined]])(
      "downloads nothing when the result %j has no wrapped material",
      async (result) => {
        h.kms.exportKey.mockResolvedValue(result);
        render(<KMSKeysPage />);
        await table().onExport(key());
        await waitFor(() => expect(h.kms.exportKey).toHaveBeenCalled());
        await act(async () => undefined);
        expect(createObjectURL).not.toHaveBeenCalled();
        expect(click).not.toHaveBeenCalled();
      },
    );

    it("toasts the error when export fails", async () => {
      h.kms.exportKey.mockRejectedValue(new Error("not exportable"));
      render(<KMSKeysPage />);
      await table().onExport(key());
      await waitFor(() =>
        expect(h.toast).toHaveBeenCalledWith({
          title: "Error exporting key",
          description: "not exportable",
          variant: "destructive",
        }),
      );
      expect(click).not.toHaveBeenCalled();
    });
  });

  describe("generate", () => {
    const openDialog = () => {
      render(<KMSKeysPage />);
      expect(screen.queryByTestId("key-form")).toBeNull();
      fireEvent.click(screen.getByRole("button", { name: /Generate Key/ }));
      expect(screen.getByTestId("key-form")).toBeTruthy();
      expect(screen.getByText("Generate New Key")).toBeTruthy();
    };

    it.each([
      ["AES-256", "AES_256"],
      ["RSA-2048", "RSA_2048"],
      ["RSA-4096", "RSA_4096"],
      ["ECDSA-P256", "ECDSA_P256"],
      ["ECDSA-P384", "ECDSA_P384"],
    ])("generates a %s key as %s, then closes the dialog and reloads", async (web, sdk) => {
      h.kms.generateKey.mockResolvedValue({});
      openDialog();
      await act(async () => {
        await form().onSubmit({ name: "new-key", algorithm: web } as GenerateKeyInput);
      });
      expect(h.kms.generateKey).toHaveBeenCalledWith({
        keySpec: { algorithm: sdk, usage: ["ENCRYPT", "DECRYPT"] },
        name: "new-key",
      });
      expect(h.toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Key generated", variant: "success" }));
      expect(h.refetch).toHaveBeenCalledTimes(1);
      await waitFor(() => expect(screen.queryByTestId("key-form")).toBeNull());
    });

    it("falls back to AES_256 for an unknown algorithm", async () => {
      h.kms.generateKey.mockResolvedValue({});
      openDialog();
      await act(async () => {
        await form().onSubmit({ name: "x", algorithm: "DES" } as unknown as GenerateKeyInput);
      });
      expect(h.kms.generateKey).toHaveBeenCalledWith(
        expect.objectContaining({ keySpec: { algorithm: "AES_256", usage: ["ENCRYPT", "DECRYPT"] } }),
      );
    });

    it("toasts the error, rejects the submit and keeps the dialog open on failure", async () => {
      h.kms.generateKey.mockRejectedValue(new Error("quota exceeded"));
      openDialog();
      let caught: unknown;
      await act(async () => {
        await form()
          .onSubmit({ name: "x", algorithm: "AES-256" } as GenerateKeyInput)
          .catch((e: unknown) => {
            caught = e;
          });
      });
      expect((caught as Error).message).toBe("quota exceeded");
      expect(h.toast).toHaveBeenCalledWith({
        title: "Error generating key",
        description: "quota exceeded",
        variant: "destructive",
      });
      expect(h.refetch).not.toHaveBeenCalled();
      expect(screen.getByTestId("key-form")).toBeTruthy();
    });
  });
});
