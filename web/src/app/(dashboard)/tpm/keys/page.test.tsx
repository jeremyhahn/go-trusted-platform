import * as React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TPMKeysPage from "./page";

// The View Details dialog must show the server's reason when the
// certificate fetch is refused (#2068). The SDK client does not throw by
// default: a refusal comes back as resp.error with data undefined, which
// the dialog used to read as "no certificate is provisioned".

const tpm = {
  getEK: vi.fn(),
  getSRK: vi.fn(),
  getEKCertificate: vi.fn(),
};

const idevid = {
  getIAKInfo: vi.fn(),
  getIDevIDInfo: vi.fn(),
  getIAKCertificate: vi.fn(),
  getIDevIDCertificate: vi.fn(),
};

const toastResult = { toast: vi.fn() };

type Resp = { success: boolean; data?: unknown };

function useApiMock(fetcher: () => Promise<Resp>) {
  const [data, setData] = React.useState<unknown>(null);
  React.useEffect(() => {
    let alive = true;
    fetcher().then((resp) => {
      if (alive) setData(resp?.data ?? null);
    });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return { data, isLoading: false, error: null, refetch: vi.fn() };
}

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useTPM: () => tpm,
  useIDevID: () => idevid,
  useToast: () => toastResult,
  useApi: (fetcher: () => Promise<Resp>) => useApiMock(fetcher),
}));

vi.mock("@/components/features/tpm/tpm-key-lifecycle-card", () => ({
  TPMKeyLifecycleCard: () => <div data-testid="tpm-key-lifecycle-card" />,
}));

vi.mock("@/components/features/tpm/tpm-certify-card", () => ({
  TPMCertifyCard: () => <div data-testid="tpm-certify-card" />,
}));

vi.mock("@/components/ui/dropdown-menu", async (importOriginal) => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Item = ({
    children,
    onClick,
  }: {
    children?: React.ReactNode;
    onClick?: () => void;
  }) => (
    <button type="button" role="menuitem" onClick={onClick}>
      {children}
    </button>
  );
  return {
    ...(await importOriginal<typeof import("@/components/ui/dropdown-menu")>()),
    DropdownMenu: Pass,
    DropdownMenuTrigger: Pass,
    DropdownMenuContent: Pass,
    DropdownMenuLabel: Pass,
    DropdownMenuSeparator: () => null,
    DropdownMenuItem: Item,
  };
});

beforeEach(() => {
  tpm.getEK.mockResolvedValue({
    success: true,
    data: { publicKey: "EK-PEM", algorithm: "KEY_ALGORITHM_RSA_2048", handle: 0x81010001 },
  });
  tpm.getSRK.mockResolvedValue({ success: false });
  idevid.getIAKInfo.mockResolvedValue({ success: false });
  idevid.getIDevIDInfo.mockResolvedValue({ success: false });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

async function openEKDetails() {
  render(<TPMKeysPage />);
  await screen.findByText("Endorsement Key");
  fireEvent.click(await screen.findByText("View Details"));
}

describe("TPM keys View Details certificate", () => {
  it("shows the server's message when the EK certificate fetch is refused", async () => {
    tpm.getEKCertificate.mockResolvedValue({
      success: false,
      error: { code: "NOT_FOUND", message: "EK certificate not found in NV" },
    });
    await openEKDetails();
    expect(await screen.findByText("EK certificate not found in NV")).toBeTruthy();
    expect(screen.queryByText(/No certificate is provisioned/)).toBeNull();
  });

  it("says no certificate is provisioned when the server returns an empty one", async () => {
    tpm.getEKCertificate.mockResolvedValue({ success: true, data: { certificate: "" } });
    await openEKDetails();
    expect(await screen.findByText(/No certificate is provisioned/)).toBeTruthy();
  });

  it("shows the thrown error when the EK certificate fetch rejects", async () => {
    tpm.getEKCertificate.mockRejectedValue(new Error("network down"));
    await openEKDetails();
    expect(await screen.findByText("network down")).toBeTruthy();
  });
});

// #2068: the key lifecycle and certify cards are reachable from /tpm/keys.
describe("TPM keys page cards", () => {
  it("shows the key lifecycle and certify cards", async () => {
    render(<TPMKeysPage />);
    expect(await screen.findByTestId("tpm-key-lifecycle-card")).toBeTruthy();
    expect(await screen.findByTestId("tpm-certify-card")).toBeTruthy();
  });
});
