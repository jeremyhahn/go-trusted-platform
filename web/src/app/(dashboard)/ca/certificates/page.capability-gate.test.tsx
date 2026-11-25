import * as React from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the certificates page lists, issues, renews and revokes through
// useCA (network boundary, mocked here) and gates the list and every control
// on the server's capabilities.

const { ca, capability, caps, push } = vi.hoisted(() => ({
  ca: {
    listCertificates: vi.fn(),
    issueCertificate: vi.fn(),
    revokeCertificate: vi.fn(),
    renewCertificate: vi.fn(),
  },
  capability: vi.fn(),
  caps: { loading: false },
  push: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useCA: () => ca,
}));

// #2033 item 5: Gated and the page read the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: caps.loading, error: undefined, capability }),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push, replace: vi.fn(), back: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/ca/certificates",
}));

// The Radix menu's portal does not settle in jsdom, so row menus render inline
// and keep the gate's disabled and title.
vi.mock("@/components/ui/dropdown-menu", async (importOriginal) => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Item = ({
    children,
    onClick,
    disabled,
    title,
  }: {
    children?: React.ReactNode;
    onClick?: () => void;
    disabled?: boolean;
    title?: string;
  }) => (
    <button type="button" role="menuitem" onClick={onClick} disabled={disabled} title={title}>
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

import CertificatesPage from "./page";

const LIST_OP = "GET /api/v1/ca/certificates";
const ISSUE_OP = "POST /api/v1/ca/certificates";
const RENEW_OP = "POST /api/v1/ca/certificates/{serial}/renew";
const REVOKE_OP = "DELETE /api/v1/ca/certificates/{serial}";
const REASON = "blocked: integration";

const cert = {
  serial: "0a1b2c3d",
  commonName: "leaf.example.com",
  issuer: "Example Issuing CA",
  status: "ACTIVE",
  notBefore: Math.floor(Date.now() / 1000) - 86400,
  notAfter: Math.floor(Date.now() / 1000) + 365 * 86400,
  keyAlgorithm: "ECDSA-P256",
};

function offExcept(off: string[]) {
  capability.mockImplementation((op: string) => (off.includes(op) ? { enabled: false, reason: REASON } : { enabled: true }));
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole("button", { name }) as HTMLButtonElement;
}

function expectWithheld(el: HTMLElement, op?: string) {
  expect((el as HTMLButtonElement).disabled).toBe(true);
  expect(el.getAttribute("title")).toBe(REASON);
  if (op) {
    expect(el.getAttribute("data-capability-op")).toBe(op);
    expect(el.getAttribute("data-capability-enabled")).toBe("false");
  }
}

async function certRow(): Promise<HTMLElement> {
  const cell = await screen.findByText("leaf.example.com");
  return cell.closest("tr") as HTMLElement;
}

beforeEach(() => {
  for (const fn of Object.values(ca)) fn.mockReset();
  ca.listCertificates.mockResolvedValue({ data: { certificates: [] } });
  ca.issueCertificate.mockResolvedValue({ data: {} });
  ca.revokeCertificate.mockResolvedValue({ data: {} });
  ca.renewCertificate.mockResolvedValue({ data: {} });
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
  caps.loading = false;
  push.mockReset();
});

afterEach(() => {
  cleanup();
});

describe("CertificatesPage capability gate", () => {
  it("shows the not-enabled card with the server's reason and does not list when GET /api/v1/ca/certificates is not offered", async () => {
    offExcept([LIST_OP]);
    render(<CertificatesPage />);

    const card = await screen.findByTestId("ca-certificates-not-enabled");
    expect(card.textContent).toContain(REASON);
    expect(ca.listCertificates).not.toHaveBeenCalled();
    expectWithheld(button("Refresh"), LIST_OP);
  });

  it("neither lists nor shows the not-enabled card while the capabilities load", async () => {
    caps.loading = true;
    capability.mockImplementation(() => ({ enabled: false, reason: "loading" }));
    render(<CertificatesPage />);

    await screen.findByText("Certificates");
    expect(screen.queryByTestId("ca-certificates-not-enabled")).toBeNull();
    expect(ca.listCertificates).not.toHaveBeenCalled();
  });

  it("withholds Issue Certificate when POST /api/v1/ca/certificates is not offered", async () => {
    offExcept([ISSUE_OP]);
    render(<CertificatesPage />);
    await screen.findByText("Certificates");

    expectWithheld(button("Issue Certificate"), ISSUE_OP);
  });

  it("disables an active certificate's Renew and Revoke when their ops are not offered", async () => {
    ca.listCertificates.mockResolvedValue({ data: { certificates: [cert] } });
    offExcept([RENEW_OP, REVOKE_OP]);
    render(<CertificatesPage />);
    const row = await certRow();

    expectWithheld(within(row).getByRole("menuitem", { name: /Renew/ }));
    expectWithheld(within(row).getByRole("menuitem", { name: /Revoke/ }));
  });

  it("enables Refresh, Issue Certificate, Renew and Revoke when the server offers them", async () => {
    ca.listCertificates.mockResolvedValue({ data: { certificates: [cert] } });
    render(<CertificatesPage />);
    const row = await certRow();

    expect(ca.listCertificates).toHaveBeenCalled();
    expect(screen.queryByTestId("ca-certificates-not-enabled")).toBeNull();
    expect(button("Refresh").disabled).toBe(false);
    expect(button("Issue Certificate").disabled).toBe(false);
    expect((within(row).getByRole("menuitem", { name: /Renew/ }) as HTMLButtonElement).disabled).toBe(false);
    expect((within(row).getByRole("menuitem", { name: /Revoke/ }) as HTMLButtonElement).disabled).toBe(false);
  });
});
