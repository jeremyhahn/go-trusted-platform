import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient, DeviceService } from "trusted-platform-sdk";

import { AttestCertCard } from "./attest-cert-card";

// #491: the card drives POST /api/v1/devices/{id}/attest-cert/record through
// the real SDK DeviceService; only fetch and the toast are stubbed.

const fetchMock = vi.fn<typeof fetch>();
const toastMock = vi.fn();
const deviceService = new DeviceService(
  new ApiClient({ baseUrl: "https://platform.test/api", fetch: fetchMock, retry: { maxRetries: 0 } })
);

vi.mock("@/hooks", () => ({
  useDevice: () => deviceService,
  useToast: () => ({ toast: toastMock }),
}));

const REFUSAL =
  "device: attestation certificate refused for device 7; nothing recorded: " +
  "ca[node-03]: lacks tcg-cap-verifiedTPMRestricted";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function recorded(source: string, reissued: boolean) {
  return {
    code: 200,
    success: true,
    payload: {
      device_id: "7",
      changed: true,
      source,
      reissued,
      subject: "CN=iak-Device-7-SN7",
      certificate_serial: "1f2e3d",
      attest_cert: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    },
  };
}

function requestedReissue(call: number): boolean {
  const init = fetchMock.mock.calls[call][1] as RequestInit;
  return (JSON.parse(String(init.body)) as { reissue: boolean }).reissue;
}

async function openDialog() {
  await act(async () => screen.getByRole("button", { name: /record certificate/i }).click());
}

describe("AttestCertCard", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    toastMock.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("says when no certificate is recorded and shows the one that is", () => {
    const { rerender } = render(<AttestCertCard deviceId="7" onRecorded={vi.fn()} />);
    expect(screen.getByTestId("attest-cert-absent")).toBeTruthy();

    rerender(<AttestCertCard deviceId="7" attestCert="PEM-ON-RECORD" onRecorded={vi.fn()} />);
    expect(screen.queryByTestId("attest-cert-absent")).toBeNull();
    expect(screen.getByText("PEM-ON-RECORD")).toBeTruthy();
  });

  it("records without re-issuing by default and re-reads the device", async () => {
    const onRecorded = vi.fn();
    fetchMock.mockResolvedValue(jsonResponse(200, recorded("ca", false)));
    render(<AttestCertCard deviceId="7" onRecorded={onRecorded} />);

    await openDialog();
    expect(screen.queryByTestId("attest-cert-reissue-warning")).toBeNull();
    await act(async () => screen.getByRole("button", { name: /^record$/i }).click());

    expect(String(fetchMock.mock.calls[0][0])).toBe("https://platform.test/api/v1/devices/7/attest-cert/record");
    expect(requestedReissue(0)).toBe(false);
    expect(onRecorded).toHaveBeenCalledTimes(1);
    expect(toastMock).toHaveBeenCalledWith(expect.objectContaining({ title: "Certificate recorded" }));
  });

  it("re-issues only after the operator opts in and is warned", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, recorded("reissued", true)));
    render(<AttestCertCard deviceId="7" onRecorded={vi.fn()} />);

    await openDialog();
    await act(async () => fireEvent.click(screen.getByRole("checkbox")));
    expect(screen.getByTestId("attest-cert-reissue-warning")).toBeTruthy();
    await act(async () => screen.getByRole("button", { name: /record and re-issue/i }).click());

    expect(requestedReissue(0)).toBe(true);
  });

  it("shows a refusal verbatim, keeps the dialog open and does not re-read", async () => {
    const onRecorded = vi.fn();
    fetchMock.mockResolvedValue(jsonResponse(400, { code: 400, error: REFUSAL, success: false, payload: null }));
    render(<AttestCertCard deviceId="7" onRecorded={onRecorded} />);

    await openDialog();
    await act(async () => screen.getByRole("button", { name: /^record$/i }).click());

    expect(screen.getByTestId("attest-cert-refusal").textContent).toBe(REFUSAL);
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect(onRecorded).not.toHaveBeenCalled();
    expect(toastMock).not.toHaveBeenCalled();
  });
});
