"use client";

/**
 * BMC boot-media hook: SetBootDevice and GetBootDevice
 * (`POST` / `GET /api/v1/bmc/{profileID}/boot-device`), MountISO, UnmountISO
 * and VirtualMediaStatus (`POST` / `DELETE` / `GET
 * /api/v1/bmc/{profileID}/virtual-media`), served by
 * pkg/webservice/v1/bmc/handler.go.
 *
 * Calls the SDK API client directly, as use-ntp.ts does, because the SDK has
 * no BMC service on main. A boot-device change takes effect at the next boot.
 */

import { useMemo } from "react";
import { usePlatformClient } from "trusted-platform-sdk";

/** The boot devices the BMC handler accepts (pkg/bmc/types.go). */
export const BMC_BOOT_DEVICES = ["pxe", "disk", "cdrom", "virtual_media", "none"] as const;

export type BMCBootDevice = (typeof BMC_BOOT_DEVICES)[number];

export interface BMCBootDeviceResult {
  device: string;
}

export interface BMCSetBootDeviceResult {
  status: string;
  device: string;
}

/** pkg/bmc/types.go VirtualMediaInfo. */
export interface BMCVirtualMediaStatus {
  mounted: boolean;
  image_url?: string;
  media_type?: string;
}

export interface BMCMountISOResult {
  status: string;
  iso_url: string;
}

export interface BMCStatusResult {
  status: string;
}

export function isBMCBootDevice(s: string): s is BMCBootDevice {
  return (BMC_BOOT_DEVICES as readonly string[]).includes(s);
}

const BOOT_DEVICE_LABELS: Record<BMCBootDevice, string> = {
  pxe: "PXE",
  disk: "Disk",
  cdrom: "CD-ROM",
  virtual_media: "Virtual media",
  none: "None",
};

/** "PXE", "Disk", "CD-ROM", "Virtual media", "None". */
export function bmcBootDeviceLabel(d: BMCBootDevice): string {
  return BOOT_DEVICE_LABELS[d];
}

/** The API client path of a BMC profile operation; the profile id is escaped. */
export function bmcPath(profileID: string, op: string): string {
  return `/v1/bmc/${encodeURIComponent(profileID)}/${op}`;
}

export function useBMCBootMedia(profileID: string) {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    return {
      getBootDevice: () => api.get<BMCBootDeviceResult>(bmcPath(profileID, "boot-device")),
      // Boot device, mount and eject are writes: a dropped reply does not
      // show the server skipped them, so they are sent once and never
      // replayed (a late eject retry could remove media mounted since).
      setBootDevice: (device: BMCBootDevice, persistent = false) =>
        api.post<BMCSetBootDeviceResult>(
          bmcPath(profileID, "boot-device"),
          { device, persistent },
          { retry: { enabled: false } }
        ),
      getVirtualMedia: () => api.get<BMCVirtualMediaStatus>(bmcPath(profileID, "virtual-media")),
      mountISO: (isoURL: string) =>
        api.post<BMCMountISOResult>(
          bmcPath(profileID, "virtual-media"),
          { iso_url: isoURL.trim() },
          { retry: { enabled: false } }
        ),
      unmountISO: () =>
        api.delete<BMCStatusResult>(bmcPath(profileID, "virtual-media"), { retry: { enabled: false } }),
    };
  }, [client, profileID]);
}
