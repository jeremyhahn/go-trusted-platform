// @vitest-environment node
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// vitest runs in web/, so the matrix sits one directory up.
const matrixPath = path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md');
const lines = fs.readFileSync(matrixPath, 'utf8').split(/\r?\n/);

describe('coverage matrix: DeviceService', () => {
  it('lists the device edit, count and serial lookup as covered by their pages and the real-server spec', () => {
    const wants = [
      '| `DeviceService.UpdateDevice` | `PUT /devices/{id:[0-9]+}` | `(dashboard)/devices/[id]/page.tsx` | - | `real-server/devices.spec.ts` | covered |',
      '| `DeviceService.FindDeviceBySerial` | `GET /devices/serial/{serial}` | `(dashboard)/devices/page.tsx` | - | `real-server/devices.spec.ts` | covered |',
      '| `DeviceService.CountDevices` | `GET /devices/count` | `(dashboard)/devices/page.tsx` | - | `real-server/devices.spec.ts` | covered |',
    ];
    for (const want of wants) {
      expect(lines.filter((l) => l === want), want).toHaveLength(1);
    }
  });

  it('marks the machine-facing device routes not-UI', () => {
    const wants = [
      '| `DeviceService.GetProfile` | `GET /device/profile` | - | - | - | not-UI: machine-facing mTLS device route |',
      '| `DeviceService.BootCertificate` | `POST /device/boot/certificate` | - | - | - | not-UI: machine-facing diskless boot route |',
      '| `DeviceService.BootDelivery` | `POST /device/boot` | - | - | - | not-UI: machine-facing diskless boot route (mTLS) |',
    ];
    for (const want of wants) {
      expect(lines.filter((l) => l === want), want).toHaveLength(1);
    }
  });

  it('names files that exist', () => {
    expect(fs.existsSync(path.resolve(process.cwd(), 'src/app/(dashboard)/devices/[id]/page.tsx'))).toBe(true);
    expect(fs.existsSync(path.resolve(process.cwd(), 'src/app/(dashboard)/devices/page.tsx'))).toBe(true);
    expect(fs.existsSync(path.resolve(process.cwd(), 'e2e/real-server/devices.spec.ts'))).toBe(true);
  });
});
