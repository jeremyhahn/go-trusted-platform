// @vitest-environment node
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// vitest runs in web/, so the matrix sits one directory up.
const matrixPath = path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md');
const lines = fs.readFileSync(matrixPath, 'utf8').split(/\r?\n/);

describe('coverage matrix: DeviceService profiles', () => {
  it('lists the profile edit and lookups as covered by the profiles page and its real-server spec', () => {
    const wants = [
      '| `DeviceService.UpdateProfile` | `PUT /device/profiles/{id:[0-9]+}` | `(dashboard)/devices/profiles/page.tsx` | - | `real-server/device-profiles.spec.ts` | covered |',
      '| `DeviceService.FindProfileByMACAddress` | `GET /device/profiles/mac/{mac}` | `(dashboard)/devices/profiles/page.tsx` | - | `real-server/device-profiles.spec.ts` | covered |',
      '| `DeviceService.FindProfileBySerial` | `GET /device/profiles/serial/{serial}` | `(dashboard)/devices/profiles/page.tsx` | - | `real-server/device-profiles.spec.ts` | covered |',
      '| `DeviceService.FindMatchingProfile` | `POST /device/profiles/match` | `(dashboard)/devices/profiles/page.tsx` | - | `real-server/device-profiles.spec.ts` | covered |',
      '| `DeviceService.CountProfiles` | `GET /device/profiles/count` | `(dashboard)/devices/profiles/page.tsx` | - | `real-server/device-profiles.spec.ts` | covered |',
    ];
    for (const want of wants) {
      expect(lines.filter((l) => l === want), want).toHaveLength(1);
    }
  });

  it('lists ActivateDevice as covered by the device detail page', () => {
    const want =
      '| `DeviceService.ActivateDevice` | `POST /device/activate-json` | `(dashboard)/devices/[id]/page.tsx` | - | `real-server/device-activate.spec.ts` | covered |';
    expect(lines.filter((l) => l === want), want).toHaveLength(1);
  });

  it('recounts the DeviceService summary', () => {
    // Columns: Operations | covered | partial | missing | not-UI | blocked: integration
    const want = '| DeviceService | 32 | 21 | 5 | 3 | 3 | 0 |';
    expect(lines.filter((l) => l === want), want).toHaveLength(1);
  });

  it('names files that exist', () => {
    expect(fs.existsSync(path.resolve(process.cwd(), 'src/app/(dashboard)/devices/profiles/page.tsx'))).toBe(true);
    expect(fs.existsSync(path.resolve(process.cwd(), 'e2e/real-server/device-profiles.spec.ts'))).toBe(true);
    expect(fs.existsSync(path.resolve(process.cwd(), 'e2e/real-server/device-activate.spec.ts'))).toBe(true);
  });
});
