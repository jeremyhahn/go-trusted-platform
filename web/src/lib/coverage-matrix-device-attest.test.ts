// @vitest-environment node
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// vitest runs in web/, so the matrix sits one directory up.
const matrixPath = path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md');
const lines = fs.readFileSync(matrixPath, 'utf8').split(/\r?\n/);

describe('coverage matrix: DeviceService attestation', () => {
  it('lists AttestDevice and RecordAttestationCertificate as covered by the device page and the real-server spec', () => {
    const wants = [
      '| `DeviceService.AttestDevice` | `POST /devices/{id}/attest` | `(dashboard)/devices/[id]/page.tsx` | - | `real-server/device-attestation.spec.ts` | covered |',
      '| `DeviceService.RecordAttestationCertificate` | `POST /devices/{id:[0-9]+}/attest-cert/record` | `(dashboard)/devices/[id]/page.tsx` | - | `real-server/device-attestation.spec.ts` | covered |',
    ];
    for (const want of wants) {
      expect(lines.filter((l) => l === want), want).toHaveLength(1);
    }
  });

  it('names files that exist', () => {
    expect(fs.existsSync(path.resolve(process.cwd(), 'src/app/(dashboard)/devices/[id]/page.tsx'))).toBe(true);
    expect(fs.existsSync(path.resolve(process.cwd(), 'e2e/real-server/device-attestation.spec.ts'))).toBe(true);
  });
});
