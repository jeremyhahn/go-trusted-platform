// @vitest-environment node
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// #2055 (epic #1665): the IDevIDService rows the TPM status page and its
// real-server spec ship are covered; CreateIAKCSR stays missing (deferred: the
// daemon cannot yet return a PEM CSR).

const matrixPath = path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md');
const lines = fs.readFileSync(matrixPath, 'utf8').split('\n');

const md = (p: string) => '`' + p + '`';

const statusPage = '(dashboard)/tpm/status/page.tsx';
const idevidSpec = 'real-server/tpm-idevid.spec.ts';

// [operation, REST]
const rows: Array<[string, string]> = [
  ['IDevIDService.HasIDevID', 'GET /exists'],
  ['IDevIDService.GenerateIAK', 'POST /iak/generate'],
  ['IDevIDService.HasIAK', 'GET /iak/exists'],
  ['IDevIDService.DeleteIAK', 'DELETE /iak'],
  ['IDevIDService.CreateLDevID', 'POST /ldevid'],
  ['IDevIDService.InstallIDevIDCertificate', 'POST /certificate'],
  ['IDevIDService.InstallIAKCertificate', 'POST /iak/certificate'],
  ['IDevIDService.DeleteIAKCertificate', 'DELETE /iak/certificate'],
  ['IDevIDService.GetDeviceAttributes', 'GET /attributes'],
  ['IDevIDService.FlushTransientContexts', 'POST /flush'],
  ['IDevIDService.ActivateCredential', 'POST /activate-credential'],
];

describe('coverage matrix: IDevIDService rows (#2055)', () => {
  for (const [op, route] of rows) {
    it(`lists ${op} as covered by ${idevidSpec}`, () => {
      const want = `| \`${op}\` | \`${route}\` | ${md(statusPage)} | - | ${md(idevidSpec)} | covered |`;
      expect(lines.filter((l) => l === want), op).toHaveLength(1);
    });
  }

  it('keeps CreateIAKCSR missing', () => {
    const want = '| `IDevIDService.CreateIAKCSR` | `POST /iak/csr` | - | - | - | missing |';
    expect(lines.filter((l) => l === want)).toHaveLength(1);
  });

  it('counts the IDevIDService rows in the summary', () => {
    expect(lines.filter((l) => l === '| IDevIDService | 20 | 19 | 0 | 1 | 0 | 0 |')).toHaveLength(1);
  });

  it('names files that exist', () => {
    expect(fs.existsSync(path.resolve(process.cwd(), 'src/app', statusPage)), statusPage).toBe(true);
    expect(fs.existsSync(path.resolve(process.cwd(), 'e2e', idevidSpec)), idevidSpec).toBe(true);
  });
});
