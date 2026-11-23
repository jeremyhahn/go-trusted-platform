// @vitest-environment node
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// #2057 (epic #1665): the KeyManagementService rows the KMS pages and their
// real-server specs ship are covered; GenerateDataKey and GenerateWrappedDataKey
// stay partial until the SDK sends the body the server reads; BatchEncrypt,
// BatchDecrypt and Rewrap stay missing (no UI yet).

const matrixPath = path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md');
const lines = fs.readFileSync(matrixPath, 'utf8').split('\n');

const md = (p: string) => '`' + p + '`';

const kmsPage = '(dashboard)/kms/page.tsx';
const keyPage = '(dashboard)/kms/[id]/page.tsx';
const dataKeysPage = '(dashboard)/kms/data-keys/page.tsx';
const kmsSpec = 'real-server/kms.spec.ts';
const keySpec = 'real-server/kms-key-detail.spec.ts';

const row = (op: string, route: string, page: string, spec: string, status: string) =>
  `| \`KeyManagementService.${op}\` | \`${route}\` | ${page} | - | ${spec} | ${status} |`;

// [operation, REST, web page cell, spec cell, status]
const rows: Array<[string, string, string, string, string]> = [
  ['ImportKey', 'POST /keys/import', md(kmsPage), md(kmsSpec), 'covered'],
  ['UpdateKeyStatus', 'PUT /keys/{name}/status', `${md(kmsPage)}<br>${md(keyPage)}`, `${md(kmsSpec)}<br>${md(keySpec)}`, 'covered'],
  ['GetKeyVersions', 'GET /keys/{name}/versions', md(keyPage), md(keySpec), 'covered'],
  ['Hash', 'POST /hash', md(kmsPage), md(kmsSpec), 'covered'],
  ['HMAC', 'POST /hmac/{name}', md(kmsPage), md(kmsSpec), 'covered'],
  ['VerifyHMAC', 'POST /hmac/{name}/verify', md(kmsPage), md(kmsSpec), 'covered'],
  ['GenerateRandom', 'POST /random', md(kmsPage), md(kmsSpec), 'covered'],
  ['BackendStatus', 'GET /backend/status', md(kmsPage), md(kmsSpec), 'covered'],
  ['GenerateDataKey', 'POST /data-keys', md(dataKeysPage), md(kmsSpec), 'partial'],
  ['GenerateWrappedDataKey', 'POST /data-keys/wrapped', md(dataKeysPage), md(kmsSpec), 'partial'],
  ['BatchEncrypt', 'POST /encrypt/{name}', '-', '-', 'missing'],
  ['BatchDecrypt', 'POST /decrypt/{name}', '-', '-', 'missing'],
];

describe('coverage matrix: KeyManagementService rows (#2057)', () => {
  for (const [op, route, page, spec, status] of rows) {
    it(`lists ${op} as ${status}`, () => {
      const want = row(op, route, page, spec, status);
      expect(lines.filter((l) => l === want), op).toHaveLength(1);
    });
  }

  it('keeps Rewrap missing', () => {
    const want = '| `KeyManagementService.Rewrap` | - | - | - | - | missing |';
    expect(lines.filter((l) => l === want)).toHaveLength(1);
  });

  it('counts the KeyManagementService rows in the summary', () => {
    expect(lines.filter((l) => l === '| KeyManagementService | 23 | 18 | 2 | 3 | 0 | 0 |')).toHaveLength(1);
  });

  it('names files that exist', () => {
    for (const p of [kmsPage, keyPage, dataKeysPage]) {
      expect(fs.existsSync(path.resolve(process.cwd(), 'src/app', p)), p).toBe(true);
    }
    for (const p of [kmsSpec, keySpec]) {
      expect(fs.existsSync(path.resolve(process.cwd(), 'e2e', p)), p).toBe(true);
    }
  });
});
