// @vitest-environment node
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const matrixPath = path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md');
const lines = fs.readFileSync(matrixPath, 'utf8').split('\n');

const page = '`(dashboard)/compute/registry/page.tsx`';

const rows: Array<[string, string, string]> = [
  ['List', 'GET /{name:.+}/tags/list', 'registry.spec.ts'],
  ['Inspect', 'GET /compute/images/{repository:.+}', 'registry-seeded.spec.ts'],
  ['Delete', 'DELETE /{name:.+}/manifests/{reference}', 'registry-seeded.spec.ts'],
  ['Status', 'GET /status', 'registry.spec.ts'],
];

describe('coverage matrix: RegistryService', () => {
  it('lists List, Inspect, Delete and Status as covered by the registry page and its real-server specs', () => {
    for (const [op, route, spec] of rows) {
      const want = `| \`RegistryService.${op}\` | \`${route}\` | ${page} | - | \`${spec}\` | covered |`;
      expect(lines.filter((l) => l === want), `RegistryService.${op}`).toHaveLength(1);
    }
    const open = lines.filter((l) => {
      if (!l.startsWith('| `RegistryService.')) return false;
      const status = l.trimEnd().replace(/\|$/, '').split('|').pop()!.trim();
      return l.trimEnd().endsWith('| missing |') || status.startsWith('partial');
    });
    expect(open, 'RegistryService rows still missing or partial').toEqual([]);
  });

  it('recounts the RegistryService summary line', () => {
    expect(lines.filter((l) => l === '| RegistryService | 6 | 4 | 0 | 0 | 2 | 0 |')).toHaveLength(1);
  });

  it('names files that exist', () => {
    expect(fs.existsSync(path.resolve(process.cwd(), 'src/app/(dashboard)/compute/registry/page.tsx'))).toBe(true);
    expect(fs.existsSync(path.resolve(process.cwd(), 'e2e/real-server/registry.spec.ts'))).toBe(true);
    expect(fs.existsSync(path.resolve(process.cwd(), 'e2e/real-server/registry-seeded.spec.ts'))).toBe(true);
  });
});
