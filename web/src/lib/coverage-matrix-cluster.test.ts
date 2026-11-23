// @vitest-environment node
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const matrixPath = path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md');
const lines = fs.readFileSync(matrixPath, 'utf8').split('\n');

const page = '`(dashboard)/platform/cluster/page.tsx`';
const spec = '`real-server/cluster.spec.ts`';

const rows: Array<[string, string]> = [
  ['Bootstrap', 'POST /cluster/bootstrap'],
  ['Join', 'POST /cluster/join'],
  ['Leave', 'POST /cluster/leave'],
  ['GetStatus', 'GET /cluster/status'],
  ['ListNodes', 'GET /cluster/nodes'],
];

describe('coverage matrix: ClusterService', () => {
  it('lists each ClusterService operation as covered by the cluster page and its real-server spec', () => {
    for (const [op, route] of rows) {
      const want = `| \`ClusterService.${op}\` | \`${route}\` | ${page} | - | ${spec} | covered |`;
      expect(lines.filter((l) => l === want), `ClusterService.${op}`).toHaveLength(1);
    }
    const missing = lines.filter(
      (l) => l.startsWith('| `ClusterService.') && l.trimEnd().endsWith('| missing |'),
    );
    expect(missing, 'ClusterService rows still missing').toEqual([]);
  });

  it('names files that exist', () => {
    expect(fs.existsSync(path.resolve(process.cwd(), 'src/app/(dashboard)/platform/cluster/page.tsx'))).toBe(true);
    expect(fs.existsSync(path.resolve(process.cwd(), 'e2e/real-server/cluster.spec.ts'))).toBe(true);
  });
});
